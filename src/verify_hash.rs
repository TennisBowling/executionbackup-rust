/*
Copyright 2018 Sigma Prime Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

Thank you Lighthouse Team for everything you do!
- <3 Tennis
*/


use std::error::Error;
use triehash::ordered_trie_root;
use rlp::{RlpStream};
use ethereum_types::{Address, H256, H64, U256};
use keccak_hash::KECCAK_EMPTY_LIST_RLP;
use metastruct::metastruct;
mod keccak;
use self::keccak::{KeccakHasher, keccak256};


pub struct ExecutionPayload {
    pub parent_hash: H256,
    pub fee_recipient: Address,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Vec<u8>,
    pub prev_randao: H256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: U256,
    pub block_hash: H256,
    pub transactions: Vec<Vec<u8>>,
}

impl ExecutionPayload {
    pub fn from_json(payload: &serde_json::Value) -> Result<Self, Box<dyn Error>> {
        let parent_hash = H256::from_slice(&hex::decode(payload["parentHash"].as_str().unwrap()[2..].to_string())?);
        let fee_recipient = Address::from_slice(&hex::decode(payload["feeRecipient"].as_str().unwrap()[2..].to_string())?);
        let state_root = H256::from_slice(&hex::decode(payload["stateRoot"].as_str().unwrap()[2..].to_string())?);
        let receipts_root = H256::from_slice(&hex::decode(payload["receiptsRoot"].as_str().unwrap()[2..].to_string())?);
        let logs_bloom = hex::decode(payload["logsBloom"].as_str().unwrap()[2..].to_string())?;
        let prev_randao = H256::from_slice(&hex::decode(payload["prevRandao"].as_str().unwrap()[2..].to_string())?);
        let block_number: u64 = u64::from_str_radix(&payload["blockNumber"].as_str().unwrap()[2..], 16)?;
        let gas_limit: u64 = u64::from_str_radix(&payload["gasLimit"].as_str().unwrap()[2..], 16)?;
        let gas_used = u64::from_str_radix(&payload["gasUsed"].as_str().unwrap()[2..], 16)?;
        let timestamp = u64::from_str_radix(&payload["timestamp"].as_str().unwrap()[2..], 16)?;
        let extra_data = hex::decode(payload["extraData"].as_str().unwrap()[2..].to_string())?;
        let base_fee_per_gas = U256::from_str_radix(&payload["baseFeePerGas"].as_str().unwrap()[2..], 16)?;
        let block_hash = H256::from_slice(&hex::decode(payload["blockHash"].as_str().unwrap()[2..].to_string())?);
        let transactions = payload["transactions"].as_array().unwrap().iter().map(|txn| txn.as_str().unwrap().to_string()).collect::<Vec<String>>().iter().map(|txn| txn[2..].to_string()).map(|txn_str| hex::decode(txn_str).unwrap()).collect::<Vec<Vec<u8>>>();

        Ok(ExecutionPayload {
            parent_hash,
            fee_recipient,
            state_root,
            receipts_root,
            logs_bloom,
            prev_randao,
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            base_fee_per_gas,
            block_hash,
            transactions,
        })
    }
}



#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[metastruct(mappings(map_execution_block_header_fields()))]
pub struct ExecutionBlockHeader {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Vec<u8>,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: H64,
    pub base_fee_per_gas: U256,
}

impl ExecutionBlockHeader {
    pub fn from_payload(
        payload: &ExecutionPayload,
        rlp_empty_list_root: H256,
        rlp_transactions_root: H256,
    ) -> Self {
        // Most of these field mappings are defined in EIP-3675 except for `mixHash`, which is
        // defined in EIP-4399.
        ExecutionBlockHeader {
            parent_hash: payload.parent_hash,
            ommers_hash: rlp_empty_list_root,
            beneficiary: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root: rlp_transactions_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            difficulty: U256::zero(),
            number: payload.block_number.into(),
            gas_limit: payload.gas_limit.into(),
            gas_used: payload.gas_used.into(),
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            mix_hash: payload.prev_randao,
            nonce: H64::zero(),
            base_fee_per_gas: payload.base_fee_per_gas,
        }
    }
}


// Thank you lighthouse team! https://github.com/sigp/lighthouse/blob/stable/beacon_node/execution_layer/src/block_hash.rs#L50-L59
/// RLP encode an execution block header.
fn rlp_encode_block_header(header: &ExecutionBlockHeader) -> Vec<u8> {
    let mut rlp_header_stream = RlpStream::new();
    rlp_header_stream.begin_unbounded_list();
    map_execution_block_header_fields!(&header, |_, field| {
        rlp_header_stream.append(field);
    });
    rlp_header_stream.finalize_unbounded_list();
    rlp_header_stream.out().into()
}

// Thank you lighthouse team again! https://github.com/sigp/lighthouse/blob/stable/beacon_node/execution_layer/src/block_hash.rs#L17-L48
pub fn verify_payload_block_hash(payload: &ExecutionPayload) -> Result<(), Box<dyn Error>> {

    // Calculate the transactions root.
    // We're currently using a deprecated Parity library for this. We should move to a
    // better alternative when one appears, possibly following Reth.
    let rlp_transactions_root = ordered_trie_root::<KeccakHasher, _>(
        payload.transactions.iter().map(|txn_bytes| &**txn_bytes),
    );

    // Construct the block header.
    let exec_block_header = ExecutionBlockHeader::from_payload(
        payload,
        KECCAK_EMPTY_LIST_RLP.as_fixed_bytes().into(),
        rlp_transactions_root,
    );


    // Hash the RLP encoding of the block header.
    let rlp_block_header = rlp_encode_block_header(&exec_block_header);
    let header_hash = H256(keccak256(&rlp_block_header).into());

    if header_hash != payload.block_hash {
        return Err(format!(
            "Block hash mismatch: expected {:?}, got {:?}",
            header_hash, payload.block_hash
        ).into());
    }

    Ok(())
}