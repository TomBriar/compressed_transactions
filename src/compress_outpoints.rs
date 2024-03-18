use crate::{CompressedInput, CompressedOutPoint, CompressedTxIn};
use crate::{Error, Client};
use bitcoin::{Transaction, ScriptBuf, OutPoint, TxOut};
use bitcoincore_rpc::{RpcApi};
use std::cmp;

pub fn CompressOutPoints(rpc: &Client, tx: &Transaction, compress: bool, warnings: &mut Vec<String>) -> Result<(u32, Vec<CompressedInput>), Error> {
    let mut result: Vec<CompressedInput> = Vec::new();
    let mut minimum_height = tx.lock_time.to_consensus_u32().wrapping_sub(1);

    for i in 0..tx.input.len() {
        let txin = &tx.input[i];
        let prevout = match rpc.get_tx_out(&txin.previous_output.txid, txin.previous_output.vout, Some(true))? {
            Some(prevout) => prevout,
            None => {
                warnings.push(format!("UTXO({}): Input missing or spent", i));
                result.push(CompressedInput::new(txin.previous_output, ScriptBuf::new()));
                break;
            }
        };

        if prevout.confirmations >= 100 {
            let block_height = rpc.get_block_count()? as u32 - prevout.confirmations + 1;
            let block = rpc.get_block(&rpc.get_block_hash(block_height as u64)?)?;
            let mut block_index: u32 = 0;
            for txi in block.txdata {
                if txi.txid() == txin.previous_output.txid {
                    result.push(CompressedInput::new_compressed(CompressedOutPoint::new(block_height, block_index+txin.previous_output.vout), prevout.script_pub_key.script()?));
                    minimum_height = cmp::min(minimum_height, block_height-1);
                    break;
                }
                block_index += txi.output.len() as u32;
            }
        } else {
            result.push(CompressedInput::new(txin.previous_output, prevout.script_pub_key.script()?));
            warnings.push(format!("UTXO({}): Input less than 100 blocks old", i));
            break;
        }

        if result.len() < i+1 {
            result.push(CompressedInput::new(txin.previous_output, prevout.script_pub_key.script()?));
            warnings.push(format!("UTXO({}): Input could not be found in block", i));
        }
    }

    for r in &mut result {
        if r.is_compressed() {
            r.compressed_outpoint.as_mut().unwrap().block_height -= minimum_height;
        }
    }

    Ok((minimum_height, result))
}

pub fn DecompressOutPoints(rpc: &Client, minimum_height: u32, txins: &Vec<CompressedTxIn>) -> Result<(Vec<OutPoint>, Vec<TxOut>), Error> {
    let mut prevouts: Vec<OutPoint> = vec![];
    let mut outs: Vec<TxOut> = vec![];
    for txin in txins {
        if txin.outpoint_is_compressed() {
            let coutpoint = txin.compressed_outpoint.as_ref().unwrap();
            let block_height = minimum_height+coutpoint.block_height;
            let block = rpc.get_block(&rpc.get_block_hash(block_height as u64)?)?;
            let mut block_index: u32 = 0;
            for tx in block.txdata {
                let vout = coutpoint.block_index-block_index;
                if vout < tx.output.len() as u32 {
                    prevouts.push(OutPoint::new(tx.txid(), vout));
                    outs.push(tx.output[vout as usize].clone());
                    break;
                }
                block_index += tx.output.len() as u32;
            }
        } else {
            let out = match rpc.get_tx_out(&txin.outpoint.unwrap().txid, txin.outpoint.unwrap().vout, Some(true))? {
                Some(out) => TxOut{value: out.value, script_pubkey: out.script_pub_key.script()?},
                None => {return Err(Error::InputsMissing());}
            };
            prevouts.push(txin.outpoint.unwrap());
            outs.push(out);
        }
    }
    if prevouts.len() != txins.len() || outs.len() != txins.len() { return Err(Error::InputsMissing()); }
    Ok((prevouts, outs))
}
