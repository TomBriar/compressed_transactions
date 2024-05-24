use crate::compressed_transaction::{CompressedInput, CompressedOutPoint, CompressedTxIn};
use crate::error::Error;
use bitcoin::{Transaction, ScriptBuf, OutPoint, TxOut};
use bitcoincore_rpc::{RpcApi, Client};

pub fn compress_outpoints(rpc: &Client, tx: &Transaction, compress: bool) -> Result<(u32, Vec<CompressedInput>), Error> {
    let bh: u32 = rpc.get_block_count()? as u32;
    let barrier: u32 = bh-100;

    let bh_is: Vec<(u32, ScriptBuf)> = tx.input.iter().map(|txin| {
        let prevout = rpc.get_tx_out(&txin.previous_output.txid, txin.previous_output.vout, Some(true))?.ok_or(Error::InputMissing())?;
        Ok((bh-prevout.confirmations+1, prevout.script_pub_key.script()?))
    }).collect::<Result<Vec<(u32, ScriptBuf)>, Error>>()?;

    let minimum_height: u32 = std::cmp::min(bh_is.iter().map(|item| if item.0 < barrier { item.0 } else { u32::MAX }).min().unwrap().wrapping_sub(1), tx.lock_time.to_consensus_u32().wrapping_sub(1));

    let cinputs: Vec<CompressedInput> = tx.input.iter().enumerate().map(|(i, txin)| {
        if bh_is[i].0 > 0 && bh_is[i].0 < barrier && compress {
            let block = rpc.get_block(&rpc.get_block_hash(bh_is[i].0 as u64)?)?;
            let tx_index = block.txdata.iter().position(|tx| tx.txid() == txin.previous_output.txid).ok_or(Error::InputMissing())?;
            return Ok(CompressedInput::new(CompressedOutPoint::new(bh_is[i].0-minimum_height, block.txdata[0..tx_index].iter().map(|tx| tx.output.len() as u32).sum::<u32>()+txin.previous_output.vout), bh_is[i].1.clone()))
        }
        Ok(CompressedInput::new_uncompressed(txin.previous_output, bh_is[i].1.clone()))
    }).collect::<Result<Vec<CompressedInput>, Error>>()?;

    let compressed: bool = cinputs.iter().any(|i| i.compressed_outpoint().is_some());

    Ok((if minimum_height == u32::MAX || !compressed { 0 } else { minimum_height}, cinputs))
}

pub fn decompress_outpoints(rpc: &Client, minimum_height: u32, txins: &[CompressedTxIn]) -> Result<Vec<(OutPoint, TxOut)>, Error> {
    txins.iter().map(|txin| {
        if txin.compressed_outpoint().is_some() {
            let coutpoint = txin.compressed_outpoint().as_ref().unwrap();
            let block_height = minimum_height+coutpoint.block_height();
            let block = rpc.get_block(&rpc.get_block_hash(block_height as u64)?)?;
            let mut block_index: u32 = 0;
            for tx in block.txdata {
                let vout = coutpoint.block_index()-block_index;
                if vout < tx.output.len() as u32 {
                    return Ok((OutPoint::new(tx.txid(), vout), tx.output[vout as usize].clone()));
                }
                block_index += tx.output.len() as u32;
            }
            Err(Error::InputMissing())
        } else {
            let out = rpc.get_tx_out(&txin.outpoint().unwrap().txid, txin.outpoint().unwrap().vout, Some(true))?.ok_or(Error::InputMissing())?;
            Ok((txin.outpoint().unwrap(), TxOut{value: out.value, script_pubkey: out.script_pub_key.script()?}))
        }
    }).collect()
}
