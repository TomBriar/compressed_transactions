use bitcoin::consensus::{Encodable, Decodable};
use bitcoincore_rpc::{Auth, Client};
use bitcoin::Transaction;
use std::env;

mod error;
use crate::error::{Error};

mod util;

mod compressed_transaction;
use crate::compressed_transaction::{CompressedTransaction};

mod compress_outpoints;
use crate::compress_outpoints::{compress_outpoints, decompress_outpoints};


fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    let mut rpc_username = "";
    let mut rpc_password = "";
    let mut rpc_port = "8332";

    let mut parameters = vec![];

    for arg in &args[1..args.len()] {
        if &arg[0..2] == "--" {
            let split = arg[2..].split('=').collect::<Vec<&str>>();
            if split.len() != 2 { return Err(Error::UnknownArgument(arg.to_string())); }
            match split[0] {
                "rpcuser" => rpc_username = split[1],
                "rpcpassword" => rpc_password = split[1],
                "rpcport" => rpc_port = split[1],
                _ => { return Err(Error::UnknownArgument(arg.to_string())); }
            }
        } else {
            parameters.push(arg);
        }
    }

    let rpc = Client::new(&("http://localhost:".to_owned()+rpc_port), Auth::UserPass(rpc_username.to_string(), rpc_password.to_string()))?;

    if parameters.len() != 2 { return Err(Error::HelpMessage()); }

    match parameters[0].as_str() {
        "compressrawtransaction" => {
            let hex_bytes: Vec<u8> = hex::decode(parameters[1]).or(Err(Error::InvalidHex(parameters[1].to_string())))?;
            let transaction: Transaction = Transaction::consensus_decode(&mut hex_bytes.as_slice()).or(Err(Error::InvalidHex(parameters[1].to_string())))?;
            let (minimum_height, compressed_inputs) = compress_outpoints(&rpc, &transaction, true)?;
            let ctx: CompressedTransaction = CompressedTransaction::compress(&transaction, minimum_height, &compressed_inputs)?;
            let mut stream: Vec<u8> = vec![];
            _ = ctx.consensus_encode(&mut stream)?;
            println!("{}", hex::encode(stream));
            Ok(())
        },
        "decompressrawtransaction" => {
            let hex_bytes: Vec<u8> = hex::decode(parameters[1]).or(Err(Error::InvalidHex(parameters[1].to_string())))?;
            let ctx: CompressedTransaction = CompressedTransaction::consensus_decode(&mut hex_bytes.as_slice()).or(Err(Error::InvalidHex(parameters[1].to_string())))?;
            let out_tup = decompress_outpoints(&rpc, ctx.minimum_height(), ctx.input())?;
            let utx: Transaction = ctx.decompress(&out_tup)?;
            let mut stream: Vec<u8> = vec![];
            _ = utx.consensus_encode(&mut stream)?;
            println!("{}", hex::encode(stream));
            Ok(())
        },
        m => Err(Error::UnknownMethod(m.to_string()))
    }
}
