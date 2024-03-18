use std::env;
use bitcoin::Transaction;
use bitcoin::consensus::Decodable;
use bitcoincore_rpc::{Auth, Client, RpcApi};

use bitcoin::consensus::Encodable;
use hex::decode as hex_decode;

mod compressed_transaction;
use crate::compressed_transaction::{CompressedOutPoint, CompressedInput, CompressedTransaction, CompressedTxIn};
mod compress_outpoints;
use crate::compress_outpoints::{CompressOutPoints, DecompressOutPoints};

mod error;
use crate::error::{Error};

//  fn main() {
//      match main_err() {
//          Ok(()) => (),
//          Err(e) => println!("{}", e)
//      }
//  }

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    
    let mut hex = "";

    let mut rpc_username = "";
    let mut rpc_password = "";
    let mut rpc_port = "8332";

    for arg in &args[1..args.len()] {
        if &arg[0..2] == "--" {
            let split = arg[2..].split("=").collect::<Vec<&str>>();
            if split.len() != 2 {Err(Error::UnknownArgument(arg.to_string()))?;}
            match split[0] {
                "rpcuser" => rpc_username = split[1],
                "rpcpassword" => rpc_password = split[1],
                "rpcport" => rpc_port = split[1],
                _ => {Err(Error::UnknownArgument(arg.to_string()))?;}
            }
        } else {
            if hex != "" {Err(Error::HelpMessage())?;}
            hex = arg;
        }
    }
    if hex == "" {Err(Error::HelpMessage())?;}

    let rpc = Client::new(&("http://localhost:".to_owned()+rpc_port), Auth::UserPass(rpc_username.to_string(), rpc_password.to_string()))?;

    //println!("{:?}", rpc.get_blockchain_info()?);
 
    let hex_bytes = hex_decode(hex)?;
    let transaction: Transaction = Transaction::consensus_decode(&mut hex_bytes.as_slice()).or(Err(Error::InvalidHex(hex.to_string())))?;
    println!("{:?}", transaction);

    let mut warnings: Vec<String> = vec![];

    let (minimum_height, compressed_inputs) = CompressOutPoints(&rpc, &transaction, true, &mut warnings)?;

    println!("minimum_height: {}", minimum_height);
    println!("warnings: {:?}", warnings);
    println!("compressed_inputs: {:?}", compressed_inputs);

    let ctx: CompressedTransaction = CompressedTransaction::compress(&transaction, minimum_height, &compressed_inputs)?;
    println!("ctx: {:?}", ctx);
    let mut stream: Vec<u8> = vec![];
    let len: usize = ctx.consensus_encode(&mut stream)?;
    println!("encoded:\n{}", hex::encode(stream));
    println!("length: {}", len);

//  let (prevouts, outs) = DecompressOutPoints(&rpc, ctx.minimum_height, &ctx.input)?;

//  let utx: Transaction = CompressedTransaction::decompress(&ctx, &prevouts, &outs)?;
//  println!("utx: {:?}", utx);
//  assert!(transaction == utx);
//  println!("SUCCESS");
//
    Ok(())
}
