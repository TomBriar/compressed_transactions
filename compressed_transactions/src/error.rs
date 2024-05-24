#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Help Message")]
    HelpMessage(),

    #[error("Argument is not valid (see --help):\n{}", .0)]
    UnknownArgument(String),
    #[error("Unknown method  (see --help):\n{}", .0)]
    UnknownMethod(String),
    #[error("Hex is not a valid hex encoded raw transaction:\n{}", .0)]
    InvalidHex(String),

    #[error("Could not find input, Input missing or spent.")]
    InputMissing(),

    #[error("Cannot Compress Object.")]
    CannotCompress(),

    #[error("Bitcoin Core RPC Failed (Ensure rpcuser and rpcpassword are set correctly):\n{}", .0)]
    BitcoincoreRPC(#[from] bitcoincore_rpc::Error),
    #[error("Bitcoin Core Absolute Error:\n{}", .0)]
    BitcoinAbsolute(#[from] bitcoin::absolute::Error),
    #[error("Bitcoin Core Decode Error:\n{}", .0)]
    BitcoinConensus(#[from] bitcoin::consensus::encode::Error),
    #[error("Bitcoin Sighash Error:\n{}", .0)]
    BitcoinSighash(#[from] bitcoin::sighash::Error),
    #[error("Bitcoin Key Error:\n{}", .0)]
    BitcoinKey(#[from] bitcoin::key::Error),
    #[error("Secp256k1 Error:\n{}", .0)]
    Secp256k1(#[from] secp256k1::Error),
    #[error("FromSlice Error:\n{}", .0)]
    FromSlice(#[from] bitcoin::hashes::FromSliceError),
    #[error("From Hex Error:\n{}", .0)]
    Hex(#[from] hex::FromHexError),
    #[error("IO Error:\n{}", .0)]
    Io(#[from] std::io::Error),
}
