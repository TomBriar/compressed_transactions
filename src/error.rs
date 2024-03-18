#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Help Message")]
    HelpMessage(),

    #[error("Argument is not valid (see --help):\n{}", .0)]
    UnknownArgument(String),
    #[error("Hex is not a valid hex encoded raw transaction:\n{}", .0)]
    InvalidHex(String),


    #[error("Attempted to access compressed object that was uncompressed.")]
    NotCompressed(),
    #[error("Attempted to access uncompressed object that was compressed.")]
    NotUncompressed(),
    #[error("Could not decompress input(s), input(s) missing or spent.")]
    InputsMissing(),

    #[error("Bitcoin Core Decode Error:\n{}", .0)]
    BitcoinConensusError(#[from] bitcoin::consensus::encode::Error),
    #[error("Bitcoin Core Absolute Error:\n{}", .0)]
    BitcoinAbsoluteError(#[from] bitcoin::absolute::Error),

//  #[error(transparent)]
//  BitcoinAddressError(#[from] bitcoin::address::Error),
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    #[error("IO Error:\n{}", .0)]
    IoError(#[from] std::io::Error),
    #[error("Bitcoin Core RPC Failed (Ensure rpcuser and rpcpassword are set correctly):\n{}", .0)]
    BitcoincoreRPCError(#[from] bitcoincore_rpc::Error),
//  #[error(transparent)]
//  SQLiteError(#[from] sqlite::Error),
//  #[error(transparent)]
//  JSONError(#[from] serde_json::Error),
//  #[error(transparent)]
//  ParseError(#[from] std::num::ParseIntError),
//  #[error(transparent)]
//  SystemTimeError(#[from] std::time::SystemTimeError),
//  #[error(transparent)]
//  TryFromSliceError(#[from] std::array::TryFromSliceError),
}
