mod derive;
#[cfg(feature = "ecops")]
mod ec_ops;

pub use derive::*;
#[cfg(feature = "ecops")]
pub use ec_ops::*;

#[cfg(feature = "p256")]
pub extern crate p256;

#[cfg(feature = "p384")]
pub extern crate p384;

#[cfg(feature = "k256")]
pub extern crate k256;

#[cfg(feature = "curve25519")]
pub use vsss_rs::curve25519;

#[cfg(feature = "bls")]
pub extern crate blsful;

#[cfg(feature = "ed448")]
pub extern crate ed448_goldilocks_plus;

#[cfg(feature = "jubjub")]
pub extern crate jubjub;

#[cfg(feature = "decaf377")]
pub extern crate decaf377;


#[cfg(not(any(
    feature = "p256",
    feature = "p384",
    feature = "k256",
    feature = "curve25519",
    feature = "bls",
    feature = "ed448",
    feature = "jubjub",
    feature = "decaf377"
)))]
compile_error!("At least one feature curve must be enabled");
