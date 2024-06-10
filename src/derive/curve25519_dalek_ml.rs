use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};

use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;

use super::sum_of_products_pippenger;

impl HDDeriver for curve25519_dalek_ml::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        let mut expander = ExpandMsgXmd::<sha2::Sha512>::expand_message(&msg, &dst, 64)
            .expect("expand_message failed");
        let mut okm = [0u8; 64];
        expander.fill_bytes(&mut okm);
        curve25519_dalek_ml::Scalar::from_bytes_mod_order_wide(&okm)
    }
}

impl HDDerivableScalar<4> for curve25519_dalek_ml::Scalar {
    fn as_limbs(&self) -> [u64; 4] {
        let mut out = [0u64; 4];
        let bytes = self.to_bytes();
        out[0] = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        out[1] = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        out[2] = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        out[3] = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        out
    }
}

impl HDDerivable for curve25519_dalek_ml::EdwardsPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<curve25519_dalek_ml::Scalar, Self, 4>(points, scalars)
    }
}

impl HDDerivable for curve25519_dalek_ml::RistrettoPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<curve25519_dalek_ml::Scalar, Self, 4>(points, scalars)
    }
}
