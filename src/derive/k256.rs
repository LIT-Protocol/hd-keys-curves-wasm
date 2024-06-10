use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};

use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;

use super::{scalar_primitive_to_limbs, sum_of_products_pippenger};

impl HDDeriver for k256::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        k256::Secp256k1::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl HDDerivableScalar<4> for k256::Scalar {
    fn as_limbs(&self) -> [u64; 4] {
        scalar_primitive_to_limbs::<4, 8, k256::Secp256k1>(*self)
    }
}

impl HDDerivable for k256::ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<k256::Scalar, Self, 4>(points, scalars)
    }
}
