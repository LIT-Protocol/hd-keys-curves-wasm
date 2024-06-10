use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};

use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;

use super::{scalar_primitive_to_limbs, sum_of_products_pippenger};

impl HDDeriver for p384::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        p384::NistP384::hash_to_scalar::<ExpandMsgXmd<sha2::Sha384>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl HDDerivableScalar<6> for p384::Scalar {
    fn as_limbs(&self) -> [u64; 6] {
        scalar_primitive_to_limbs::<6, 12, p384::NistP384>(*self)
    }
}

impl HDDerivable for p384::ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<p384::Scalar, Self, 6>(points, scalars)
    }
}
