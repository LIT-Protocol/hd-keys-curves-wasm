use elliptic_curve::hash2curve::ExpandMsgXmd;

use crate::derive::HDDeriver;
use crate::HDDerivable;

impl HDDeriver for blsful::inner_types::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        blsful::inner_types::Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst)
    }
}

impl HDDerivable for blsful::inner_types::G1Projective {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        blsful::inner_types::G1Projective::sum_of_products(points, scalars)
    }
}

impl HDDerivable for blsful::inner_types::G2Projective {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        blsful::inner_types::G2Projective::sum_of_products(points, scalars)
    }
}
