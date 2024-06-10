use elliptic_curve::hash2curve::ExpandMsgXof;

use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;

use super::sum_of_products_pippenger;

impl HDDeriver for ed448_goldilocks_plus::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        ed448_goldilocks_plus::Scalar::hash::<ExpandMsgXof<sha3::Shake256>>(msg, dst)
    }
}

impl HDDerivableScalar<7> for ed448_goldilocks_plus::Scalar {
    fn as_limbs(&self) -> [u64; 7] {
        struct InnerScalar(pub(crate) [u32; 14]);
        let inner_scalar = unsafe { core::mem::transmute::<Self, InnerScalar>(*self) };
        let mut out = [0u64; 7];
        let mut i = 0;
        let mut j = 0;
        while i < inner_scalar.0.len() && j < out.len() {
            out[j] = (inner_scalar.0[i + 1] as u64) << 32 | (inner_scalar.0[i] as u64);
            i += 2;
            j += 1;
        }
        out
    }
}

impl HDDerivable for ed448_goldilocks_plus::EdwardsPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<ed448_goldilocks_plus::Scalar, Self, 7>(points, scalars)
    }
}
