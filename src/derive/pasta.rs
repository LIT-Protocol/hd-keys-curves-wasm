use crate::HDDerivable;
use crate::derive::{HDDerivableScalar, HDDeriver};
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve_tools::SumOfProducts;

impl HDDeriver for pasta_curves::pallas::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        pasta_curves::pallas::Scalar::hash::<ExpandMsgXmd<blake2::Blake2b512>>(msg, dst)
    }
}

impl HDDerivableScalar<4> for pasta_curves::pallas::Scalar {
    fn as_limbs(&self) -> [u64; 4] {
        let mut out = self.to_raw();
        out.reverse();
        out
    }
}

impl HDDerivable for pasta_curves::pallas::Point {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        let data = scalars
            .iter()
            .zip(points.iter())
            .map(|(&s, &p)| (s, p))
            .collect::<Vec<_>>();
        <Self as SumOfProducts>::sum_of_products(data.as_slice())
    }
}
