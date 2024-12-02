use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve_tools::SumOfProducts;

use super::scalar_primitive_to_limbs;

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
        let data = scalars
            .iter()
            .zip(points.iter())
            .map(|(&s, &p)| (s, p))
            .collect::<Vec<_>>();
        <p384::ProjectivePoint as SumOfProducts>::sum_of_products(data.as_slice())
    }
}

#[cfg(test)]
mod test {
    use elliptic_curve::Field;
    use p384::{ProjectivePoint, Scalar};

    use crate::HDDerivable;

    #[test]
    fn pippinger() {
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).unwrap();

        let points = [ProjectivePoint::GENERATOR; 3];

        for _ in 0..25 {
            let scalars = [
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
            ];
            let expected = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];

            let actual = ProjectivePoint::sum_of_products(&points, &scalars);

            assert_eq!(expected, actual);
        }
    }
}
