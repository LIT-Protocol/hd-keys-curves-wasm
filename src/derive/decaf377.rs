use decaf377::{Element as ProjectivePoint, Fr as Scalar};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};

use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;

use super::sum_of_products_pippenger;

impl HDDeriver for Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let dst = [dst];
        let mut expander = ExpandMsgXmd::<blake2::Blake2b512>::expand_message(&[msg], &dst, 64)
            .expect("valid xmd");
        let mut bytes = [0u8; 64];
        expander.fill_bytes(&mut bytes);
        Scalar::from_le_bytes_mod_order(&bytes)
    }
}

impl HDDerivableScalar<4> for Scalar {
    fn as_limbs(&self) -> [u64; 4] {
        let bytes = self.to_bytes_le();
        [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ]
    }
}

impl HDDerivable for ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<Scalar, Self, 4>(points, scalars)
    }
}

#[cfg(test)]
mod test {
    use decaf377::{Element as ProjectivePoint, Fr as Scalar};
    use elliptic_curve::{Field, Group};

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
