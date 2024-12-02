use crate::derive::{HDDerivableScalar, HDDeriver};
use crate::HDDerivable;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use elliptic_curve_tools::SumOfProducts;

impl HDDeriver for jubjub::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        jubjub::Scalar::hash::<ExpandMsgXmd<blake2::Blake2b512>>(msg, dst)
    }
}

impl HDDerivableScalar<4> for jubjub::Scalar {
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

impl HDDerivable for jubjub::ExtendedPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        let data = scalars
            .iter()
            .zip(points.iter())
            .map(|(&s, &p)| (s, p))
            .collect::<Vec<_>>();
        <Self as SumOfProducts>::sum_of_products(data.as_slice())
    }
}

impl HDDerivable for jubjub::SubgroupPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        let data = scalars
            .iter()
            .zip(points.iter())
            .map(|(&s, &p)| (s, p))
            .collect::<Vec<_>>();
        <Self as SumOfProducts>::sum_of_products(data.as_slice())
    }
}

#[cfg(test)]
mod test {
    use elliptic_curve::{Field, Group};

    use crate::HDDerivable;

    #[test]
    fn pippinger() {
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaChaRng::from_rng(rand_core::OsRng).unwrap();

        let points = [jubjub::SubgroupPoint::generator(); 3];

        for _ in 0..25 {
            let scalars = [
                jubjub::Scalar::random(&mut rng),
                jubjub::Scalar::random(&mut rng),
                jubjub::Scalar::random(&mut rng),
            ];
            let expected = points[0] * scalars[0] + points[1] * scalars[1] + points[2] * scalars[2];

            let actual = jubjub::SubgroupPoint::sum_of_products(&points, &scalars);

            assert_eq!(expected, actual);
        }
    }
}
