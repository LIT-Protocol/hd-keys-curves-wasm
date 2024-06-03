use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, ExpandMsgXof, Expander};
use elliptic_curve::{
    hash2curve::GroupDigest, CurveArithmetic, Field, Group, PrimeField, ScalarPrimitive,
};

pub trait HDDeriver: PrimeField {
    fn create(msg: &[u8], dst: &[u8]) -> Self;

    fn hd_derive_secret_key(&self, secret_keys: &[Self]) -> Self {
        secret_keys
            .iter()
            .rfold(Self::ZERO, |acc, sk| acc * self + sk)
    }

    fn hd_derive_public_key<D: HDDerivable<Scalar = Self>>(&self, public_keys: &[D]) -> D {
        if public_keys.is_empty() {
            return D::identity();
        }
        if public_keys.len() == 1 {
            return public_keys[0] * *self;
        }
        let powers = get_poly_powers(*self, public_keys.len());
        D::sum_of_products(public_keys, powers.as_slice())
    }
}

pub trait HDDerivable: Group {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self;
}

trait HDDerivableScalar<const N: usize>: PrimeField {
    fn as_limbs(&self) -> [u64; N];
}

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

impl HDDeriver for p256::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        let msg = [msg];
        let dst = [dst];
        p256::NistP256::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&msg, &dst)
            .expect("hash_to_scalar failed")
    }
}

impl HDDerivableScalar<4> for p256::Scalar {
    fn as_limbs(&self) -> [u64; 4] {
        scalar_primitive_to_limbs::<4, 8, p256::NistP256>(*self)
    }
}

impl HDDerivable for p256::ProjectivePoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<p256::Scalar, Self, 4>(points, scalars)
    }
}

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
        sum_of_products_pippenger::<jubjub::Scalar, Self, 4>(points, scalars)
    }
}

impl HDDerivable for jubjub::SubgroupPoint {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        sum_of_products_pippenger::<jubjub::Scalar, Self, 4>(points, scalars)
    }
}

impl HDDeriver for bls12_381_plus::Scalar {
    fn create(msg: &[u8], dst: &[u8]) -> Self {
        bls12_381_plus::Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, dst)
    }
}

impl HDDerivable for bls12_381_plus::G1Projective {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        bls12_381_plus::G1Projective::sum_of_products(points, scalars)
    }
}

impl HDDerivable for bls12_381_plus::G2Projective {
    fn sum_of_products(points: &[Self], scalars: &[Self::Scalar]) -> Self {
        bls12_381_plus::G2Projective::sum_of_products(points, scalars)
    }
}

fn get_poly_powers<D: HDDeriver>(scalar: D, count: usize) -> Vec<D> {
    let mut powers = vec![<D as Field>::ONE; count];
    powers[1] = scalar;
    for i in 2..powers.len() {
        powers[i] = powers[i - 1] * scalar;
    }
    powers
}

fn sum_of_products_pippenger<F: HDDerivableScalar<N>, G: Group<Scalar = F>, const N: usize>(
    points: &[G],
    scalars: &[F],
) -> G {
    const WINDOW: usize = 4;
    const NUM_BUCKETS: usize = 1 << WINDOW;
    const EDGE: usize = WINDOW - 1;
    const MASK: u64 = (NUM_BUCKETS - 1) as u64;

    let scalars = scalars.iter().map(|s| s.as_limbs()).collect::<Vec<_>>();
    let num_components = core::cmp::min(points.len(), scalars.len());
    let mut buckets = [G::identity(); NUM_BUCKETS];
    let mut res = G::identity();
    let mut num_doubles = 0;
    let mut bit_sequence_index = 255usize;

    loop {
        for _ in 0..num_doubles {
            res = res.double();
        }

        let mut max_bucket = 0;
        let word_index = bit_sequence_index >> 6;
        let bit_index = bit_sequence_index & 63;

        if bit_index < EDGE {
            // we are on the edge of a word; have to look at the previous word, if it exists
            if word_index == 0 {
                // there is no word before
                let smaller_mask = ((1 << (bit_index + 1)) - 1) as u64;
                for i in 0..num_components {
                    let bucket_index: usize = (scalars[i][word_index] & smaller_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            } else {
                // there is a word before
                let high_order_mask = ((1 << (bit_index + 1)) - 1) as u64;
                let high_order_shift = EDGE - bit_index;
                let low_order_mask = ((1 << high_order_shift) - 1) as u64;
                let low_order_shift = 64 - high_order_shift;
                let prev_word_index = word_index - 1;
                for i in 0..num_components {
                    let mut bucket_index =
                        ((scalars[i][word_index] & high_order_mask) << high_order_shift) as usize;
                    bucket_index |= ((scalars[i][prev_word_index] >> low_order_shift)
                        & low_order_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            }
        } else {
            let shift = bit_index - EDGE;
            for i in 0..num_components {
                let bucket_index: usize = ((scalars[i][word_index] >> shift) & MASK) as usize;
                if bucket_index > 0 {
                    buckets[bucket_index] += points[i];
                    if bucket_index > max_bucket {
                        max_bucket = bucket_index;
                    }
                }
            }
        }
        res += &buckets[max_bucket];
        for i in (1..max_bucket).rev() {
            buckets[i] += buckets[i + 1];
            res += buckets[i];
            buckets[i + 1] = G::identity();
        }
        buckets[1] = G::identity();
        if bit_sequence_index < WINDOW {
            break;
        }
        bit_sequence_index -= WINDOW;
        num_doubles = {
            if bit_sequence_index < EDGE {
                bit_sequence_index + 1
            } else {
                WINDOW
            }
        };
    }
    res
}

#[cfg(target_pointer_width = "32")]
fn scalar_primitive_to_limbs<const N: usize, const NN: usize, C: CurveArithmetic>(
    s: C::Scalar,
) -> [u64; N] {
    let primitive: ScalarPrimitive<C> = s.into();
    let mut out = [0u64; N];
    let mut space = [0u64; NN];
    space
        .iter_mut()
        .zip(primitive.as_limbs())
        .for_each(|(o, l)| *o = l.0 as u64);
    let mut i = 0;
    let mut j = 0;
    while i < NN && j < N {
        out[j] = space[i + 1] << 32 | space[i];
        i += 2;
        j += 1;
    }
    out
}
#[cfg(target_pointer_width = "64")]
fn scalar_primitive_to_limbs<const N: usize, const NN: usize, C: CurveArithmetic>(
    s: C::Scalar,
) -> [u64; N] {
    let primitive: ScalarPrimitive<C> = s.into();
    let mut out = [0u64; N];
    out.iter_mut()
        .zip(primitive.as_limbs())
        .for_each(|(o, l)| *o = l.0);
    out
}

#[test]
fn pippinger_k256_known() {
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
