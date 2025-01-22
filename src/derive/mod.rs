use elliptic_curve::{CurveArithmetic, Field, Group, PrimeField, ScalarPrimitive};

#[cfg(feature = "bls")]
pub mod blsful;
#[cfg(feature = "curve25519")]
pub mod curve25519_dalek_ml;
#[cfg(feature = "decaf377")]
pub mod decaf377;
#[cfg(feature = "ed448")]
pub mod ed448_goldilocks_plus;
#[cfg(feature = "jubjub")]
pub mod jubjub;
#[cfg(feature = "k256")]
pub mod k256;
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "p384")]
pub mod p384;

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
            return public_keys[0];
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
