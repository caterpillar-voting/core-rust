//! Wrapper around [`ristretto`]
//!
//! [`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html

use crate::foundation::group::ByteSerialize;
use crate::foundation::group::Group;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint as RistrettoPointRaw},
    scalar::Scalar as RistrettoScalarRaw,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;

#[derive(Debug, PartialEq)]
pub struct RistrettoGroup(());

impl ByteSerialize for RistrettoPointRaw {
    const BUFFER_SIZE: usize = 32;

    fn to_bytes(&self, out: &mut [u8]) {
        let bytes = &self.compress().to_bytes();
        out.copy_from_slice(bytes);
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(buffer).ok()?.decompress()
    }
}

impl ByteSerialize for RistrettoScalarRaw {
    const BUFFER_SIZE: usize = 32;

    fn to_bytes(&self, out: &mut [u8]) {
        let bytes = self.to_bytes();
        out.copy_from_slice(&bytes)
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        let bytes: &[u8; 32] = buffer.try_into().expect("Incorrect byte size");
        Self::from_canonical_bytes(*bytes).into()
    }
}

impl Group for RistrettoGroup {
    const GROUP_IDENTIFIER: &'static [u8] = b"Ristretto";

    type Point = RistrettoPointRaw;
    type Scalar = RistrettoScalarRaw;

    fn identity() -> Self::Point {
        Self::Point::identity()
    }

    fn basepoint() -> Self::Point {
        RISTRETTO_BASEPOINT_POINT
    }

    fn hash_to_point(payload: &[u8]) -> Self::Point {
        RistrettoPointRaw::hash_from_bytes::<Sha512>(payload)
    }

    fn independent_generators(prefix: &[u8], size: usize) -> Vec<Self::Point> {
        let mut result = Vec::with_capacity(size);

        for i in 0..size {
            let mut payload =
                Vec::with_capacity(prefix.len() + Self::GROUP_IDENTIFIER.len() + size_of::<u32>());
            payload.extend_from_slice(prefix);
            payload.extend_from_slice(&Self::GROUP_IDENTIFIER);

            let i = u32::try_from(i).expect("index does not fit in u32");
            payload.extend_from_slice(&i.to_le_bytes());

            result.push(RistrettoPointRaw::hash_from_bytes::<Sha512>(&payload));
        }

        result
    }

    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point {
        Self::Point::random(rng)
    }

    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        let mut uniform_bytes = [0u8; 64];
        rng.try_fill_bytes(&mut uniform_bytes).unwrap();
        Self::Scalar::from_bytes_mod_order_wide(&uniform_bytes)
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    type Point = <RistrettoGroup as Group>::Point;
    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn identity_is_zero() {
        let two = Scalar::from(2u8);
        let four = Scalar::from(4u8);
        let two_point = RistrettoGroup::basepoint() * two;
        let four_point = RistrettoGroup::basepoint() * four;
        let zero = four_point - two_point - two_point;
        assert_eq!(zero, RistrettoGroup::identity());
    }

    #[test]
    fn construct_random_points_and_scalars() {
        let mut rng = thread_rng();
        let random_point = RistrettoGroup::point_random(&mut rng);
        let random_scalar = RistrettoGroup::scalar_random(&mut rng);
        let point_from_random_operation = random_point * random_scalar;

        let mut bytes = [0u8; 43];
        rng.fill_bytes(&mut bytes);
        let point_from_hash = RistrettoGroup::hash_to_point(&bytes);

        assert_ne!(point_from_random_operation, RistrettoGroup::identity());
        assert_ne!(point_from_hash, RistrettoGroup::identity());
        assert_ne!(point_from_hash, point_from_random_operation);
    }

    #[test]
    fn serialization_roundtrips() {
        let mut rng = thread_rng();

        let points = [
            RistrettoGroup::identity(),
            RistrettoGroup::basepoint(),
            RistrettoGroup::point_random(&mut rng),
            RistrettoGroup::hash_to_point(b"payload"),
        ];

        for point in points {
            let mut bytes = [0u8; <Point as ByteSerialize>::BUFFER_SIZE];
            ByteSerialize::to_bytes(&point, &mut bytes);
            let recovered_point = Point::from_bytes(&bytes).unwrap();
            assert_eq!(point, recovered_point);
        }

        let scalars = [
            Scalar::from(0u64),
            Scalar::from(1u64),
            RistrettoGroup::scalar_random(&mut rng),
        ];

        for scalar in scalars {
            let mut bytes = [0u8; <Scalar as ByteSerialize>::BUFFER_SIZE];
            ByteSerialize::to_bytes(&scalar, &mut bytes);
            let recovered_scalar = Scalar::from_bytes(&bytes).unwrap();
            assert_eq!(scalar, recovered_scalar);
        }
    }
}

// endregion: --- Tests
