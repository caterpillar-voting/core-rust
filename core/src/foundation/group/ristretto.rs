//! Wrapper around [`ristretto`]
//!
//! [`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html

use crate::foundation::group::_shared::independent_generators_default;
use crate::foundation::group::ByteSerialize;
use crate::foundation::group::Group;
use core::{cmp, fmt, ops};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint as RistrettoPointRaw},
    scalar::Scalar as RistrettoScalarRaw,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha3::Sha3_512;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct RistrettoGroup(());

#[derive(Clone, Copy, cmp::Eq, cmp::PartialEq, fmt::Debug)]
pub struct RistrettoPoint(RistrettoPointRaw);

impl<'a> ops::Add<&'a RistrettoPoint> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn add(self, rhs: &'a RistrettoPoint) -> Self::Output {
        RistrettoPoint(self.0 + rhs.0)
    }
}

impl<'a> ops::Sub<&'a RistrettoPoint> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn sub(self, rhs: &'a RistrettoPoint) -> Self::Output {
        RistrettoPoint(self.0 - rhs.0)
    }
}

impl<'a> ops::Mul<&'a RistrettoScalar> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn mul(self, rhs: &'a RistrettoScalar) -> Self::Output {
        RistrettoPoint(self.0 * rhs.0)
    }
}

impl ByteSerialize for RistrettoPoint {
    const BUFFER_SIZE: usize = 32;

    fn to_bytes(&self, out: &mut [u8]) {
        let bytes = &self.0.compress().to_bytes();
        out.copy_from_slice(bytes);
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(buffer).ok()?.decompress().map(RistrettoPoint)
    }
}

#[derive(Clone, Copy, cmp::Eq, cmp::PartialEq, fmt::Debug, Zeroize)]
pub struct RistrettoScalar(RistrettoScalarRaw);

impl<'a> ops::Add<&'a RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    fn add(self, rhs: &'a RistrettoScalar) -> Self::Output {
        RistrettoScalar(self.0 + rhs.0)
    }
}

impl<'a> ops::Sub<&'a RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    fn sub(self, rhs: &'a RistrettoScalar) -> Self::Output {
        RistrettoScalar(self.0 - rhs.0)
    }
}

impl<'a> ops::Mul<&'a RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    fn mul(self, rhs: &'a RistrettoScalar) -> Self::Output {
        RistrettoScalar(self.0 * rhs.0)
    }
}

impl From<u64> for RistrettoScalar {
    fn from(value: u64) -> Self {
        RistrettoScalar(RistrettoScalarRaw::from(value))
    }
}

impl ByteSerialize for RistrettoScalar {
    const BUFFER_SIZE: usize = 32;

    fn to_bytes(&self, out: &mut [u8]) {
        let bytes = &self.0.to_bytes();
        out.copy_from_slice(bytes)
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        let bytes: [u8; 32] = buffer.try_into().expect("Incorrect byte size");
        RistrettoScalarRaw::from_canonical_bytes(bytes).into_option().map(RistrettoScalar)
    }
}

impl Group for RistrettoGroup {
    const GROUP_IDENTIFIER: &'static [u8] = b"Ristretto";

    type Point = RistrettoPoint;
    type Scalar = RistrettoScalar;

    fn identity() -> Self::Point {
        RistrettoPoint(RistrettoPointRaw::identity())
    }

    fn basepoint() -> Self::Point {
        RistrettoPoint(RISTRETTO_BASEPOINT_POINT)
    }

    fn hash_to_point(payload: &[u8]) -> Self::Point {
        RistrettoPoint(RistrettoPointRaw::hash_from_bytes::<Sha3_512>(payload))
    }

    fn hash_to_scalar(payload: &[u8]) -> Self::Scalar {
        RistrettoScalar(RistrettoScalarRaw::hash_from_bytes::<Sha3_512>(payload))
    }

    fn independent_generators(size: usize, context: &[u8]) -> Vec<Self::Point> {
        independent_generators_default::<Self>(size, context)
    }

    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point {
        RistrettoPoint(RistrettoPointRaw::random(rng))
    }

    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        let mut uniform_bytes = [0u8; 64];
        rng.try_fill_bytes(&mut uniform_bytes).unwrap();
        RistrettoScalar(RistrettoScalarRaw::from_bytes_mod_order_wide(&uniform_bytes))
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
        let two = Scalar::from(2u64);
        let four = Scalar::from(4u64);
        let two_point = RistrettoGroup::basepoint() * &two;
        let four_point = RistrettoGroup::basepoint() * &four;
        let zero = four_point - &two_point - &two_point;
        assert_eq!(zero, RistrettoGroup::identity());
    }

    #[test]
    fn construct_random_points_and_scalars() {
        let mut rng = thread_rng();
        let random_point = RistrettoGroup::point_random(&mut rng);
        let random_scalar = RistrettoGroup::scalar_random(&mut rng);
        let point_from_random_operation = random_point * &random_scalar;

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

        let scalars = [Scalar::from(0u64), Scalar::from(1u64), RistrettoGroup::scalar_random(&mut rng)];

        for scalar in scalars {
            let mut bytes = [0u8; <Scalar as ByteSerialize>::BUFFER_SIZE];
            ByteSerialize::to_bytes(&scalar, &mut bytes);
            let recovered_scalar = Scalar::from_bytes(&bytes).unwrap();
            assert_eq!(scalar, recovered_scalar);
        }
    }
}

// endregion: --- Tests
