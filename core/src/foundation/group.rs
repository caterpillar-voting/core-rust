//! Wrapper around different rust implementations of prime-order groups

pub mod ristretto;

/// Define a Trait for a generic Elliptic Curve Group
use core::{fmt, ops};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub trait ByteSerialize {
    const BUFFER_SIZE: usize;
    fn to_bytes(&self, buffer: &mut [u8]);
    fn from_bytes(buffer: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

pub trait Group {
    type Point: Clone
        + Copy
        + Eq
        + PartialEq
        + for<'a> ops::Add<&'a Self::Point, Output = Self::Point>
        + ops::AddAssign
        + for<'a> ops::Sub<&'a Self::Point, Output = Self::Point>
        + ops::SubAssign
        + for<'a> ops::Neg<Output = Self::Point>
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Point>
        + Zeroize
        + ByteSerialize
        + fmt::Debug;

    type Scalar: Clone
        + Default
        + Copy
        + Eq
        + PartialEq
        + fmt::Debug
        + From<u64>
        + for<'a> ops::Add<&'a Self::Scalar, Output = Self::Scalar>
        + ops::AddAssign
        + for<'a> ops::Sub<&'a Self::Scalar, Output = Self::Scalar>
        + ops::SubAssign
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Scalar>
        + ops::MulAssign
        + Zeroize
        + ByteSerialize
        + fmt::Debug;

    /// Return the identity
    fn identity() -> Self::Point;

    /// Return the basepoint, i.e., a generator defined by the spec to be used as a starting point for the group.
    fn basepoint() -> Self::Point;

    /// Generate a random Point.
    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point;

    /// Hash to group point.
    fn hash_to_point(payload: &[u8]) -> Self::Point;

    /// Generate a random scalar.
    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
}
