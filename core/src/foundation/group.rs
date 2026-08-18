//! Wrapper around different rust implementations of prime-order groups

pub mod electionguard;
pub mod ristretto;

/// Define a Trait for a generic Elliptic Curve Group
use core::{fmt, ops};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub trait ByteSerialize {
    const BUFFER_SIZE: usize;
    fn to_bytes(&self, buffer: &mut [u8]); // TODO: Refactor API to return vec<u8>, not take &mut as argument
    fn from_bytes(buffer: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

pub trait Group {
    const GROUP_IDENTIFIER: &'static [u8];

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
        + From<u64>
        + for<'a> ops::Add<&'a Self::Scalar, Output = Self::Scalar>
        + ops::AddAssign
        + for<'a> ops::Sub<&'a Self::Scalar, Output = Self::Scalar>
        + ops::SubAssign
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Scalar>
        + for<'a> ops::Mul<&'a Self::Point, Output = Self::Point>
        + ops::MulAssign
        + Zeroize
        + ByteSerialize
        + fmt::Debug;

    /// Return the identity
    fn identity() -> Self::Point;

    /// Return the basepoint, i.e., a generator defined by the spec to be used as a starting point for the group.
    fn basepoint() -> Self::Point;

    fn hash_to_point(payload: &[u8]) -> Self::Point;
    fn hash_to_scalar(payload: &[u8]) -> Self::Scalar;

    /// Generate (verifiably) independent generators
    /// FIXME: N is sometimes known only at runtime (e.g. when these generators are used in a mixnet)
    fn independent_generators<const N: usize>(prefix: &[u8]) -> Box<[Self::Point; N]>;

    /// Generate a random Point.
    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point;

    /// Generate a random scalar.
    fn scalar_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar;
}
