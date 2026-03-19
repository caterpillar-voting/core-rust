//! Wrapper around [`ristretto`]
//!
//! [`ristretto`]: https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ristretto/index.html

use crate::foundation::group::Group;
use crate::foundation::group::{ByteSerialize, Invertible};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint as RistrettoPointRaw},
    scalar::Scalar as RistrettoScalarRaw,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};

pub struct RistrettoGroup(());

impl ByteSerialize for RistrettoPointRaw {
    fn to_bytes(&self, out: &mut [u8]) {
        let bytes = &self.compress().to_bytes();
        out.copy_from_slice(bytes);
    }

    fn from_bytes(buffer: &[u8]) -> Option<Self> {
        CompressedRistretto::from_slice(buffer).ok()?.decompress()
    }
}

impl Invertible for RistrettoPointRaw {
    fn invert(&self) -> Option<Self>
    where
        Self: Sized,
    {
        Some(-self)
    }
}

impl ByteSerialize for RistrettoScalarRaw {
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

impl Invertible for RistrettoScalarRaw {
    fn invert(&self) -> Option<Self>
    where
        Self: Sized,
    {
        Some(self.invert())
    }
}

impl Group for RistrettoGroup {
    type Point = RistrettoPointRaw;
    type Scalar = RistrettoScalarRaw;

    fn generator() -> Self::Point {
        RISTRETTO_BASEPOINT_POINT
    }

    fn point_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Point {
        Self::Point::random(rng)
    }

    fn identity() -> Self::Point {
        Self::Point::identity()
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

    macro_rules! scalar_operation {
        ($rng: ident, $opr:tt) => {
            let r1: u64 = $rng.next_u64();
            let r2: u64 = $rng.next_u64();

            let group_scalar_opr = Scalar::from(r1) $opr Scalar::from(r2);
            let ristretto_scalar_opr = Scalar::from(r1) $opr Scalar::from(r2);
            assert_eq!(group_scalar_opr, ristretto_scalar_opr);
        };
    }

    #[test]
    fn scalar_operations() {
        // check that the Scalar and the Scalar operations lead to the same result
        let mut rng = thread_rng();
        scalar_operation!(rng, +);
        scalar_operation!(rng, -);
        scalar_operation!(rng, *);
    }

    #[test]
    fn neg_vs_add_sub() {
        // check that neg, add, sub are compatible
        let mut rng = thread_rng();
        let x = RistrettoPointRaw::random(&mut rng);
        let y = RistrettoPointRaw::random(&mut rng);
        let z1 = x - y;
        let minus_y = -y;
        let z2 = x + minus_y;
        assert_eq!(z1, z2);
    }

    #[test]
    fn point_isid() {
        let mut rng = rand::thread_rng();
        let scalar = RistrettoGroup::scalar_random(&mut rng);
        let zero = RistrettoGroup::generator() * scalar - RistrettoGroup::generator() * scalar;
        assert_eq!(zero, RistrettoGroup::identity());
    }

    #[test]
    fn point_from_bytes() {
        let g = RistrettoGroup::generator();
        let mut bytes = [0u8; 32];
        g.to_bytes(&mut bytes);
        let g_from_bytes = Point::from_bytes(&bytes).unwrap();

        assert_eq!(g, g_from_bytes)
    }

    #[test]
    fn scalar_from_bytes() {
        let mut rng = thread_rng();
        let e = RistrettoGroup::scalar_random(&mut rng);
        let mut bytes = [0u8; 32];
        ByteSerialize::to_bytes(&e, &mut bytes);
        let e_from_bytes = Scalar::from_bytes(&bytes).unwrap();

        assert_eq!(e, e_from_bytes)
    }
}

// endregion: --- Tests
