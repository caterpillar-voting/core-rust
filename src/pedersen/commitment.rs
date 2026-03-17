use std::ops;
use crate::group::lib::group::Group;

/// Public parameters for Pedersen commitments.
#[derive(Clone, Debug, PartialEq)]
pub struct Parameters<G: Group> {
    pub point: G::Point, // blinding base H
    pub generators: Vec<G::Point>,
    pub list_len: usize,
}

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pedersen<G: Group> {
    pub commitment: G::Point,
}

impl<G: Group> Pedersen<G> {
    pub fn commit(
        params: &Parameters<G>,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
    ) -> Self {
        debug_assert!(messages.len() <= params.list_len);

        let mut scalars = Vec::with_capacity(1 + messages.len());
        let mut points = Vec::with_capacity(1 + messages.len());

        scalars.push(randomness);
        points.push(params.point);
        scalars.extend(messages);
        points.extend_from_slice(&params.generators[..messages.len()]);

        let commitment = G::vartime_multi_mul(scalars, points);
        Self { commitment }
    }

    /// Verify that `(messages, randomness)` open this commitment under
    /// `params`.
    pub fn verify(
        &self,
        params: &Parameters<G>,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
    ) -> Result<(), Error> {
        if messages.len() > params.list_len {
            return Err(Error::LengthMismatch);
        }
        let recomputed =
            Self::commit(params, messages, randomness).commitment;
        if self.commitment == recomputed {
            Ok(())
        } else {
            Err(Error::PedersenCommitmentMismatch)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; G::POINT_SIZE];
        G::point_to_bytes(&mut bytes, &self.commitment);
        bytes
    }

    pub fn from_bytes<A: AsRef<[u8]>>(bytes: A) -> Option<Self> {
        let p = G::point_from_bytes(&bytes.as_ref()[..G::POINT_SIZE])?;
        if G::is_id(&p) {
            None
        } else {
            Some(Pedersen { commitment: p })
        }
    }
}

impl<G: Group> ops::Add for Pedersen<G> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            commitment: self.commitment + &rhs.commitment,
        }
    }
}
impl<G: Group> ops::AddAssign for Pedersen<G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl<G: Group> ops::Sub for Pedersen<G> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            commitment: self.commitment - &rhs.commitment,
        }
    }
}
impl<G: Group> ops::SubAssign for Pedersen<G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl<G: Group> ops::Mul<&G::Scalar> for Pedersen<G> {
    type Output = Self;
    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            commitment: self.commitment * rhs,
        }
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    type Scalar = <Curve as GroupScalar>::Scalar;

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();
        let params = Parameters::<Curve>::new(5, &mut rng);
        let messages: Vec<Scalar> = (0..5).map(|_| Curve::scalar_random(&mut rng)).collect();

        let commitment = ExtendedPedersen::var_commit(&params, &messages, &mut rng).unwrap();
        let res = commitment
            .inner
            .verify(&params, &messages, commitment.randomness.expose());
        assert!(res.is_ok());
    }

    #[test]
    fn serialize_commitment() {
        {
            use serde_json;

            let mut rng = thread_rng();
            let params = Parameters::<Curve>::new(3, &mut rng);
            let messages: Vec<Scalar> = (0..3).map(|_| Curve::scalar_random(&mut rng)).collect();
            let commitment = ExtendedPedersen::const_commit(&params, &messages, &mut rng).unwrap();

            let json = serde_json::to_string(&params).unwrap();
            let de_params: Parameters<Curve> = serde_json::from_str(&json).unwrap();

            let json = serde_json::to_string(&commitment.inner).unwrap();
            let de_commitment: Pedersen<Curve> = serde_json::from_str(&json).unwrap();

            let res = de_commitment.verify(&de_params, &messages, commitment.randomness.expose());
            assert!(res.is_ok());
        }
    }

    #[test]
    fn homomorphic_properties() {
        let mut rng = thread_rng();
        let params = Parameters::<Curve>::new(3, &mut rng);
        let msgs1: Vec<Scalar> = (0..3).map(|_| Curve::scalar_random(&mut rng)).collect();
        let msgs2: Vec<Scalar> = (0..3).map(|_| Curve::scalar_random(&mut rng)).collect();

        let c1 = ExtendedPedersen::var_commit(&params, &msgs1, &mut rng).unwrap();
        let c2 = ExtendedPedersen::var_commit(&params, &msgs2, &mut rng).unwrap();

        let expected_r = c1.randomness.expose() + c2.randomness.expose();
        let c_sum = c1 + c2;

        let expected_msgs: Vec<Scalar> = msgs1.iter().zip(&msgs2).map(|(a, b)| *a + b).collect();

        assert!(c_sum
            .inner
            .verify(&params, &expected_msgs, &expected_r)
            .is_ok());
    }

    #[test]
    fn const_vs_var_commitment_equivalence() {
        let mut rng = thread_rng();
        let params = Parameters::<Curve>::new(4, &mut rng);
        let messages: Vec<Scalar> = (0..4).map(|_| Curve::scalar_random(&mut rng)).collect();
        let r = Curve::scalar_random(&mut rng);

        let c_var = Pedersen::var_commit_with_randomness(&params, &messages, &r);
        let c_const = Pedersen::const_commit_with_randomness(&params, &messages, &r);

        assert_eq!(c_var, c_const, "var_commit and const_commit mismatch");
    }
}

// endregion: --- Tests
