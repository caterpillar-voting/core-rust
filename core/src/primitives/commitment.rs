pub mod pedersen;

use crate::foundation::group::Group;
use crate::primitives::commitment::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Debug, PartialEq)]
pub struct HidingCommitment<G: Group> {
    pedersen: Pedersen<G>,
    messages_size: usize,
}

/// Unified error type for this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Messages are of different length as foreseen.
    MessagesLengthMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Message<G: Group> {
    inner: G::Scalar,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Commitment<G: Group> {
    inner: G::Point,
}
#[derive(Debug, PartialEq, Eq)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretRandomness<G: Group> {
    inner: G::Scalar,
}

impl<G: Group> HidingCommitment<G> {
    pub fn new(messages_size: usize) -> Self {
        let pedersen = Pedersen::new(
            G::basepoint(),
            G::independent_generators(b"PedersenParameters", messages_size),
        );
        Self {
            pedersen,
            messages_size,
        }
    }

    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        messages: &[Message<G>],
    ) -> Result<(Commitment<G>, SecretRandomness<G>), Error> {
        if messages.len() != self.messages_size {
            return Err(Error::MessagesLengthMismatch);
        }

        let randomness = G::scalar_random(rng);
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.inner).collect();
        let commitment = self.pedersen.commit(&randomness, &scalar_messages);

        Ok((
            Commitment { inner: commitment },
            SecretRandomness { inner: randomness },
        ))
    }

    pub fn verify(
        &self,
        messages: &[Message<G>],
        commitment: &Commitment<G>,
        randomness: &SecretRandomness<G>,
    ) -> Result<bool, Error> {
        if messages.len() != self.messages_size {
            return Err(Error::MessagesLengthMismatch);
        }

        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.inner).collect();
        Ok(self.pedersen.commit(&randomness.inner, &scalar_messages) == commitment.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::{thread_rng};

    type Curve = RistrettoGroup;
    type Scalar = <Curve as Group>::Scalar;


    fn new_messages(n: usize) -> Vec<Message<Curve>> {
        (0..n).map(|i| Message::<Curve> {
            inner: Scalar::from(u32::try_from(i).unwrap()),
        }).collect()
    }

    #[test]
    fn commit_and_verify() {
        let mut rng = thread_rng();

        let hiding_commitment = HidingCommitment::new(2);

        let messages = new_messages(2);
        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages).unwrap();

        assert_eq!(
            hiding_commitment.verify(&messages, &commitment, &randomness),
            Ok(true)
        );
    }

    #[test]
    fn invalid_commit_and_verify() {
        let mut rng = thread_rng();

        let hiding_commitment = HidingCommitment::new(2);
        let messages = new_messages(2);

        let to_few_messages = new_messages(1);
        let to_many_messages = new_messages(3);
        assert_eq!(hiding_commitment.commit(&mut rng, &to_few_messages), Err(Error::MessagesLengthMismatch));
        assert_eq!(hiding_commitment.commit(&mut rng, &to_many_messages), Err(Error::MessagesLengthMismatch));

        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages).unwrap();
        assert_eq!(hiding_commitment.verify(&to_few_messages, &commitment, &randomness), Err(Error::MessagesLengthMismatch));
        assert_eq!(hiding_commitment.verify(&to_many_messages, &commitment, &randomness), Err(Error::MessagesLengthMismatch));
    }
}
