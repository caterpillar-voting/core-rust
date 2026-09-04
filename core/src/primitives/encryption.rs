use crate::foundation::group::Group;
use crate::foundation::message::{EncodedMessage, MessageEncoder};
use crate::primitives::encryption::el_gamal::ElGamal;
use crate::primitives::zkp::htdh2::ZKPHTDH2;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod el_gamal;

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(pub G::Scalar);

#[allow(type_alias_bounds)]
pub type PublicKey<G: Group> = G::Point;

#[allow(type_alias_bounds)]
pub type Context = Vec<u8>;

#[allow(type_alias_bounds)]
pub type Ciphertext<G: Group> = ((G::Point, G::Point), (G::Point, G::Scalar, G::Scalar));

#[derive(Debug)]
pub struct Encryption<G: Group> {
    pub el_gamal: ElGamal<G>,
    pub g0: G::Point,
}

impl<G: Group> Default for Encryption<G> {
    fn default() -> Self {
        Self {
            el_gamal: ElGamal::default(),
            g0: G::independent_generators(1, b"HTDH2ZKP")[0],
        }
    }
}

impl<G: Group> Encryption<G> {
    /* Not yet ready for use of mr-elgamal in the high-level API.
    pub fn new(max_message_length: Option<usize>, g0: Option<G::Point>) -> Self {
        let message_encoder = MessageEncoder::<G>::default();
        let g0 = g0.unwrap_or_else(|| G::independent_generators(1, b"HTDH2ZKP")[0]);
        let n = match max_message_length {
            Some(l) => message_encoder.number_of_points_from_message_length(l),
            None => 1,
        };
        let el_gamal = ElGamal::<G>::new(n);
        Self { el_gamal, g0 }
    }
     */

    pub fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
        assert_eq!(self.el_gamal.n, 1);
        let (secret_key, public_key) = self.el_gamal.keygen(rng);

        (SecretKey(secret_key[0]), public_key[0])
    }

    pub fn encrypt<R: RngCore + CryptoRng>(&self, public_key: &PublicKey<G>, context: &Context, rng: &mut R, message: &EncodedMessage<G>) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);
        let uv = self.el_gamal.encrypt(&[*public_key], &randomness, &[*message]);
        let uv = (uv[0], uv[1]);

        let zkp = ZKPHTDH2::<G>::default();
        let proof = zkp.prove(&self.g0, &uv, &randomness, context, rng);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        (uv, proof)
    }

    pub fn decrypt(&self, context: &Context, secret_key: &SecretKey<G>, ciphertext: &Ciphertext<G>) -> Option<EncodedMessage<G>> {
        let (uv, proof) = ciphertext;

        let zkp = ZKPHTDH2::<G>::default();
        if !zkp.verify(&self.g0, uv, &proof.0, &proof.1, &proof.2, context) {
            return None;
        }
        let uv = &[uv.0, uv.1];

        Some(self.el_gamal.decrypt(&[secret_key.0], uv)[0])
    }
}

#[cfg(test)]
mod _test_utils;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = G::point_random(&mut rng);

        let encryption = Encryption::<G>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ctx = "test_encrypt".as_bytes().to_vec();
        let ciphertext = encryption.encrypt(&public_key, &ctx, &mut rng, &message);
        let message_recovered = encryption.decrypt(&ctx, &secret_key, &ciphertext);

        assert_eq!(message_recovered, Some(message));
    }
}
