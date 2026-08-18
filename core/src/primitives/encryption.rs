use crate::foundation::group::Group;
use crate::foundation::representation::EncodedMessage;
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
    pub label: Vec<u8>,
    pub g0: G::Point,
}

impl<G: Group> Default for Encryption<G> {
    fn default() -> Self {
        Self {
            el_gamal: ElGamal::default(),
            label: b"ElGamal".to_vec(),
            g0: G::independent_generators::<1>(b"HTDH2ZKP")[0],
        }
    }
}

impl<G: Group> Encryption<G> {
    pub fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
        let secret_key = SecretKey(self.el_gamal.generate_secret_key(rng));

        let public_key = self.el_gamal.derive_public_key(&secret_key.0);

        (secret_key, public_key)
    }

    pub fn encrypt<R: RngCore + CryptoRng>(&self, public_key: &PublicKey<G>, context: &Context, rng: &mut R, message: &EncodedMessage<G>) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);
        let uv = self.el_gamal.encrypt(public_key, &randomness, message);

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
        if !zkp.verify(&self.g0, &uv, &proof.0, &proof.1, &proof.2, context) {
            return None;
        }

        Some(self.el_gamal.decrypt(&secret_key.0, uv))
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
