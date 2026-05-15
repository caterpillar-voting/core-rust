use crate::foundation::group::Group;
use crate::foundation::representation::{EncodedMessage};
use crate::primitives::encryption::el_gamal::{ElGamal};
pub use crate::primitives::encryption::representation::{Ciphertext, HomomorphicCiphertext, PublicKey, SecretKey};
use rand_core::{CryptoRng, RngCore};
use crate::primitives::zkp::proof_builder::el_gamal::HTDH2ProofBuilder;
use crate::primitives::zkp::{NIZKProof};
use crate::primitives::zkp::context::htdh2::HTDH2Hash;
use crate::primitives::zkp::representation::SecretKnowledge;

pub mod el_gamal;
mod representation;

#[cfg(test)]
mod _test_utils;

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
            g0: G::independent_generators::<1>(b"HTDH2ZKP")[0]
        }
    }
}

impl<G: Group> Encryption<G> {
    pub fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
        let secret_key = SecretKey(self.el_gamal.generate_secret_key(rng));

        let public_key = self.el_gamal.derive_public_key(&secret_key.0);

        (secret_key, public_key)
    }

    pub fn encrypt<R: RngCore + CryptoRng>(&self, public_key: &PublicKey<G>, rng: &mut R, message: &EncodedMessage<G>) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);
        let uv = self.el_gamal.encrypt(public_key, &randomness, message);

        let g0r = self.g0 * &randomness;
        let claim = HTDH2ProofBuilder::build_claim::<G>(self.g0, uv, g0r);
        let nizkp = NIZKProof::new(claim, HTDH2Hash::new(self.label.clone(), uv));

        let knowledge = HTDH2ProofBuilder::build_knowledge::<G>(Some(randomness));
        let proof = nizkp.prove(rng, &SecretKnowledge(knowledge));

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        (uv, g0r, proof)
    }

    pub fn decrypt(&self, secret_key: &SecretKey<G>, ciphertext: &Ciphertext<G>) -> Option<EncodedMessage<G>> {
        let (uv, g0r, proof) = ciphertext;

        let claim = HTDH2ProofBuilder::build_claim::<G>(self.g0, *uv, *g0r);
        let nizkp = NIZKProof::new(claim, HTDH2Hash::new(self.label.clone(), *uv));
        let verify = nizkp.verify(proof);
        if (!verify).into() {
            return None
        }

        Some(self.el_gamal.decrypt(&secret_key.0, &uv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = Curve::point_random(&mut rng);

        let encryption = Encryption::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext);

        assert_eq!(message_recovered, Some(message));
    }
}
