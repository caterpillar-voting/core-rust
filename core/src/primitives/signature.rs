use crate::foundation::group::Group;
use crate::primitives::signature::schnorr::Schnorr;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod schnorr;

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(pub G::Scalar);

#[allow(type_alias_bounds)]
pub type PublicKey<G: Group> = G::Point;

#[allow(type_alias_bounds)]
pub type Message = Vec<u8>;

#[allow(type_alias_bounds)]
pub type Signature<G: Group> = (G::Scalar, G::Scalar);

#[derive(Debug)]
pub struct SchnorrSignature<G: Group> {
    pub schnorr: Schnorr<G>,
}

impl<G: Group> Default for SchnorrSignature<G> {
    fn default() -> Self {
        Self { schnorr: Schnorr::default() }
    }
}

impl<G: Group> SchnorrSignature<G> {
    pub fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
        let keygen = self.schnorr.keygen(rng);

        (SecretKey(keygen.0), keygen.1)
    }

    pub fn sign<R: RngCore + CryptoRng>(&self, secret_key: &SecretKey<G>, rng: &mut R, message: &Message) -> Signature<G> {
        let randomness = G::scalar_random(rng);
        let se = self.schnorr.sign(&secret_key.0, &randomness, message);

        se
    }

    pub fn verify(&self, public_key: &PublicKey<G>, message: &Message, signature: &Signature<G>) -> bool {
        self.schnorr.verify(public_key, message, &signature.0, &signature.1)
    }
}

pub mod hash;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = "test_message".as_bytes().to_vec();

        let schnorr_signature = SchnorrSignature::<G>::default();
        let (secret_key, public_key) = schnorr_signature.key_gen(&mut rng);

        let signature = schnorr_signature.sign(&secret_key, &mut rng, &message);
        assert!(schnorr_signature.verify(&public_key, &message, &signature));
    }
}
