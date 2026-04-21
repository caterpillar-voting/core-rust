use crate::foundation::discrete_log::DiscreteLog;
use crate::foundation::group::Group;
use crate::foundation::representation::{EncodedMessage, Message};
use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
pub use crate::primitives::encryption::representation::{
    Ciphertext, HomomorphicCiphertext, PublicKey, SecretKey,
};
use rand_core::{CryptoRng, RngCore};

pub mod el_gamal;
mod representation;

#[cfg(test)]
mod _test_utils;

#[derive(Debug)]
pub struct Encryption<G: Group> {
    el_gamal: ElGamal<G>,
}

impl<G: Group> Default for Encryption<G> {
    fn default() -> Self {
        Self {
            el_gamal: ElGamal::default(),
        }
    }
}
impl<G: Group> Encryption<G> {
    pub fn new(el_gamal: ElGamal<G>) -> Self {
        Self { el_gamal }
    }

    pub fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
        let secret_key = SecretKey(self.el_gamal.generate_secret_key(rng));

        let public_key = self.el_gamal.derive_public_key(&secret_key.0);

        (secret_key, public_key)
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        message: &EncodedMessage<G>,
    ) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);
        let (alpha, beta) = self.el_gamal.encrypt(&public_key, &randomness, &message.0);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        (alpha, beta)
    }

    pub fn reencrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        ciphertext: &Ciphertext<G>,
    ) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);

        let (alpha, beta) =
            self.el_gamal
                .reencrypt(&public_key, &randomness, &(ciphertext.0, ciphertext.1));

        (alpha, beta)
    }

    pub fn decrypt(
        &self,
        secret_key: &SecretKey<G>,
        ciphertext: &Ciphertext<G>,
    ) -> EncodedMessage<G> {
        let decrypted = self
            .el_gamal
            .decrypt(&secret_key.0, &(ciphertext.0, ciphertext.1));

        EncodedMessage(decrypted)
    }
}

#[derive(Debug)]
pub struct EncryptionHomomorph<G: Group> {
    exponential_el_gamal: ExponentialElGamal<G>,
}

impl<G: Group> Default for EncryptionHomomorph<G> {
    fn default() -> Self {
        Self {
            exponential_el_gamal: ExponentialElGamal::default(),
        }
    }
}

impl<G: Group> EncryptionHomomorph<G> {
    pub fn new(exponential_el_gamal: ExponentialElGamal<G>) -> Self {
        Self {
            exponential_el_gamal,
        }
    }

    pub fn key_gen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
        let secret_key = SecretKey(self.exponential_el_gamal.0.generate_secret_key(rng));

        let public_key = self.exponential_el_gamal.0.derive_public_key(&secret_key.0);

        (secret_key, public_key)
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        message: &Message<G>,
    ) -> HomomorphicCiphertext<G> {
        let randomness = G::scalar_random(rng);
        let (alpha, beta) = self
            .exponential_el_gamal
            .encrypt(&public_key, &randomness, &message);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        HomomorphicCiphertext(alpha, beta)
    }

    pub fn reencrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        ciphertext: &HomomorphicCiphertext<G>,
    ) -> HomomorphicCiphertext<G> {
        let randomness = G::scalar_random(rng);

        let (alpha, beta) = self.exponential_el_gamal.0.reencrypt(
            &public_key,
            &randomness,
            &(ciphertext.0, ciphertext.1),
        );

        HomomorphicCiphertext(alpha, beta)
    }

    pub fn decrypt(
        &self,
        secret_key: &SecretKey<G>,
        ciphertext: &HomomorphicCiphertext<G>,
        decoder: &dyn DiscreteLog<G>,
    ) -> Option<Message<G>> {
        let decrypted = self.exponential_el_gamal.decrypt(
            &secret_key.0,
            &(ciphertext.0, ciphertext.1),
            decoder,
        )?;

        Some(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::discrete_log::GreedyDiscreteLog;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = EncodedMessage(Curve::point_random(&mut rng));

        let encryption = Encryption::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let ciphertext_reencrypted = encryption.reencrypt(&public_key, &mut rng, &ciphertext);
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext_reencrypted);

        assert_eq!(message_recovered, message);
    }

    #[test]
    fn homomorphic_encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = Scalar::from(1u8);
        let message_2 = Scalar::from(2u8);
        let message_decoder = GreedyDiscreteLog::new(Scalar::from(2u8), None);

        let encryption = EncryptionHomomorph::<Curve>::default();
        let (secret_key, public_key) = encryption.key_gen(&mut rng);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let ciphertext_reencrypted = encryption.reencrypt(&public_key, &mut rng, &ciphertext);
        let ciphertext_2 = &ciphertext_reencrypted + &ciphertext;
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext_2, &message_decoder);

        assert_eq!(message_recovered, Some(message_2));
    }
}
