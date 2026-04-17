use crate::foundation::group::Group;
use crate::foundation::representation::{EncodedMessage, Message, MessageRange};
use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
pub use crate::primitives::encryption::representation::{
    Ciphertext, HomomorphicCiphertext, PublicKey, SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod el_gamal;
mod representation;
mod builder;

#[derive(Debug)]
pub struct KeyGen<'a, G: Group> {
    el_gamal: &'a ElGamal<G>,
}
impl<'a, G: Group> KeyGen<'a, G> {
    pub fn new(el_gamal: &'a ElGamal<G>) -> Self {
        Self { el_gamal }
    }

    pub fn generate_secret_key<R: RngCore + CryptoRng>(&self, rng: &mut R) -> SecretKey<G> {
        SecretKey {
            inner: self.el_gamal.generate_secret_key(rng),
        }
    }

    pub fn derive_public_key(&self, secret_key: &SecretKey<G>) -> PublicKey<G> {
        PublicKey {
            inner: self.el_gamal.derive_public_key(&secret_key.inner),
        }
    }
}

#[derive(Debug)]
pub struct Encrypt<'a, G: Group> {
    el_gamal: &'a ElGamal<G>,
}

impl<'a, G: Group> Encrypt<'a, G> {
    pub fn new(el_gamal: &'a ElGamal<G>) -> Self {
        Self {
            el_gamal,
        }
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        message: &EncodedMessage<G>,
    ) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);
        let (alpha, beta) = self
            .el_gamal
            .encrypt(&public_key.inner, &randomness, &message.inner);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        Ciphertext { alpha, beta }
    }

    pub fn reencrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        ciphertext: &Ciphertext<G>,
    ) -> Ciphertext<G> {
        let randomness = G::scalar_random(rng);

        let (alpha, beta) = self.el_gamal.reencrypt(
            &public_key.inner,
            &randomness,
            &(ciphertext.alpha, ciphertext.beta),
        );

        Ciphertext { alpha, beta }
    }
}

#[derive(Debug)]
pub struct EncryptHomomorph<'a, G: Group> {
    exponential_el_gamal: &'a ExponentialElGamal<'a, G>,
}

impl<'a, G: Group> EncryptHomomorph<'a, G> {
    pub fn new(exponential_el_gamal: &'a ExponentialElGamal<'a, G>) -> Self {
        Self {
            exponential_el_gamal,
        }
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        message: &Message<G>,
    ) -> HomomorphicCiphertext<G> {
        let randomness = G::scalar_random(rng);
        let (alpha, beta) =
            self.exponential_el_gamal
                .encrypt(&public_key.inner, &randomness, &message.inner);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        HomomorphicCiphertext { alpha, beta }
    }

    pub fn reencrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        ciphertext: &HomomorphicCiphertext<G>,
    ) -> HomomorphicCiphertext<G> {
        let randomness = G::scalar_random(rng);

        let (alpha, beta) = self.exponential_el_gamal.reencrypt(
            &public_key.inner,
            &randomness,
            &(ciphertext.alpha, ciphertext.beta),
        );

        HomomorphicCiphertext { alpha, beta }
    }
}

#[derive(Debug)]
pub struct Decrypt<'a, G: Group> {
    el_gamal: &'a ElGamal<G>,
}

impl<'a, G: Group> Decrypt<'a, G> {
    pub fn new(el_gamal: &'a ElGamal<G>) -> Self {
        Self {
            el_gamal,
        }
    }

    pub fn decrypt(
        &self,
        secret_key: &SecretKey<G>,
        ciphertext: &Ciphertext<G>,
    ) -> EncodedMessage<G> {
        let inner = self
            .el_gamal
            .decrypt(&secret_key.inner, &(ciphertext.alpha, ciphertext.beta));

        EncodedMessage { inner }
    }
}

#[derive(Debug)]
pub struct DecryptHomomorphInRange<'a, G: Group> {
    exponential_el_gamal: &'a ExponentialElGamal<'a, G>,
}

impl<'a, G: Group> DecryptHomomorphInRange<'a, G> {
    pub fn new(exponential_el_gamal: &'a ExponentialElGamal<'a, G>) -> Self {
        Self {
            exponential_el_gamal,
        }
    }

    pub fn decrypt(
        &self,
        secret_key: &SecretKey<G>,
        ciphertext: &HomomorphicCiphertext<G>,
        message_range: &MessageRange<G>,
    ) -> Option<Message<G>> {
        let inner = self.exponential_el_gamal.decrypt(
            &secret_key.inner,
            &(ciphertext.alpha, ciphertext.beta),
            &(message_range.start, message_range.end),
        )?;

        Some(Message { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = EncodedMessage::new(Curve::point_random(&mut rng));

        let encryption = Encrypt::<Curve>::new();
        let secret_key = encryption.generate_secret_key(&mut rng);
        let public_key = encryption.derive_public_key(&secret_key);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let ciphertext_reencrypted = encryption.reencrypt(&public_key, &mut rng, &ciphertext);
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext_reencrypted);

        assert_eq!(message_recovered, message);
    }

    #[test]
    fn homomorphic_encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let message = Message::new(Scalar::from(1u8));
        let message_2 = Message::new(Scalar::from(2u8));
        let message_range_2 = MessageRange::new(Scalar::from(2u8), Scalar::from(2u8));

        let encryption = HomomorphicEncryption::<Curve>::new();
        let secret_key = encryption.generate_secret_key(&mut rng);
        let public_key = encryption.derive_public_key(&secret_key);

        let ciphertext = encryption.encrypt(&public_key, &mut rng, &message);
        let ciphertext_reencrypted = encryption.reencrypt(&public_key, &mut rng, &ciphertext);
        let ciphertext_2 = &ciphertext_reencrypted + &ciphertext;
        let message_recovered = encryption.decrypt(&secret_key, &ciphertext_2, &message_range_2);

        assert_eq!(message_recovered, Some(message_2));
    }
}
