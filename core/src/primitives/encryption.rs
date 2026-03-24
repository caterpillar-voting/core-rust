use crate::foundation::group::Group;
use crate::primitives::encryption::el_gamal::ElGamal;
use crate::primitives::encryption::exponential_el_gamal::ExponentialElGamal;
use rand_core::{CryptoRng, RngCore};
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod el_gamal;
pub mod exponential_el_gamal;

#[derive(Debug)]
pub struct Encryption<'a, G: Group, R: RngCore + CryptoRng> {
    el_gamal: ElGamal<G>,
    rng: &'a mut R,
}

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group> {
    inner: G::Scalar,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey<G: Group> {
    inner: G::Point,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message<G: Group> {
    inner: G::Point,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext<G: Group> {
    alpha: G::Point,
    beta: G::Point,
    // TODO: include ZKP for CCA2
}

impl<'a, G: Group, R: RngCore + CryptoRng> Encryption<'a, G, R> {
    pub fn new(point: G::Point, rng: &'a mut R) -> Self {
        Self {
            el_gamal: ElGamal::new(point),
            rng,
        }
    }

    pub fn generate_secret_key(&mut self) -> SecretKey<G> {
        SecretKey {
            inner: G::scalar_random(&mut self.rng),
        }
    }

    pub fn derive_public_key(&self, secret_key: &SecretKey<G>) -> PublicKey<G> {
        PublicKey {
            inner: *self.el_gamal.g() * &secret_key.inner,
        }
    }

    pub fn encrypt(&mut self, public_key: &PublicKey<G>, message: &Message<G>) -> Ciphertext<G> {
        let randomness = G::scalar_random(self.rng);
        let (alpha, beta) = self
            .el_gamal
            .encrypt(&public_key.inner, &randomness, &message.inner);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        Ciphertext { alpha, beta }
    }

    pub fn decrypt(&self, secret_key: &SecretKey<G>, ciphertext: &Ciphertext<G>) -> Message<G> {
        let inner = self
            .el_gamal
            .decrypt(&secret_key.inner, (&ciphertext.alpha, &ciphertext.beta));

        Message { inner }
    }

    pub fn reencrypt(
        &mut self,
        public_key: &PublicKey<G>,
        ciphertext: &Ciphertext<G>,
    ) -> Ciphertext<G> {
        let randomness = G::scalar_random(self.rng);

        let (alpha, beta) = self.el_gamal.reencrypt(
            &public_key.inner,
            &randomness,
            (&ciphertext.alpha, &ciphertext.beta),
        );

        Ciphertext { alpha, beta }
    }
}

#[derive(Debug)]
pub struct HomomorphicEncryption<'a, G: Group, R: RngCore + CryptoRng> {
    exponential_el_gamal: ExponentialElGamal<G>,
    rng: &'a mut R,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HomomorphicMessage<G: Group> {
    inner: G::Scalar,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HomomorphicMessageRange<G: Group> {
    start: G::Scalar,
    end: G::Scalar,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HomomorphicCiphertext<G: Group> {
    alpha: G::Point,
    beta: G::Point,
    // TODO: include ZKP for CCA2
}

impl<'a, G: Group, R: RngCore + CryptoRng> HomomorphicEncryption<'a, G, R> {
    pub fn new(point: G::Point, rng: &'a mut R) -> Self {
        Self {
            exponential_el_gamal: ExponentialElGamal::new(point),
            rng,
        }
    }

    pub fn generate_secret_key(&mut self) -> SecretKey<G> {
        SecretKey {
            inner: G::scalar_random(&mut self.rng),
        }
    }

    pub fn derive_public_key(&self, secret_key: &SecretKey<G>) -> PublicKey<G> {
        PublicKey {
            inner: *self.exponential_el_gamal.g() * &secret_key.inner,
        }
    }

    pub fn encrypt(
        &mut self,
        public_key: &PublicKey<G>,
        message: &HomomorphicMessage<G>,
    ) -> HomomorphicCiphertext<G> {
        let randomness = G::scalar_random(self.rng);
        let (alpha, beta) =
            self.exponential_el_gamal
                .encrypt(&public_key.inner, &randomness, &message.inner);

        // we do not expose the randomness to the user.
        // the randomness could be misunderstood and stored together with the ciphertext, even in cases where it is not needed (e.g., no decryption using the randomness)
        // this deliberate choice also leads to not providing the method to decrypt using the randomness.

        HomomorphicCiphertext { alpha, beta }
    }

    pub fn decrypt(
        &self,
        secret_key: &SecretKey<G>,
        ciphertext: &HomomorphicCiphertext<G>,
        message_range: &HomomorphicMessageRange<G>,
    ) -> Option<HomomorphicMessage<G>> {
        let inner = self.exponential_el_gamal.decrypt(
            &secret_key.inner,
            (&ciphertext.alpha, &ciphertext.beta),
            (&message_range.start, &message_range.end),
        )?;

        Some(HomomorphicMessage { inner })
    }

    pub fn reencrypt(
        &mut self,
        public_key: &PublicKey<G>,
        ciphertext: &HomomorphicCiphertext<G>,
    ) -> HomomorphicCiphertext<G> {
        let randomness = G::scalar_random(self.rng);

        let (alpha, beta) = self.exponential_el_gamal.reencrypt(
            &public_key.inner,
            &randomness,
            (&ciphertext.alpha, &ciphertext.beta),
        );

        HomomorphicCiphertext { alpha, beta }
    }
}

impl<G: Group> ops::Add<&Ciphertext<G>> for &Ciphertext<G> {
    type Output = Ciphertext<G>;
    fn add(self, rhs: &Ciphertext<G>) -> Self::Output {
        Ciphertext {
            alpha: self.alpha + &rhs.alpha,
            beta: self.beta + &rhs.beta,
        }
    }
}
