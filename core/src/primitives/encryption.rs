use crate::foundation::group::Group;
use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
use rand_core::{CryptoRng, RngCore};
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod el_gamal;

#[derive(Debug)]
pub struct Encryption<G: Group> {
    el_gamal: ElGamal<G>,
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

impl<G: Group> Message<G> {
    pub fn new(message: G::Point) -> Self {
        Self { inner: message }
    }
}

impl<G: Group> Encryption<G> {
    pub fn new() -> Self {
        Self {
            el_gamal: ElGamal::new(G::basepoint()),
        }
    }

    pub fn generate_secret_key<R: RngCore + CryptoRng>(&self, rng: &mut R) -> SecretKey<G> {
        SecretKey {
            inner: G::scalar_random(rng),
        }
    }

    pub fn derive_public_key(&self, secret_key: &SecretKey<G>) -> PublicKey<G> {
        PublicKey {
            inner: self.el_gamal.derive_public_key(&secret_key.inner),
        }
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        message: &Message<G>,
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

    pub fn decrypt(&self, secret_key: &SecretKey<G>, ciphertext: &Ciphertext<G>) -> Message<G> {
        let inner = self
            .el_gamal
            .decrypt(&secret_key.inner, &(ciphertext.alpha, ciphertext.beta));

        Message { inner }
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
pub struct HomomorphicEncryption<G: Group> {
    exponential_el_gamal: ExponentialElGamal<G>,
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

impl<G: Group> HomomorphicMessage<G> {
    pub fn new(message: G::Scalar) -> Self {
        Self { inner: message }
    }
}

impl<G: Group> HomomorphicMessageRange<G> {
    pub fn new(start: G::Scalar, end: G::Scalar) -> Self {
        Self { start, end }
    }
}

impl<'a, G: Group> HomomorphicEncryption<G> {
    pub fn new() -> Self {
        Self {
            exponential_el_gamal: ExponentialElGamal::new(G::basepoint()),
        }
    }

    pub fn generate_secret_key<R: RngCore + CryptoRng>(&self, rng: &mut R) -> SecretKey<G> {
        SecretKey {
            inner: G::scalar_random(rng),
        }
    }

    pub fn derive_public_key(&self, secret_key: &SecretKey<G>) -> PublicKey<G> {
        PublicKey {
            inner: self
                .exponential_el_gamal
                .derive_public_key(&secret_key.inner),
        }
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        public_key: &PublicKey<G>,
        rng: &mut R,
        message: &HomomorphicMessage<G>,
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

    pub fn decrypt(
        &self,
        secret_key: &SecretKey<G>,
        ciphertext: &HomomorphicCiphertext<G>,
        message_range: &HomomorphicMessageRange<G>,
    ) -> Option<HomomorphicMessage<G>> {
        let inner = self.exponential_el_gamal.decrypt(
            &secret_key.inner,
            &(ciphertext.alpha, ciphertext.beta),
            &(message_range.start, message_range.end),
        )?;

        Some(HomomorphicMessage { inner })
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

impl<G: Group> ops::Add<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;
    fn add(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext {
            alpha: self.alpha + &rhs.alpha,
            beta: self.beta + &rhs.beta,
        }
    }
}

impl<G: Group> ops::AddAssign<&HomomorphicCiphertext<G>> for HomomorphicCiphertext<G> {
    fn add_assign(&mut self, rhs: &HomomorphicCiphertext<G>) {
        self.alpha += rhs.alpha;
        self.beta += rhs.beta;
    }
}

impl<G: Group> ops::Sub<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;

    fn sub(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext {
            alpha: self.alpha - &rhs.alpha,
            beta: self.beta - &rhs.beta,
        }
    }
}

impl<G: Group> ops::SubAssign<&HomomorphicCiphertext<G>> for HomomorphicCiphertext<G> {
    fn sub_assign(&mut self, rhs: &HomomorphicCiphertext<G>) {
        self.alpha -= rhs.alpha;
        self.beta -= rhs.beta;
    }
}

impl<G: Group> ops::Add<&HomomorphicMessage<G>> for &HomomorphicMessage<G> {
    type Output = HomomorphicMessage<G>;
    fn add(self, rhs: &HomomorphicMessage<G>) -> Self::Output {
        HomomorphicMessage {
            inner: self.inner + &rhs.inner,
        }
    }
}

impl<G: Group> ops::AddAssign<&HomomorphicMessage<G>> for HomomorphicMessage<G> {
    fn add_assign(&mut self, rhs: &HomomorphicMessage<G>) {
        self.inner += rhs.inner;
    }
}

impl<G: Group> ops::Sub<&HomomorphicMessage<G>> for &HomomorphicMessage<G> {
    type Output = HomomorphicMessage<G>;

    fn sub(self, rhs: &HomomorphicMessage<G>) -> Self::Output {
        HomomorphicMessage {
            inner: self.inner - &rhs.inner,
        }
    }
}

impl<G: Group> ops::SubAssign<&HomomorphicMessage<G>> for HomomorphicMessage<G> {
    fn sub_assign(&mut self, rhs: &HomomorphicMessage<G>) {
        self.inner -= rhs.inner;
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
        let message = Message::new(Curve::point_random(&mut rng));

        let encryption = Encryption::<Curve>::new();
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
        let message = HomomorphicMessage::new(Scalar::from(1u8));
        let message_2 = HomomorphicMessage::new(Scalar::from(2u8));
        let message_range_2 = HomomorphicMessageRange::new(Scalar::from(2u8), Scalar::from(2u8));

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
