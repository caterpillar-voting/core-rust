use crate::foundation::discrete_log::DiscreteLog;
use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamal<G: Group> {
    _marker: PhantomData<G>,
}

impl<G: Group> Default for ElGamal<G> {
    fn default() -> Self {
        Self { _marker: Default::default() }
    }
}

impl<G: Group> ElGamal<G> {
    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Point) {
        let sk = G::scalar_random(rng);
        let pk = G::basepoint() * &sk;

        (sk, pk)
    }

    pub fn encrypt(&self, pk: &G::Point, r: &G::Scalar, m: &G::Point) -> (G::Point, G::Point) {
        let alpha = G::basepoint() * r;
        let beta = *pk * r + m;

        (alpha, beta)
    }

    pub fn decrypt(&self, sk: &G::Scalar, ciphertext: &(G::Point, G::Point)) -> G::Point {
        let (alpha, beta) = ciphertext;

        *beta - &(*alpha * sk)
    }

    pub fn decrypt_randomness(&self, pk: &G::Point, r: &G::Scalar, ciphertext: &(G::Point, G::Point)) -> G::Point {
        // we explicitly do not check here whether g^r = alpha, as this is expensive

        let (_, beta) = ciphertext;
        let hiding_factor = *pk * r;

        *beta - &hiding_factor
    }

    pub fn reencrypt(&self, pk: &G::Point, r: &G::Scalar, ciphertext: &(G::Point, G::Point)) -> (G::Point, G::Point) {
        let (alpha, beta) = ciphertext;

        let alpha = G::basepoint() * r + alpha;
        let beta = *pk * r + beta;

        (alpha, beta)
    }
}

#[derive(Debug, PartialEq)]
pub struct ExponentialElGamal<G: Group>(pub ElGamal<G>);

impl<G: Group> Default for ExponentialElGamal<G> {
    fn default() -> Self {
        Self(ElGamal::default())
    }
}

impl<G: Group> ExponentialElGamal<G> {
    pub fn new(el_gamal: ElGamal<G>) -> Self {
        Self(el_gamal)
    }

    pub fn encrypt(&self, pk: &G::Point, r: &G::Scalar, m: &G::Scalar) -> (G::Point, G::Point) {
        let m_point = G::basepoint() * m;
        self.0.encrypt(pk, r, &m_point)
    }

    pub fn decrypt(&self, sk: &G::Scalar, ciphertext: &(G::Point, G::Point), decoder: &dyn DiscreteLog<G>) -> Option<G::Scalar> {
        let m_point = self.0.decrypt(sk, ciphertext);

        decoder.log(&m_point)
    }

    pub fn decrypt_randomness(&self, pk: &G::Point, r: &G::Scalar, ciphertext: &(G::Point, G::Point), decoder: &dyn DiscreteLog<G>) -> Option<G::Scalar> {
        let m_point = self.0.decrypt_randomness(pk, r, ciphertext);

        decoder.log(&m_point)
    }

    // we explicitly do not repeat the methods that remain the same towards ElGamal (e.g., key generation, renecryption)
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use crate::foundation::discrete_log::BruteForceDiscreteLog;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::_test_utils::{new_el_gamal_sample, new_exponential_el_gamal_sample};
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let (el_gamal, sk, pk, r, m) = new_el_gamal_sample(&mut rng);

        let ciphertext = el_gamal.encrypt(&pk, &r, &m);
        let m_decrypted = el_gamal.decrypt(&sk, &ciphertext);
        let m_decrypted_randomness = el_gamal.decrypt_randomness(&pk, &r, &ciphertext);

        assert_eq!(m_decrypted, m);
        assert_eq!(m_decrypted_randomness, m);
    }

    #[test]
    fn encrypt_reencrypt_and_decrypt() {
        let mut rng = thread_rng();
        let (el_gamal, sk, pk, r, m) = new_el_gamal_sample(&mut rng);

        let ciphertext = el_gamal.encrypt(&pk, &r, &m);

        let r_2 = G::scalar_random(&mut rng);
        let ciphertext_2 = el_gamal.reencrypt(&pk, &r_2, &ciphertext);

        let m_decrypted = el_gamal.decrypt(&sk, &ciphertext_2);
        let r_combined = r + &r_2;
        let m_decrypted_randomness = el_gamal.decrypt_randomness(&pk, &r_combined, &ciphertext_2);

        assert_eq!(m_decrypted, m);
        assert_eq!(m_decrypted_randomness, m);
    }

    #[test]
    fn exponential_encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let (exponential_el_gamal, sk, pk, r, m) = new_exponential_el_gamal_sample(&mut rng);

        let ciphertext = exponential_el_gamal.encrypt(&pk, &r, &m);
        let m_decoder = BruteForceDiscreteLog::new(m, None);
        let m_decrypted = exponential_el_gamal.decrypt(&sk, &ciphertext, &m_decoder);
        let m_decrypted_randomness = exponential_el_gamal.decrypt_randomness(&pk, &r, &ciphertext, &m_decoder);

        assert_eq!(m_decrypted, Some(m));
        assert_eq!(m_decrypted_randomness, Some(m));
    }

    #[test]
    fn exponential_encrypt_reencrypt_and_decrypt() {
        let mut rng = thread_rng();
        let (exponential_el_gamal, sk, pk, r, m) = new_exponential_el_gamal_sample(&mut rng);

        let ciphertext = exponential_el_gamal.encrypt(&pk, &r, &m);

        let r_2 = G::scalar_random(&mut rng);
        let ciphertext_2 = exponential_el_gamal.0.reencrypt(&pk, &r_2, &ciphertext);

        let m_decoder = BruteForceDiscreteLog::new(m, None);
        let m_decrypted = exponential_el_gamal.decrypt(&sk, &ciphertext_2, &m_decoder);
        let r_combined = r + &r_2;
        let m_decrypted_randomness = exponential_el_gamal.decrypt_randomness(&pk, &r_combined, &ciphertext_2, &m_decoder);

        assert_eq!(m_decrypted, Some(m));
        assert_eq!(m_decrypted_randomness, Some(m));
    }
}

// endregion: --- Tests
