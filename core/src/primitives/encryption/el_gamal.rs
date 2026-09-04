use crate::foundation::discrete_log::DiscreteLog;
use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq)]
pub struct ElGamal<G: Group> {
    _marker: PhantomData<G>,
    pub(crate) n: usize, // Multi-recipient ElGamal, with n recipients
}

impl<G: Group> Default for ElGamal<G> {
    fn default() -> Self {
        Self { _marker: Default::default(), n: 1 }
    }
}

impl<G: Group> ElGamal<G> {
    pub fn new(n: usize) -> Self {
        Self { _marker: Default::default(), n }
    }

    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (Vec<G::Scalar>, Vec<G::Point>) {
        let sk = (0..self.n).map(|_| G::scalar_random(rng)).collect::<Vec<_>>();
        let pk = (0..self.n).map(|i| G::basepoint() * &sk[i]).collect::<Vec<_>>();

        (sk, pk)
    }

    pub fn encrypt(&self, pk: &[G::Point], r: &G::Scalar, m: &[G::Point]) -> (G::Point, Vec<G::Point>) {
        assert_eq!(pk.len(), self.n);
        assert_eq!(m.len(), self.n);
        let alpha = G::basepoint() * r;
        let beta = (0..self.n).map(|i| pk[i] * r + &m[i]).collect::<Vec<_>>();

        (alpha, beta)
    }

    pub fn decrypt(&self, sk: &[G::Scalar], ciphertext: &(G::Point, Vec<G::Point>)) -> Vec<G::Point> {
        let (alpha, beta) = ciphertext;
        assert_eq!(sk.len(), self.n);
        assert_eq!(beta.len(), self.n);

        (0..self.n).map(|i| beta[i] - &(*alpha * &sk[i])).collect::<Vec<_>>()
    }

    pub fn decrypt_randomness(&self, pk: &[G::Point], r: &G::Scalar, ciphertext: &(G::Point, Vec<G::Point>)) -> Vec<G::Point> {
        let (_alpha, beta) = ciphertext;
        assert_eq!(pk.len(), self.n);
        assert_eq!(beta.len(), self.n);
        // In production, we explicitly do not check here whether g^r = alpha, as this is expensive
        debug_assert!(*_alpha == G::basepoint() * r);

        (0..self.n).map(|i| beta[i] - &(pk[i] * r)).collect::<Vec<_>>()
    }

    pub fn reencrypt(&self, pk: &[G::Point], r: &G::Scalar, ciphertext: &(G::Point, Vec<G::Point>)) -> (G::Point, Vec<G::Point>) {
        let (alpha, beta) = ciphertext;
        assert_eq!(pk.len(), self.n);
        assert_eq!(beta.len(), self.n);

        let alpha = G::basepoint() * r + alpha;
        let beta = (0..self.n).map(|i| pk[i] * r + &beta[i]).collect::<Vec<_>>();

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
        assert_eq!(el_gamal.n, 1);
        Self(el_gamal)
    }

    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Point) {
        let (sk, pk) = self.0.keygen(rng);
        (sk[0], pk[0])
    }

    pub fn encrypt(&self, pk: &G::Point, r: &G::Scalar, m: &G::Scalar) -> (G::Point, G::Point) {
        let m_point = G::basepoint() * m;
        let c = self.0.encrypt(&[*pk], r, &[m_point]);
        (c.0, c.1[0])
    }

    pub fn decrypt(&self, sk: &G::Scalar, ciphertext: &(G::Point, G::Point), decoder: &dyn DiscreteLog<G>) -> Option<G::Scalar> {
        let c = (ciphertext.0, vec![ciphertext.1]);
        let m_point = self.0.decrypt(&[*sk], &c)[0];

        decoder.log(&m_point)
    }

    pub fn decrypt_randomness(&self, pk: &G::Point, r: &G::Scalar, ciphertext: &(G::Point, G::Point), decoder: &dyn DiscreteLog<G>) -> Option<G::Scalar> {
        let m_point = self.0.decrypt_randomness(&[*pk], r, &(ciphertext.0, vec![ciphertext.1]))[0];

        decoder.log(&m_point)
    }

    pub fn reencrypt(&self, pk: &G::Point, r: &G::Scalar, ciphertext: &(G::Point, G::Point)) -> (G::Point, G::Point) {
        let c = self.0.reencrypt(&[*pk], r, &(ciphertext.0, vec![ciphertext.1]));
        (c.0, c.1[0])
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use crate::foundation::discrete_log::BruteForceDiscreteLog;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::_test_utils::{new_el_gamal_sample, new_exponential_el_gamal_sample};
    use crate::primitives::encryption::el_gamal::ElGamal;
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
    fn multi_encrypt_decrypt_reencrypt() {
        let mut rng = thread_rng();
        let n = 5;
        let el_gamal = ElGamal::<G>::new(n);
        let (sk, pk) = el_gamal.keygen(&mut rng);
        let m = (0..n).map(|_| G::point_random(&mut rng)).collect::<Vec<_>>();
        let r = G::scalar_random(&mut rng);
        let ciphertext = el_gamal.encrypt(&pk, &r, &m);
        let m_decrypted = el_gamal.decrypt(&sk, &ciphertext);
        let m_decrypted_randomness = el_gamal.decrypt_randomness(&pk, &r, &ciphertext);
        assert_eq!(m_decrypted, m);
        assert_eq!(m_decrypted_randomness, m);

        let r2 = G::scalar_random(&mut rng);
        let ciphertext2 = el_gamal.reencrypt(&pk, &r2, &ciphertext);
        let m_decrypted2 = el_gamal.decrypt(&sk, &ciphertext2);
        let r_combined = r + &r2;
        let m_decrypted_randomness2 = el_gamal.decrypt_randomness(&pk, &r_combined, &ciphertext2);
        assert_eq!(m_decrypted2, m);
        assert_eq!(m_decrypted_randomness2, m);
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
        let ciphertext_2 = exponential_el_gamal.reencrypt(&pk, &r_2, &ciphertext);

        let m_decoder = BruteForceDiscreteLog::new(m, None);
        let m_decrypted = exponential_el_gamal.decrypt(&sk, &ciphertext_2, &m_decoder);
        let r_combined = r + &r_2;
        let m_decrypted_randomness = exponential_el_gamal.decrypt_randomness(&pk, &r_combined, &ciphertext_2, &m_decoder);

        assert_eq!(m_decrypted, Some(m));
        assert_eq!(m_decrypted_randomness, Some(m));
    }
}

// endregion: --- Tests
