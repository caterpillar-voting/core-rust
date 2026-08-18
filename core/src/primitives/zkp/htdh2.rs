use crate::foundation::group::Group;
use crate::primitives::zkp::get_challenge::{GetChallenge, get_challenge_default};
/**
https://www.usenix.org/legacy/event/evtwote11/tech/final_files/Bulens.pdf
section 4.1.4
*/
use rand_core::{CryptoRng, RngCore};

pub struct ZKPHTDH2<G: Group> {
    get_challenge: GetChallenge<G>,
}

impl<G: Group> Default for ZKPHTDH2<G> {
    fn default() -> Self {
        Self {
            get_challenge: get_challenge_default::<G>,
        }
    }
}

impl<G: Group> ZKPHTDH2<G> {
    pub fn new(get_challenge: GetChallenge<G>) -> Self {
        Self { get_challenge }
    }

    pub fn prove<R: RngCore + CryptoRng>(&self, g0: &G::Point, ue: &(G::Point, G::Point), r: &G::Scalar, ctx: &Vec<u8>, rng: &mut R) -> (G::Point, G::Scalar, G::Scalar) {
        let s = G::scalar_random(rng);
        let u0 = *g0 * &r;

        let w = G::basepoint() * &s;
        let w0 = *g0 * &s;

        let c = (self.get_challenge)(&vec![ue.0, ue.1, w, w0], ctx);
        let f = s + &(*r * &c);

        (u0, c, f)
    }

    pub fn verify(&self, g0: &G::Point, ue: &(G::Point, G::Point), u0: &G::Point, c: &G::Scalar, f: &G::Scalar, ctx: &Vec<u8>) -> bool {
        let w = G::basepoint() * f - &(ue.0 * &c);
        let w0 = *g0 * f - &(*u0 * &c);

        let c_dash = (self.get_challenge)(&vec![ue.0, ue.1, w, w0], ctx);

        *c == c_dash
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::discrete_log::ZKPDiscreteLog;

    type G = RistrettoGroup;

    #[test]
    pub fn prove_verify() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x, &ctx, &mut rng);

        assert!(zkp.verify(&h, &c, &r, &ctx));
    }

    #[test]
    pub fn cannot_prove_invalid_x() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();
        let x_dash = G::scalar_random(&mut rng);

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x_dash, &ctx, &mut rng);

        assert!(!zkp.verify(&h, &c, &r, &ctx));
    }

    #[test]
    pub fn cannot_verify_invalid_c_or_r() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x, &ctx, &mut rng);

        let random = G::scalar_random(&mut rng);
        assert!(!zkp.verify(&h, &random, &r, &ctx));
        assert!(!zkp.verify(&h, &c, &random, &ctx));
    }
}
