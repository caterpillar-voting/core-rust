use crate::foundation::group::Group;
use crate::primitives::zkp3::zkp_from_phi::{ZkpFromPhi, expected_output_know_dlp, phi_know_dlp, zero_g1_know_dlp};
use crate::primitives::zkp3::{InteractiveGenericZKP, ZkpItems};
use rand_core::{CryptoRng, RngCore};

pub struct KnowsDLogNIZKP<G: Group + Clone> {
    pub public_point: G::Point,
    pub context: Vec<u8>,
    zkp_dl: ZkpFromPhi<G>,
    pub_data: Vec<ZkpItems<G>>,
}

impl<G: Group + Clone> KnowsDLogNIZKP<G> {
    pub fn new(public_point: G::Point, context: Vec<u8>) -> Self {
        let zkp_dl = ZkpFromPhi::new(phi_know_dlp::<G>, zero_g1_know_dlp::<G>, expected_output_know_dlp::<G>);
        let pub_data = vec![ZkpItems::<G>::Point(public_point)];
        Self {
            public_point,
            context,
            zkp_dl,
            pub_data,
        }
    }

    // TODO: Shall we answer with (challenge, response) and recompute the commit from it?
    pub fn prove<R: RngCore + CryptoRng>(&self, witness: G::Scalar, rng: &mut R) -> (G::Point, G::Scalar) {
        // Convert to generic structures
        let witness = vec![ZkpItems::<G>::Scalar(witness)];
        // Do the proof
        let (commit, state) = self.zkp_dl.commit(&witness, &self.pub_data, rng);
        // FIXME: use context in challenge computation
        let challenge = self.zkp_dl.get_challenge(&self.pub_data, &commit);
        let response = self.zkp_dl.respond(&witness, challenge, &state);
        // Convert back to the flat types
        let commit = match commit[0] {
            ZkpItems::Point(x) => x,
            _ => panic!("Invalid type"),
        };
        let response = match response[0] {
            ZkpItems::Scalar(x) => x,
            _ => panic!("Invalid type"),
        };
        (commit, response)
    }

    pub fn verify(&self, commit: G::Point, response: G::Scalar) -> bool {
        // Convert to generic structures
        let commit = vec![ZkpItems::<G>::Point(commit)];
        let response = vec![ZkpItems::<G>::Scalar(response)];
        // Do the verification
        let challenge = self.zkp_dl.get_challenge(&self.pub_data, &commit);
        self.zkp_dl.interactive_verify(&commit, challenge, &response, &self.pub_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use crate::primitives::zkp3::wrapper::KnowsDLogNIZKP;
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn prove_and_verify() {
        let mut rng = thread_rng();
        let el_gamal = ElGamal::<G>::default();
        let sk = el_gamal.generate_secret_key(&mut rng);
        let pk = el_gamal.derive_public_key(&sk);

        let nizpk = KnowsDLogNIZKP::<G>::new(pk, b"Hello".to_vec());
        let proof = nizpk.prove(sk, &mut rng);
        let (commit, response) = proof;
        assert!(nizpk.verify(commit, response));
    }
}
