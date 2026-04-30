use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp2;
use crate::primitives::zkp2::reenc::{ReEncZKP, ReEncZKPProof};
use crate::primitives::zkp2::{Challenge, SigmaZKP, SimulableZKP, ZKP};
use rand_core::{CryptoRng, RngCore};

// The two ZKPs that we want to combine with an OR
// The goal is to write everything in terms of these two aliases,
// so that we can have a macro at some point.
type ZKP1<G> = ReEncZKP<G>;
type ZKP2<G> = ReEncZKP<G>;

// No more refs to RencZKP below this line ?
#[derive(Clone)]
pub struct OrTwoReEncZKP<G>
where
    G: Group,
{
    zkp1: ZKP1<G>,
    zkp2: ZKP2<G>,
    #[allow(unused)]
    public_data: OrTwoReEncZKPPublicData<G>,
    context: Vec<u8>,
}
// Only one of the two witnesses is needed, the other one is None
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPWitness<G>
where
    G: Group,
{
    pub zkp1_witness: Option<<ZKP1<G> as ZKP<G>>::Witness>,
    pub zkp2_witness: Option<<ZKP2<G> as ZKP<G>>::Witness>,
}
pub type OrTwoReEncZKPContext = Vec<u8>;
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPCommit<G>
where
    G: Group,
{
    zkp1_commit: <ZKP1<G> as SigmaZKP<G>>::Commit,
    zkp2_commit: <ZKP2<G> as SigmaZKP<G>>::Commit,
}

#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPInnerChallenges<G>
where
    G: Group,
{
    chal1: Challenge<G>,
    chal2: Challenge<G>,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPResponse<G>
where
    G: Group,
{
    zkp1_response: <ZKP1<G> as SigmaZKP<G>>::Response,
    zkp2_response: <ZKP2<G> as SigmaZKP<G>>::Response,
    inner_challenges: OrTwoReEncZKPInnerChallenges<G>,
}
// The real challenge is the sum of the two inner challenges
pub type OrTwoReEncZKPChallenge<G> = Challenge<G>;
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPState<G>
where
    G: Group,
{
    side: u8, // remember which one is the one that is simulated
    // when witness is known for zkp1:
    zkp1_state: Option<<ZKP1<G> as SigmaZKP<G>>::State>,
    zkp2_simulated: Option<<ZKP2<G> as ZKP<G>>::Proof>,
    // when witness is known for zkp2:
    zkp2_state: Option<<ZKP2<G> as SigmaZKP<G>>::State>,
    zkp1_simulated: Option<<ZKP1<G> as ZKP<G>>::Proof>,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPPublicData<G>
where
    G: Group,
{
    #[allow(unused)]
    zkp1_pubdata: <ZKP1<G> as ZKP<G>>::PublicData,
    #[allow(unused)]
    zkp2_pubdata: <ZKP2<G> as ZKP<G>>::PublicData,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPProof<G: Group> {
    commit: OrTwoReEncZKPCommit<G>,
    challenge: Challenge<G>,
    response: OrTwoReEncZKPResponse<G>,
}

impl<G> OrTwoReEncZKP<G>
where
    G: Group + Clone + Copy,
{
    pub fn new(zkp1: ZKP1<G>, zkp2: ZKP2<G>, context: Vec<u8>) -> Self {
        let public_data = OrTwoReEncZKPPublicData {
            zkp1_pubdata: zkp1.public_data,
            zkp2_pubdata: zkp2.public_data,
        };
        Self { zkp1, zkp2, public_data, context }
    }

    fn commit<R: RngCore + CryptoRng>(&self, witness: &OrTwoReEncZKPWitness<G>, rng: &mut R) -> (OrTwoReEncZKPCommit<G>, OrTwoReEncZKPState<G>) {
        assert!(witness.zkp1_witness.is_some() || witness.zkp2_witness.is_some());
        if let Some(zkp1_witness) = witness.zkp1_witness {
            let pf2 = self.zkp2.simulate(rng);
            assert!(self.zkp2.interactive_verify(&pf2.commit, &pf2.challenge, &pf2.response));
            let (com1, st1) = self.zkp1.commit(&zkp1_witness, rng);
            let com = OrTwoReEncZKPCommit {
                zkp1_commit: com1,
                zkp2_commit: pf2.commit,
            };
            let state = OrTwoReEncZKPState {
                side: 1,
                zkp1_state: Some(st1),
                zkp2_simulated: Some(pf2),
                zkp2_state: None,
                zkp1_simulated: None,
            };
            (com, state)
        } else {
            let pf1 = self.zkp1.simulate(rng);
            assert!(self.zkp1.interactive_verify(&pf1.commit, &pf1.challenge, &pf1.response));
            let (com2, st2) = self.zkp2.commit(&witness.zkp2_witness.unwrap(), rng);
            let com = OrTwoReEncZKPCommit {
                zkp1_commit: pf1.commit,
                zkp2_commit: com2,
            };
            let state = OrTwoReEncZKPState {
                side: 2,
                zkp1_state: None,
                zkp2_simulated: None,
                zkp2_state: Some(st2),
                zkp1_simulated: Some(pf1),
            };
            (com, state)
        }
    }

    fn respond(&self, state: OrTwoReEncZKPState<G>, challenge: OrTwoReEncZKPChallenge<G>) -> OrTwoReEncZKPResponse<G> {
        assert!(state.side == 1 || state.side == 2);
        if state.side == 1 {
            assert!(state.zkp1_state.is_some());
            assert!(state.zkp2_simulated.is_some());
            let st2 = state.zkp2_simulated.unwrap();
            let chal1 = challenge - &st2.challenge;
            let resp1 = self.zkp1.respond(&state.zkp1_state.unwrap(), &chal1);
            let chal = OrTwoReEncZKPInnerChallenges { chal1, chal2: st2.challenge };

            OrTwoReEncZKPResponse {
                zkp1_response: resp1,
                zkp2_response: st2.response,
                inner_challenges: chal,
            }
        } else {
            assert!(state.zkp2_state.is_some());
            assert!(state.zkp1_simulated.is_some());
            let st1 = state.zkp1_simulated.unwrap();
            let chal2 = challenge - &st1.challenge;
            let resp2 = self.zkp2.respond(&state.zkp2_state.unwrap(), &chal2);
            let chal = OrTwoReEncZKPInnerChallenges { chal1: st1.challenge, chal2 };

            OrTwoReEncZKPResponse {
                zkp1_response: st1.response,
                zkp2_response: resp2,
                inner_challenges: chal,
            }
        }
    }

    fn get_challenge(&self, commit: &OrTwoReEncZKPCommit<G>) -> OrTwoReEncZKPChallenge<G> {
        let mut buf = VectorContextHash::new(self.context.clone());
        let chal1 = self.zkp1.get_challenge(&commit.zkp1_commit);
        let chal2 = self.zkp2.get_challenge(&commit.zkp2_commit);
        <VectorContextHash as ContextHash<G>>::add_scalar(&mut buf, &chal1);
        <VectorContextHash as ContextHash<G>>::add_scalar(&mut buf, &chal2);
        <VectorContextHash as ContextHash<G>>::hash_to_scalar(&buf)
    }
    fn verify(&self, commit: &OrTwoReEncZKPCommit<G>, sum_challenges: &OrTwoReEncZKPChallenge<G>, response: &OrTwoReEncZKPResponse<G>) -> bool {
        let pf1: ReEncZKPProof<G> = ReEncZKPProof {
            commit: commit.zkp1_commit,
            challenge: response.inner_challenges.chal1,
            response: response.zkp1_response,
        };
        let pf2: ReEncZKPProof<G> = ReEncZKPProof {
            commit: commit.zkp2_commit,
            challenge: response.inner_challenges.chal2,
            response: response.zkp2_response,
        };
        assert!(self.zkp1.interactive_verify(&pf1.commit, &pf1.challenge, &pf1.response));
        assert!(self.zkp2.interactive_verify(&pf2.commit, &pf2.challenge, &pf2.response));
        let chal = pf1.challenge + &pf2.challenge;
        assert!(chal == *sum_challenges);
        chal == *sum_challenges && self.zkp1.interactive_verify(&pf1.commit, &pf1.challenge, &pf1.response) && self.zkp2.interactive_verify(&pf2.commit, &pf2.challenge, &pf2.response)
    }
    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> OrTwoReEncZKPProof<G> {
        let pf1 = self.zkp1.simulate(rng);
        let pf2 = self.zkp2.simulate(rng);
        let commit = OrTwoReEncZKPCommit {
            zkp1_commit: pf1.commit,
            zkp2_commit: pf2.commit,
        };
        let inner_challenges = OrTwoReEncZKPInnerChallenges {
            chal1: pf1.challenge,
            chal2: pf2.challenge,
        };
        let chal = inner_challenges.chal1 + &inner_challenges.chal2;
        let response = OrTwoReEncZKPResponse {
            zkp1_response: pf1.response,
            zkp2_response: pf2.response,
            inner_challenges,
        };

        OrTwoReEncZKPProof { commit, challenge: chal, response }
    }
}

impl<G> ZKP<G> for OrTwoReEncZKP<G>
where
    G: Group + Clone + Copy,
{
    type PublicData = OrTwoReEncZKPPublicData<G>;
    type Witness = OrTwoReEncZKPWitness<G>;
    type Context = OrTwoReEncZKPContext;
    type Proof = OrTwoReEncZKPProof<G>;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> Self::Proof {
        let (commit, state) = Self::commit(self, witness, rng);
        let challenge = Self::get_challenge(self, &commit);
        let response = Self::respond(self, state, challenge);
        OrTwoReEncZKPProof { commit, challenge, response }
    }

    fn verify(&self, proof: &Self::Proof) -> bool {
        let sum_chal = Self::get_challenge(self, &proof.commit);
        assert!(proof.challenge == sum_chal);
        Self::verify(self, &proof.commit, &sum_chal, &proof.response)
    }
}

impl<G> SigmaZKP<G> for OrTwoReEncZKP<G>
where
    G: Group + Clone + Copy,
{
    type Commit = OrTwoReEncZKPCommit<G>;
    //    type Challenge = OrTwoReEncZKPChallenge<G>;
    type Response = OrTwoReEncZKPResponse<G>;
    type State = OrTwoReEncZKPState<G>;
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> (Self::Commit, Self::State) {
        Self::commit(self, witness, rng)
    }
    fn get_challenge(&self, commit: &Self::Commit) -> zkp2::Challenge<G> {
        Self::get_challenge(self, commit)
    }
    fn respond(&self, state: &Self::State, challenge: &zkp2::Challenge<G>) -> Self::Response {
        let st = *state;
        let chal = *challenge;

        Self::respond(self, st, chal)
    }

    fn interactive_verify(&self, commit: &Self::Commit, challenge: &Challenge<G>, response: &Self::Response) -> bool {
        Self::verify(self, commit, challenge, response)
    }
}

impl<G> SimulableZKP<G> for OrTwoReEncZKP<G>
where
    G: Group + Clone + Copy,
{
    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self::Proof {
        Self::simulate(self, rng)
    }
}
