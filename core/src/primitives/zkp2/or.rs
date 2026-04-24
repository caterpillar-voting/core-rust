use rand_core::{CryptoRng, RngCore};
use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp2::reenc::{ReEncZKP, ReEncZKPChallenge, ReEncZKPCommit, ReEncZKPContext, ReEncZKPProof, ReEncZKPPublicData, ReEncZKPResponse, ReEncZKPState, ReEncZKPWitness};
use crate::primitives::zkp2::{ZKP, SigmaZKP, SimulableZKP};

// The two ZKPs that we want to combine with an OR
// The goal is to write everything in terms of these two aliases,
// so that we can have a macro at some point.
type ZKP1<G> = ReEncZKP<G>;
type ZKP2<G> = ReEncZKP<G>;


// No more refs to RencZKP below this line ?
#[derive(Clone)]
pub struct OrTwoReEncZKP<G> where G: Group {
    zkp1: ZKP1<G>,
    zkp2: ZKP2<G>,
    context: Vec<u8>,
}
// Only one of the two witnesses is needed, the other one is None
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPWitness<G> where G: Group {
    zkp1_witness: Option<<ZKP1<G> as ZKP<G>>::Witness>,
    zkp2_witness: Option<<ZKP2<G> as ZKP<G>>::Witness>,
}
pub type OrTwoReEncZKPContext = Vec<u8>;
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPCommit<G> where G: Group {
    zkp1_commit: <ZKP1<G> as SigmaZKP<G>>::Commit,
    zkp2_commit: <ZKP2<G> as SigmaZKP<G>>::Commit,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPResponse<G> where G: Group {
    zkp1_response: <ZKP1<G> as SigmaZKP<G>>::Response,
    zkp2_response: <ZKP2<G> as SigmaZKP<G>>::Response,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPProofChallenge<G> where G: Group{
    chal1: <G as Group>::Scalar,
    chal2: <G as Group>::Scalar,
}
// The real challenge is the sum of the two challenges in the Proof structure
pub type OrTwoReEncZKPChallenge<G> = <G as Group>::Scalar;
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPState<G> where G: Group {
    side: u8, // remember which one is the one that is simulated
    // when witness is known for zkp1:
    zkp1_state: Option<<ZKP1<G> as SigmaZKP<G>>::State>,
    zkp2_simulated: Option<<ZKP2<G> as ZKP<G>>::Proof>,
    // when witness is known for zkp2:
    zkp2_state: Option<<ZKP2<G> as SigmaZKP<G>>::State>,
    zkp1_simulated: Option<<ZKP1<G> as ZKP<G>>::Proof>,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPPublicData<G> where G: Group {
    zkp1_pubdata: <ZKP1<G> as ZKP<G>>::PublicData,
    zkp2_pubdata: <ZKP2<G> as ZKP<G>>::PublicData,
}
#[derive(Copy, Clone)]
pub struct OrTwoReEncZKPProof<G: Group> {
    commit: OrTwoReEncZKPCommit<G>,
    challenge: OrTwoReEncZKPProofChallenge<G>,
    response: OrTwoReEncZKPResponse<G>
}


impl<G> OrTwoReEncZKP<G> where G: Group
{
    pub fn new(zkp1: ZKP1<G>, zkp2: ZKP2<G>, context: Vec<u8>) -> Self {
        Self { zkp1, zkp2, context }
    }

    fn commit<R: RngCore + CryptoRng>(&self, witness: &OrTwoReEncZKPWitness<G>, rng: &mut R)
                                      -> (OrTwoReEncZKPCommit<G>, OrTwoReEncZKPState<G>) {
        assert!(witness.zkp1_witness != None || witness.zkp2_witness != None);
        if witness.zkp1_witness.is_some() {
            let pf2 = self.zkp2.simulate(rng);
            let (com1, st1) = self.zkp1.commit(&witness.zkp1_witness.unwrap(), rng);
            let com = OrTwoReEncZKPCommit {
                zkp1_commit: com1,
                zkp2_commit: pf2.commit
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

    fn respond(&self, state: OrTwoReEncZKPState<G>, challenge: OrTwoReEncZKPChallenge<G>)
            -> (OrTwoReEncZKPResponse<G>, OrTwoReEncZKPProofChallenge<G>) {
        assert!(state.side == 1 || state.side == 2);
        if state.side == 1 {
            assert!(state.zkp1_state.is_some());
            assert!(state.zkp2_simulated.is_some());
            let st2 = state.zkp2_simulated.unwrap();
            let chal1 = st2.challenge - &challenge;
            let resp1 = self.zkp1.respond(&state.zkp1_state.unwrap(), &chal1);
            let chal = OrTwoReEncZKPProofChallenge {
                chal1: chal1,
                chal2: st2.challenge,
            };
            let resp = OrTwoReEncZKPResponse {
                zkp1_response: resp1,
                zkp2_response: st2.response,
            };
            (resp, chal)
        } else {
            assert!(state.zkp2_state.is_some());
            assert!(state.zkp1_simulated.is_some());
            let st1 = state.zkp1_simulated.unwrap();
            let chal2 = st1.challenge - &challenge;
            let resp2 = self.zkp2.respond(&state.zkp2_state.unwrap(), &chal2);
            let chal = OrTwoReEncZKPProofChallenge {
                chal1: st1.challenge,
                chal2: chal2,
            };
            let resp = OrTwoReEncZKPResponse {
                zkp1_response: st1.response,
                zkp2_response: resp2,
            };
            (resp, chal)
        }
    }

    fn get_challenge(&self, commit: &OrTwoReEncZKPCommit<G>)
                     -> OrTwoReEncZKPChallenge<G> {
        let mut buf = VectorContextHash::new(self.context.clone());
        let chal1 = self.zkp1.get_challenge(&commit.zkp1_commit);
        let chal2 = self.zkp2.get_challenge(&commit.zkp2_commit);
        <VectorContextHash as ContextHash<G>>::add_scalar(&mut buf, &chal1);
        <VectorContextHash as ContextHash<G>>::add_scalar(&mut buf, &chal2);
        <VectorContextHash as ContextHash<G>>::hash_to_scalar(&mut buf)
    }
    fn verify(&self, commit: &OrTwoReEncZKPCommit<G>, sum_challenges: &OrTwoReEncZKPChallenge<G>, challenge: &OrTwoReEncZKPProofChallenge<G>, response: &OrTwoReEncZKPResponse<G>)
              -> bool {
        let pf1 = ReEncZKPProof {
            commit: commit.zkp1_commit,
            challenge: challenge.chal1,
            response: response.zkp1_response,
        };
        let pf2 = ReEncZKPProof {
            commit: commit.zkp2_commit,
            challenge: challenge.chal2,
            response: response.zkp2_response,
        };
        let chal = pf1.challenge + &pf2.challenge;
        chal == *sum_challenges && self.zkp1.verify(&pf1) && self.zkp2.verify(&pf2)
    }
    fn simulate<R : RngCore + CryptoRng>(&self, rng: &mut R) -> (OrTwoReEncZKPProof<G>) {
        let pf1 = self.zkp1.simulate(rng);
        let pf2 = self.zkp2.simulate(rng);
        let commit = OrTwoReEncZKPCommit {
            zkp1_commit: pf1.commit,
            zkp2_commit: pf2.commit,
        };
        let challenge = OrTwoReEncZKPProofChallenge {
            chal1: pf1.challenge,
            chal2: pf2.challenge,
        };
        let response = OrTwoReEncZKPResponse {
            zkp1_response: pf1.response,
            zkp2_response: pf2.response,
        };
        let pf = OrTwoReEncZKPProof {
            commit: commit,
            challenge: challenge,
            response: response,
        };
        pf
    }
}

impl<G> ZKP<G> for OrTwoReEncZKP<G> where G: Group{
    type PublicData = OrTwoReEncZKPPublicData<G>;
    type Witness = OrTwoReEncZKPWitness<G>;
    type Context = OrTwoReEncZKPContext;
    type Proof = OrTwoReEncZKPProof<G>;
    fn prove<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R)
                                     -> (Self::Proof) {
        let (commit, state) = Self::commit(&self, witness, rng);
        let sum_chal = Self::get_challenge(&self, &commit);
        let (response, chal) = Self::respond(&self, state, sum_chal);
        (
            OrTwoReEncZKPProof {
                commit: commit,
                challenge: chal,
                response: response,
            }
        )
    }

    fn verify(&self, proof: &Self::Proof) -> bool {
        let sum_chal = Self::get_challenge(&self, &proof.commit);
        Self::verify(&self, &proof.commit, &sum_chal, &proof.challenge, &proof.response)
    }
}

impl<G> SigmaZKP<G> for OrTwoReEncZKP<G> where G: Group + Clone + Copy {
    type Commit = OrTwoReEncZKPCommit<G>;
    type Challenge = OrTwoReEncZKPChallenge<G>;
    type Response = OrTwoReEncZKPResponse<G>;
    type State = OrTwoReEncZKPState<G>;
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Self::Witness, rng: &mut R) -> (Self::Commit, Self::State) {
        Self::commit(&self, witness, rng)
    }
    fn get_challenge(&self, commit: &Self::Commit) -> (Self::Challenge) {
        Self::get_challenge(&self, commit)
    }
    fn respond(&self, state: &Self::State, challenge: &Self::Challenge) -> (Self::Response) {
        let st = state.clone();
        let chal = challenge.clone();
        let (resp, _) = Self::respond(&self, st, chal);
        resp
    }
}

impl<G> SimulableZKP<G> for OrTwoReEncZKP<G> where G: Group + Clone + Copy {
    fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (Self::Proof) {
        Self::simulate(&self, rng)
    }
}