use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp::proof::{Claim, ProofCommit, ProofResponse};

pub trait ProofTreeContextHash<G: Group> {
    fn add_claim(&mut self, claim: &Claim<G>);
    fn add_prepared_proof(&mut self, prepared_proof: &ProofCommit<G>);
    fn add_proof(&mut self, proof: &ProofResponse<G>);
}

impl<G: Group> ProofTreeContextHash<G> for VectorContextHash {
    fn add_claim(&mut self, claim: &Claim<G>) {
        claim.into_iter().for_each(|statements| {
            statements.iter().for_each(|statement| {
                <VectorContextHash as ContextHash<G>>::add_point(self, &statement.z);
            })
        })
    }

    fn add_prepared_proof(&mut self, prepared_proof: &ProofCommit<G>) {
        prepared_proof
            .into_iter()
            .for_each(|(committed_proof, simulated_proof)| {
                if let Some(commits) = committed_proof {
                    for (_, t) in commits.iter() {
                        <VectorContextHash as ContextHash<G>>::add_point(self, t);
                    }
                } else if let Some((_, simulated)) = simulated_proof {
                    for (_, t) in simulated.iter() {
                        <VectorContextHash as ContextHash<G>>::add_point(self, t);
                    }
                }
            });
    }

    fn add_proof(&mut self, transcript: &ProofResponse<G>) {
        transcript.into_iter().for_each(|(_, statements)| {
            statements.iter().for_each(|statement| {
                <VectorContextHash as ContextHash<G>>::add_point(self, &statement.1);
            })
        })
    }
}
