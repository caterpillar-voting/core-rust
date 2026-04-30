use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, VectorContextHash};
use crate::primitives::zkp::proof::{Claim, ProofCommit};

pub trait ProofTreeContextHash<G: Group> {
    fn add_claim(&mut self, claim: &Claim<G>);
    fn add_proof_commit(&mut self, proof_commit: &ProofCommit<G>);
}

impl<G: Group> ProofTreeContextHash<G> for VectorContextHash {
    fn add_claim(&mut self, claim: &Claim<G>) {
        claim.into_iter().for_each(|statements| {
            statements.iter().for_each(|statement| {
                <VectorContextHash as ContextHash<G>>::add_point(self, &statement.z);
            })
        })
    }

    fn add_proof_commit(&mut self, proof_commit: &ProofCommit<G>) {
        proof_commit.into_iter().for_each(|commits| {
            for t in commits.iter() {
                <VectorContextHash as ContextHash<G>>::add_point(self, t);
            }
        });
    }
}
