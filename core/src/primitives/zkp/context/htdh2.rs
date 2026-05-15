use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, GroupContextHash, VectorContextHash};
use crate::primitives::zkp::context::ProofTreeContextHash;
use crate::primitives::zkp::proof::{Claim, ProofCommit};
use crate::utils::tree::BooleanTree::Leaf;

#[derive(Clone)]
pub struct HTDH2Hash<G: Group> {
    label: Vec<u8>,
    uv: (G::Point, G::Point),
    claim: Option<Claim<G>>,
    proof_commit: Option<ProofCommit<G>>,
}

impl<G: Group> HTDH2Hash<G> {
    pub fn new(label: Vec<u8>, uv: (G::Point, G::Point)) -> Self {
        Self {
            label,
            uv,
            claim: None,
            proof_commit: None,
        }
    }
}

impl<G: Group> ProofTreeContextHash<G> for HTDH2Hash<G> {
    fn add_claim(&mut self, claim: &Claim<G>) {
        self.claim = Some(claim.clone());
    }

    fn add_proof_commit(&mut self, proof_commit: &ProofCommit<G>) {
        self.proof_commit = Some(proof_commit.clone());
    }
}

impl<G: Group> ContextHash<G> for HTDH2Hash<G> {
    fn get_context(&self) -> Vec<u8> {
        if let Some(Leaf(statements)) = &self.claim
            && statements.len() == 2
            && let Some(Leaf(commits)) = &self.proof_commit
            && commits.len() == 2
        {
            let mut buf = VectorContextHash::default();
            <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &statements[0].z); // u
            <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &self.uv.1); // e
            <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &commits[0]); // w
            <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &statements[1].z); // u_0
            <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &commits[1]); // w_0
            buf.add(&self.label); // L

            return <VectorContextHash as ContextHash<G>>::get_context(&buf);
        }

        unreachable!("incorrect HTDH2 proof structure")
    }
}
