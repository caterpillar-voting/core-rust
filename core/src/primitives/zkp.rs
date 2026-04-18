mod representation;
mod zkp;

use crate::foundation::discrete_log::DiscreteLog;
use crate::foundation::group::Group;
use crate::primitives::encryption::el_gamal::{ElGamal};
use rand_core::{CryptoRng, RngCore};


#[derive(Debug)]
pub struct ZeroKnowledgeProof<G: Group> {
    el_gamal: ElGamal<G>,
}


#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;
}
