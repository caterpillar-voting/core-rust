/**
Implementations of ZKP. Variable naming and structure aims to follow https://crypto.ethz.ch/publications/files/Maurer15.pdf, but no explicit abstractions are done.

The implementation variant chosen here uses explicit formulations of the ZKP.
As an alternative, one could build ZKP by building an abstraction of a Maurer ZKP, and compose these Maurer-ZKP in generic AND/OR proof trees.
This approach was explored and works, the code is however hard to read and review. As there are only a few ZKP used in practice, the trade-off has been deemed to be not worth it.
You can explore these implementations in the git history.
*/
pub mod get_challenge;
pub mod discrete_log;
pub mod htdh2;

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::discrete_log::ZKPDiscreteLog;

    type G = RistrettoGroup;

    #[test]
    fn discrete_log() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x, &ctx, &mut rng);

        assert!(zkp.verify(&h, &c, &r, &ctx));
    }
}
