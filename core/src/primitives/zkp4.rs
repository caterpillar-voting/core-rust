pub mod discrete_log;
pub mod get_challenge;

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp4::discrete_log::ZKPDiscreteLog;

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
