use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, GroupContextHash, VectorContextHash};
use crate::primitives::zkp3::zkp_from_phi::ZkpFromPhi;
use crate::primitives::zkp3::{InteractiveGenericZKP, ZkpItems};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct LeafClaim<G: Group + Clone> {
    pub public_args: Vec<u16>,
    pub witness_args: Vec<u16>,
    pub zkp: ZkpFromPhi<G>,
}

impl<G: Group + Clone> LeafClaim<G> {
    pub fn new(public_args: &Vec<u16>, witness_args: &Vec<u16>, zkp: &ZkpFromPhi<G>) -> Self {
        let public_args = public_args.clone();
        let witness_args = witness_args.clone();
        let zkp = zkp.clone();
        Self { public_args, witness_args, zkp }
    }
}

// Tree structures for Claims, commits, responses, states.
pub enum Claim<G: Group + Clone> {
    LeafClaim(LeafClaim<G>),
    OrClaim(Vec<Claim<G>>),
    AndClaim(Vec<Claim<G>>),
}
#[derive(Clone)]
pub enum TreeOfData<G: Group + Clone> {
    LeafData(Vec<ZkpItems<G>>),
    OrData(Vec<TreeOfData<G>>),
    AndData(Vec<TreeOfData<G>>),
}

type Commits<G: Group + Clone> = TreeOfData<G>;
type Responses<G: Group + Clone> = TreeOfData<G>;
type States<G: Group + Clone> = TreeOfData<G>;

#[derive(Clone)]
pub struct TreeOfChallenges<G: Group + Clone> {
    pub node_challenge: Option<G::Scalar>,
    pub sub_tree: SubTreeOfChallenges<G>,
}
#[derive(Clone)]
pub enum SubTreeOfChallenges<G: Group + Clone> {
    OrSubTree(Vec<TreeOfChallenges<G>>),
    AndSubTree(Vec<TreeOfChallenges<G>>),
    NoSubTree(),
}

pub struct CombinedZkp<G: Group + Clone> {
    pub public_data: Vec<ZkpItems<G>>, // the list of public data to which the claims refer
    pub claim: Claim<G>,               // the tree of claims
}

impl<G: Group + Clone> CombinedZkp<G> {
    pub fn new(public_data: Vec<ZkpItems<G>>, claim: Claim<G>) -> Self {
        Self { public_data, claim }
    }
    fn commit_rec<R: RngCore + CryptoRng>(&self, claim: &Claim<G>, witness: &Vec<ZkpItems<G>>, rng: &mut R) -> (Commits<G>, States<G>, TreeOfChallenges<G>, Responses<G>) {
        match claim {
            Claim::LeafClaim(leaf) => {
                let pub_data: Vec<ZkpItems<G>> = leaf.public_args.iter().map(|i| self.public_data[*i as usize].clone()).collect();
                let wit: Vec<ZkpItems<G>> = leaf.witness_args.iter().map(|i| witness[*i as usize].clone()).collect();
                let (com, st) = leaf.zkp.commit(&wit, &pub_data, rng);
                let no_chal = TreeOfChallenges {
                    node_challenge: None,
                    sub_tree: SubTreeOfChallenges::NoSubTree(),
                };
                (TreeOfData::LeafData(com), TreeOfData::LeafData(st), no_chal, TreeOfData::LeafData(vec![]))
            }
            Claim::AndClaim(and_claim) => {
                let mut out_com = vec![];
                let mut out_st = vec![];
                let mut out_chal = vec![];
                let mut out_resp = vec![];
                for claim in and_claim {
                    let (com, st, chal, resp) = self.commit_rec(claim, &witness, rng);
                    out_com.push(com);
                    out_st.push(st);
                    out_chal.push(chal);
                    out_resp.push(resp);
                }
                let chal = TreeOfChallenges {
                    node_challenge: None,
                    sub_tree: SubTreeOfChallenges::AndSubTree(out_chal),
                };
                (TreeOfData::AndData(out_com), TreeOfData::AndData(out_st), chal, TreeOfData::AndData(out_resp))
            }
            Claim::OrClaim(or_claim) => {
                // FIXME: for the moment, we assume that the first claim is proven, the others are simulated.
                let (com, st, chal, resp) = self.commit_rec(&or_claim[0], &witness, rng);
                let mut out_com = vec![com];
                let mut out_st = vec![st];
                let mut out_chal = vec![chal];
                let mut out_resp = vec![resp];
                for claim in &or_claim[1..] {
                    let (com, st, chal, resp) = self.simulate_rec(claim, None, rng);
                    out_com.push(com);
                    out_st.push(st);
                    out_chal.push(chal);
                    out_resp.push(resp);
                }
                let chal = TreeOfChallenges {
                    node_challenge: None,
                    sub_tree: SubTreeOfChallenges::OrSubTree(out_chal),
                };
                (TreeOfData::OrData(out_com), TreeOfData::OrData(out_st), chal, TreeOfData::OrData(out_resp))
            }
        }
    }

    fn simulate_rec<R: RngCore + CryptoRng>(&self, claim: &Claim<G>, challenge: Option<G::Scalar>, rng: &mut R) -> (Commits<G>, States<G>, TreeOfChallenges<G>, Responses<G>) {
        match claim {
            Claim::LeafClaim(claim) => {
                let pub_data: Vec<ZkpItems<G>> = claim.public_args.iter().map(|i| self.public_data[*i as usize].clone()).collect();
                let (commit, challenge, mut response) = claim.zkp.simulate(&pub_data, challenge, rng);
                let chal = TreeOfChallenges {
                    node_challenge: Some(challenge),
                    sub_tree: SubTreeOfChallenges::NoSubTree(),
                };
                (TreeOfData::LeafData(commit), TreeOfData::LeafData(vec![]), chal, TreeOfData::LeafData(response))
            }
            Claim::AndClaim(and_claim) => {
                let challenge = match challenge {
                    Some(challenge) => challenge,
                    None => G::scalar_random(rng),
                };
                let mut out_com = vec![];
                let mut out_st = vec![];
                let mut out_resp = vec![];
                let mut out_chal = vec![];
                for claim in and_claim {
                    let (com, st, chal, resp) = self.simulate_rec(claim, Some(challenge), rng);
                    out_com.push(com);
                    out_st.push(st);
                    out_resp.push(resp);
                    out_chal.push(chal);
                }
                let chal = TreeOfChallenges {
                    node_challenge: Some(challenge),
                    sub_tree: SubTreeOfChallenges::AndSubTree(out_chal),
                };
                (TreeOfData::AndData(out_com), TreeOfData::AndData(out_st), chal, TreeOfData::AndData(out_resp))
            }
            Claim::OrClaim(or_claim) => {
                let mut out_com = vec![];
                let mut out_st = vec![];
                let mut sum_chall = G::Scalar::from(0);
                let mut out_chal = vec![];
                let mut out_resp = vec![];
                let n = or_claim.len();
                for i in 0..n {
                    let claim = &or_claim[i];
                    let forced_chal = if i == n - 1 && challenge.is_some() { Some(challenge.unwrap() - &sum_chall) } else { None };
                    let (com, st, chal, resp) = self.simulate_rec(claim, forced_chal, rng);
                    out_com.push(com);
                    out_st.push(st);
                    sum_chall = sum_chall + &chal.node_challenge.unwrap();
                    out_chal.push(chal);
                    out_resp.push(resp);
                }
                if challenge.is_some() {
                    assert_eq!(sum_chall, challenge.unwrap())
                };
                let chal = TreeOfChallenges {
                    node_challenge: Some(sum_chall),
                    sub_tree: SubTreeOfChallenges::AndSubTree(out_chal),
                };
                (TreeOfData::AndData(out_com), TreeOfData::AndData(out_st), chal, TreeOfData::AndData(out_resp))
            }
        }
    }
    pub fn commit<R: RngCore + CryptoRng>(&self, witness: &Vec<ZkpItems<G>>, rng: &mut R) -> (Commits<G>, States<G>, TreeOfChallenges<G>, Responses<G>) {
        self.commit_rec(&self.claim, witness, rng)
    }

    pub fn get_challenge_rec(&self, commit: &Commits<G>, buf: &mut VectorContextHash) {
        // FIXME: Include context and domain separation, here.
        match commit {
            TreeOfData::LeafData(commit) => {
                for item in commit {
                    match item {
                        ZkpItems::Point(item) => {
                            <VectorContextHash as GroupContextHash<G>>::add_point(buf, &item);
                        }
                        ZkpItems::Scalar(item) => {
                            <VectorContextHash as GroupContextHash<G>>::add_scalar(buf, &item);
                        }
                        ZkpItems::CipherText(item) => {
                            <VectorContextHash as GroupContextHash<G>>::add_point(buf, &item.0);
                            <VectorContextHash as GroupContextHash<G>>::add_point(buf, &item.1);
                        }
                    }
                }
            }
            TreeOfData::OrData(subtrees) => {
                for subtree in subtrees {
                    self.get_challenge_rec(subtree, buf);
                }
            }
            TreeOfData::AndData(subtrees) => {
                for subtree in subtrees {
                    self.get_challenge_rec(subtree, buf);
                }
            }
        }
    }

    // TODO: this code is duplicated from zkp_from_phi.rs.
    pub fn get_challenge(&self, commit: &Commits<G>) -> G::Scalar {
        // FIXME: Include context and domain separation, here.
        let mut buf = VectorContextHash::new(Vec::from("TODO_context"));
        for item in &self.public_data {
            match item {
                ZkpItems::Point(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item);
                }
                ZkpItems::Scalar(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_scalar(&mut buf, &item);
                }
                ZkpItems::CipherText(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item.0);
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item.1);
                }
            }
        }
        self.get_challenge_rec(commit, &mut buf);
        G::hash_to_scalar(<VectorContextHash as ContextHash<G>>::get_context(&buf).as_slice())
    }

    fn respond_rec(
        &self,
        claim: &Claim<G>,
        witness: &Vec<ZkpItems<G>>,
        challenge: G::Scalar,
        challenge_tree: &TreeOfChallenges<G>,
        states: &States<G>,
        responses: &Responses<G>,
    ) -> (TreeOfChallenges<G>, Responses<G>) {
        match claim {
            Claim::LeafClaim(claim) => {
                if challenge_tree.node_challenge.is_some() {
                    // has been simulated
                    assert_eq!(challenge, challenge_tree.node_challenge.unwrap());
                    return (challenge_tree.clone(), responses.clone());
                }
                let wit: Vec<ZkpItems<G>> = claim.witness_args.iter().map(|i| witness[*i as usize].clone()).collect();
                let state = match states {
                    TreeOfData::LeafData(st) => st,
                    _ => panic!("Unexpected state type"),
                };
                let resp = claim.zkp.respond(&wit, challenge, &state);
                let chal = TreeOfChallenges {
                    node_challenge: None,
                    sub_tree: SubTreeOfChallenges::NoSubTree(),
                };
                return (chal, TreeOfData::LeafData(resp));
            }
            Claim::AndClaim(and_claim) => {
                if challenge_tree.node_challenge.is_some() {
                    // has been simulated
                    assert_eq!(challenge, challenge_tree.node_challenge.unwrap());
                    return (challenge_tree.clone(), responses.clone());
                }
                let chals = match challenge_tree.sub_tree.clone() {
                    SubTreeOfChallenges::AndSubTree(chals) => chals,
                    _ => panic!("Unexpected challenge type"),
                };
                let states = match states {
                    TreeOfData::AndData(st) => st,
                    _ => panic!("Unexpected state type"),
                };
                let responses = match responses {
                    TreeOfData::AndData(resps) => resps,
                    _ => panic!("Unexpected response type"),
                };
                let n = and_claim.len();
                assert_eq!(n, chals.len());
                assert_eq!(n, states.len());
                assert_eq!(n, responses.len());
                let mut out_chal = vec![];
                let mut out_resp = vec![];
                for i in 0..n {
                    let claim = &and_claim[i];
                    let chal = &chals[i];
                    let state = &states[i];
                    let resp = &responses[i];
                    assert!(chal.node_challenge.is_none());
                    let (chal, resp) = self.respond_rec(&claim, witness, challenge, &chal, &state, &resp);
                    out_chal.push(chal);
                    out_resp.push(resp);
                }
                let chal = TreeOfChallenges {
                    node_challenge: Some(challenge),
                    sub_tree: SubTreeOfChallenges::AndSubTree(out_chal),
                };
                return (chal, TreeOfData::AndData(out_resp));
            }
            Claim::OrClaim(or_claim) => {
                if challenge_tree.node_challenge.is_some() {
                    // has been simulated
                    assert_eq!(challenge, challenge_tree.node_challenge.unwrap());
                    return (challenge_tree.clone(), responses.clone());
                }
                let chals = match challenge_tree.sub_tree.clone() {
                    SubTreeOfChallenges::AndSubTree(chals) => chals,
                    _ => panic!("Unexpected challenge type"),
                };
                let states = match states {
                    TreeOfData::AndData(st) => st,
                    _ => panic!("Unexpected state type"),
                };
                let responses = match responses {
                    TreeOfData::AndData(resps) => resps,
                    _ => panic!("Unexpected response type"),
                };
                let n = or_claim.len();
                assert_eq!(n, chals.len());
                assert_eq!(n, states.len());
                assert_eq!(n, responses.len());
                // FIXME: for the moment, we assume that the first claim is proven, the others are simulated.
                // compute challenge of the proven claim
                let mut chal0 = challenge;
                for i in 1..n {
                    let chal = chals[i].node_challenge.unwrap();
                    chal0 = chal0 - &chal;
                }
                let mut out_chal = vec![];
                let mut out_resp = vec![];
                for i in 0..n {
                    let claim = &or_claim[i];
                    let chal = &chals[i];
                    let state = &states[i];
                    let resp = &responses[i];
                    let this_chal = if i == 0 { chal0 } else { chal.node_challenge.unwrap() };
                    let (chal, resp) = self.respond_rec(&claim, witness, this_chal, chal, state, resp);
                    out_chal.push(chal);
                    out_resp.push(resp);
                }
                let chal = TreeOfChallenges {
                    node_challenge: Some(challenge),
                    sub_tree: SubTreeOfChallenges::OrSubTree(out_chal),
                };
                return (chal, TreeOfData::OrData(out_resp));
            }
        }
    }
    pub fn respond(&self, witness: &Vec<ZkpItems<G>>, challenge: G::Scalar, state: &States<G>, challenge_tree: &TreeOfChallenges<G>, responses: &Responses<G>) -> (TreeOfChallenges<G>, Responses<G>) {
        self.respond_rec(&self.claim, &witness, challenge, challenge_tree, state, responses)
    }

    pub fn interactive_verify_rec(&self, claim: &Claim<G>, commits: &Commits<G>, challenge_tree: &TreeOfChallenges<G>, responses: &Responses<G>) -> bool {
        match claim {
            Claim::LeafClaim(claim) => {
                assert!(challenge_tree.node_challenge.is_some());
                assert!(matches!(challenge_tree.sub_tree, SubTreeOfChallenges::NoSubTree()));
                let chal = challenge_tree.node_challenge.unwrap();
                let pub_data: Vec<ZkpItems<G>> = claim.public_args.iter().map(|i| self.public_data[*i as usize].clone()).collect();
                let resp = match responses {
                    TreeOfData::LeafData(resp) => resp,
                    _ => panic!("Unexpected response type"),
                };
                let commit = match commits {
                    TreeOfData::LeafData(commit) => commit,
                    _ => panic!("Unexpected commit type"),
                };
                claim.zkp.interactive_verify(&pub_data, chal, &commit, &resp)
            }
            Claim::AndClaim(and_claim) => {
                assert!(challenge_tree.node_challenge.is_some());
                let challenge = challenge_tree.node_challenge.unwrap();
                let n = and_claim.len();
                let chals = match challenge_tree.sub_tree.clone() {
                    SubTreeOfChallenges::AndSubTree(chals) => chals,
                    _ => panic!("Unexpected challenge type"),
                };
                assert_eq!(n, chals.len());
                let resps = match responses {
                    TreeOfData::AndData(resps) => resps,
                    _ => panic!("Unexpected response type"),
                };
                assert_eq!(n, resps.len());
                for i in 0..n {
                    assert!(chals[i].node_challenge.is_some());
                    if chals[i].node_challenge.unwrap() != challenge {
                        return false;
                    }
                    let b = self.interactive_verify_rec(&and_claim[i], commits, &chals[i], &resps[i]);
                    if !b {
                        return false;
                    }
                }
                true
            }
            Claim::OrClaim(or_claim) => {
                assert!(challenge_tree.node_challenge.is_some());
                let challenge = challenge_tree.node_challenge.unwrap();
                let n = or_claim.len();
                let chals = match challenge_tree.sub_tree.clone() {
                    SubTreeOfChallenges::OrSubTree(chals) => chals,
                    _ => panic!("Unexpected challenge type"),
                };
                assert_eq!(n, chals.len());
                let resps = match responses {
                    TreeOfData::OrData(resps) => resps,
                    _ => panic!("Unexpected response type"),
                };
                assert_eq!(n, resps.len());
                let mut sum_chall = G::Scalar::from(0);
                let mut found_one = false;
                for i in 0..n {
                    assert!(chals[i].node_challenge.is_some());
                    sum_chall = sum_chall + &chals[i].node_challenge.unwrap();
                    let b = self.interactive_verify_rec(&or_claim[i], commits, &chals[i], &resps[i]);
                    if b {
                        found_one = true
                    }
                }
                if !found_one {
                    return false;
                }
                return challenge == sum_chall;
            }
        }
    }

    pub fn interactive_verify(&self, commits: &Commits<G>, challenge: G::Scalar, challenge_tree: &TreeOfChallenges<G>, responses: &Responses<G>) -> bool {
        assert!(challenge_tree.node_challenge.is_some());
        if challenge != challenge_tree.node_challenge.unwrap() {
            return false;
        };
        self.interactive_verify_rec(&self.claim, commits, challenge_tree, responses)
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use crate::primitives::zkp3::ZkpItems;
    use crate::primitives::zkp3::combinable_zkp::Claim;
    use crate::primitives::zkp3::combinable_zkp::{CombinedZkp, LeafClaim};
    use crate::primitives::zkp3::zkp_from_phi::{ZkpFromPhi, expected_output_know_dlp, expected_output_same_plaintext, phi_know_dlp, phi_same_plaintext, zeroG1_know_dlp, zeroG1_same_plaintext};
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn prove_and_verify() {
        let mut rng = thread_rng();
        let el_gamal = ElGamal::<G>::default();
        let sk1 = el_gamal.generate_secret_key(&mut rng);
        let pk1 = el_gamal.derive_public_key(&sk1);
        let sk2 = el_gamal.generate_secret_key(&mut rng);
        let pk2 = el_gamal.derive_public_key(&sk2);

        let zkp_dl = ZkpFromPhi::new(phi_know_dlp::<G>, zeroG1_know_dlp(), expected_output_know_dlp::<G>);

        let pub_data = vec![ZkpItems::<G>::Point(pk1), ZkpItems::Point(pk2)];
        let witness = vec![ZkpItems::<G>::Scalar(sk1), ZkpItems::Scalar(sk2)];

        let pub_pos1 = vec![0u16];
        let wit_pos1 = vec![0u16];
        let claim1 = LeafClaim::<G>::new(&pub_pos1, &wit_pos1, &zkp_dl);

        let pub_pos2 = vec![0u16];
        let wit_pos2 = vec![0u16];
        let claim2 = LeafClaim::<G>::new(&pub_pos2, &wit_pos2, &zkp_dl);

        let zkp = CombinedZkp::new(pub_data.clone(), Claim::LeafClaim(claim1.clone()));

        let (commit, st, ch, resp) = zkp.commit(&witness, &mut rng);
        let challenge = zkp.get_challenge(&commit);
        let (chal, response) = zkp.respond(&witness, challenge, &st, &ch, &resp);

        // assert!(zkp.interactive_verify(&commit, challenge, &chal, &response));

        let or_claim = Claim::OrClaim(vec![Claim::LeafClaim(claim1), Claim::LeafClaim(claim2)]);
        let or_zkp = CombinedZkp::new(pub_data, or_claim);
        let (commit, st, ch, resp) = or_zkp.commit(&witness, &mut rng);
        let challenge = or_zkp.get_challenge(&commit);
        //let (chal, response) = or_zkp.respond(&witness, challenge, &st, &ch, &resp);
        //assert!(or_zkp.interactive_verify(&commit, challenge, &chal, &response));
    }
}
