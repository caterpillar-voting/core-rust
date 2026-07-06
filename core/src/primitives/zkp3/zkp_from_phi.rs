use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, GroupContextHash, VectorContextHash};
use crate::primitives::zkp3::{InteractiveGenericZKP, MaurerPhi, MaurerPhiExpectedOutput, ZkpItems};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone)]
pub struct ZkpFromPhi<G: Group + Clone> {
    pub phi: MaurerPhi<G>,
    pub zeroG1: Vec<ZkpItems<G>>,                      // Gives the type of the witness.
    pub expected_output: MaurerPhiExpectedOutput<G>, // Compute the expected output from the public data.
}

//////////////////////
// The following are basic group operations on ZKP_Items.
// They could go in a separate file, maybe override the Ops.
//////////////////////

fn random_with_same_structure<R: RngCore + CryptoRng, G: Group + Clone>(items: &Vec<ZkpItems<G>>, rng: &mut R) -> Vec<ZkpItems<G>> {
    let mut res = vec![];
    for item in items {
        let x = match item {
            ZkpItems::Point(_x) => ZkpItems::Point(G::point_random(rng)),
            ZkpItems::Scalar(_x) => ZkpItems::Scalar(G::scalar_random(rng)),
            ZkpItems::CipherText(_x) => ZkpItems::CipherText((G::point_random(rng), G::point_random(rng))),
        };
        res.push(x);
    }
    res
}

fn add_items<G: Group + Clone>(items1: &Vec<ZkpItems<G>>, items2: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
    let mut res = vec![];
    for (item1, item2) in items1.iter().zip(items2.iter()) {
        let x = match (item1, item2) {
            (ZkpItems::Point(item1), ZkpItems::Point(item2)) => ZkpItems::Point(*item1 + item2),
            (ZkpItems::Scalar(item1), ZkpItems::Scalar(item2)) => ZkpItems::Scalar(*item1 + item2),
            (ZkpItems::CipherText(item1), ZkpItems::CipherText(item2)) => ZkpItems::CipherText((item1.0 + &item2.0, item1.1 + &item2.1)),
            _ => panic!("Invalid type"),
        };
        res.push(x);
    }
    res
}
fn sub_items<G: Group + Clone>(items1: &Vec<ZkpItems<G>>, items2: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
    let mut res = vec![];
    for (item1, item2) in items1.iter().zip(items2.iter()) {
        let x = match (item1, item2) {
            (ZkpItems::Point(item1), ZkpItems::Point(item2)) => ZkpItems::Point(*item1 - item2),
            (ZkpItems::Scalar(item1), ZkpItems::Scalar(item2)) => ZkpItems::Scalar(*item1 - item2),
            (ZkpItems::CipherText(item1), ZkpItems::CipherText(item2)) => ZkpItems::CipherText((item1.0 - &item2.0, item1.1 - &item2.1)),
            _ => panic!("Invalid type"),
        };
        res.push(x);
    }
    res
}

fn mul_items<G: Group + Clone>(items: &Vec<ZkpItems<G>>, scal: G::Scalar) -> Vec<ZkpItems<G>> {
    let mut res = vec![];
    for item in items {
        let x = match item {
            ZkpItems::Point(item) => ZkpItems::Point(scal * item),
            ZkpItems::Scalar(item) => ZkpItems::Scalar(scal * item),
            ZkpItems::CipherText(item) => ZkpItems::CipherText((scal * &item.0, scal * &item.1)),
            _ => panic!("Invalid type"),
        };
        res.push(x);
    }
    res
}

fn are_equal_items<G: Group + Clone>(items1: &Vec<ZkpItems<G>>, items2: &Vec<ZkpItems<G>>) -> bool {
    assert_eq!(items1.len(), items2.len());
    for (item1, item2) in items1.iter().zip(items2.iter()) {
        match (item1, item2) {
            (ZkpItems::Point(item1), ZkpItems::Point(item2)) => {
                if item1 != item2 {
                    return false;
                }
            }
            (ZkpItems::Scalar(item1), ZkpItems::Scalar(item2)) => {
                if item1 != item2 {
                    return false;
                }
            }
            (ZkpItems::CipherText(item1), ZkpItems::CipherText(item2)) => {
                if item1 != item2 {
                    return false;
                }
            }
            _ => panic!("Invalid type"),
        };
    }
    true
}

//////////////////////
// The main construction of a Combinable ZKP from a Maurer-Phi function.
//////////////////////

impl<G: Group + Clone> ZkpFromPhi<G> {
    pub fn new(phi: MaurerPhi<G>, zeroG1: Vec<ZkpItems<G>>, expected_output: MaurerPhiExpectedOutput<G>) -> Self {
        Self { phi, zeroG1, expected_output }
    }
}
impl<G: Group + Clone> InteractiveGenericZKP<G> for ZkpFromPhi<G> {
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Vec<ZkpItems<G>>, public_data: &Vec<ZkpItems<G>>, rng: &mut R) -> (Vec<ZkpItems<G>>, Vec<ZkpItems<G>>) {
        let k = random_with_same_structure(witness, rng);
        let t = (self.phi)(&k, public_data);
        (t, k)
    }

    fn get_challenge(&self, public_data: &Vec<ZkpItems<G>>, commit: &Vec<ZkpItems<G>>) -> G::Scalar {
        // FIXME: Include context and domain separation, here.
        let mut buf = VectorContextHash::new(Vec::from("TODO_context"));
        for item in public_data.iter().chain(commit) {
            match item {
                ZkpItems::Point(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, item);
                }
                ZkpItems::Scalar(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_scalar(&mut buf, item);
                }
                ZkpItems::CipherText(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item.0);
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item.1);
                }
            }
        }
        G::hash_to_scalar(<VectorContextHash as ContextHash<G>>::get_context(&buf).as_slice())
    }

    fn respond(&self, witness: &Vec<ZkpItems<G>>, challenge: G::Scalar, state: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
        let wc = mul_items(witness, challenge);
        add_items(&wc, state)
    }

    fn interactive_verify(&self, commit: &Vec<ZkpItems<G>>, challenge: G::Scalar, response: &Vec<ZkpItems<G>>, public_data: &Vec<ZkpItems<G>>) -> bool {
        let public_output = (self.expected_output)(public_data);
        let tmp = mul_items(&public_output, challenge);
        let tmp = add_items(&tmp, commit);
        let phir = (self.phi)(&response, public_data);
        are_equal_items(&phir, &tmp)
    }

    fn simulate<R: RngCore + CryptoRng>(&self, public_data: &Vec<ZkpItems<G>>, challenge: Option<G::Scalar>, rng: &mut R) -> (Vec<ZkpItems<G>>, G::Scalar, Vec<ZkpItems<G>>) {
        let challenge = match challenge {
            Some(x) => x,
            None => G::scalar_random(rng),
        };
        let public_output = (self.expected_output)(public_data);
        let response = random_with_same_structure(&self.zeroG1, rng);
        let phir = (self.phi)(&response, public_data);
        let tmp = mul_items(&public_output, challenge);
        let commit = sub_items(&phir, &tmp);
        (commit, challenge, response)
    }
}

//////////////////////
// Two examples of Maurer-Phi functions, that can be used with the above framework
//////////////////////

// Let G=<g> be a group, and h be a public element of G.
// This is the Maurer-Phi function to prove knowledge of x s.t. h = x*g.
// This is just Zq -> G, x -> x*g.
// Public data and public output are h.
pub fn phi_know_dlp<G: Group + Clone>(x: &Vec<ZkpItems<G>>, public_data: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
    assert_eq!(x.len(), 1);
    assert_eq!(public_data.len(), 1);
    let z = match x[0] {
        ZkpItems::Scalar(x) => x * &G::basepoint(),
        _ => panic!("Invalid type"),
    };
    vec![ZkpItems::Point(z)]
}
pub fn zeroG1_know_dlp<G: Group + Clone>() -> Vec<ZkpItems<G>> {
    vec![ZkpItems::Scalar(G::Scalar::from(0))]
}

pub fn expected_output_know_dlp<G: Group + Clone>(public_data: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
    assert_eq!(public_data.len(), 1);
    assert!(matches!(public_data[0], ZkpItems::Point(_)));
    vec![public_data[0].clone()]
}

// Let G=<g> be a group, and pk1, and pk2 be two public keys in G.
// Let C1 = (C1.0, C1.1) = (r1*g, r1*pk1 + m)
// and C2 = (C2.0, C2.1) = (r2*g, r2*pk2 + m)
// be two ElGamal encryptions of the same plaintext m in G, with randomnesses r1 and r2.
// This is the Maurer-Phi function to prove that C1 and C2 indeed encrypt the same element.
// This is (Zq x Zq) -> (G x G x G)
//         (r1, r2) -> (r1*g, r2*g, r1*pk1 - r2*pk2)
// The public data is formed by (pk1, pk2, C1, C2)
// The public output is (C1.0, C2.0, C1.1 - C2.1)
pub fn phi_same_plaintext<G: Group + Clone>(x: &Vec<ZkpItems<G>>, public_data: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
    assert_eq!(x.len(), 2);
    assert_eq!(public_data.len(), 4);
    let pk1 = match public_data[0] {
        ZkpItems::Point(pk1) => pk1,
        _ => panic!("Invalid type"),
    };
    let pk2 = match public_data[1] {
        ZkpItems::Point(pk2) => pk2,
        _ => panic!("Invalid type"),
    };
    let r1 = match x[0] {
        ZkpItems::Scalar(r1) => r1,
        _ => panic!("Invalid type"),
    };
    let r2 = match x[1] {
        ZkpItems::Scalar(r2) => r2,
        _ => panic!("Invalid type"),
    };
    let res0 = ZkpItems::Point(r1 * &G::basepoint());
    let res1 = ZkpItems::Point(r2 * &G::basepoint());
    let res2 = ZkpItems::Point(r1 * &pk1 - &(r2 * &pk2));
    vec![res0, res1, res2]
}

pub fn zeroG1_same_plaintext<G: Group + Clone>() -> Vec<ZkpItems<G>> {
    vec![ZkpItems::Scalar(G::Scalar::from(0)), ZkpItems::Scalar(G::Scalar::from(0))]
}

pub fn expected_output_same_plaintext<G: Group + Clone>(public_data: &Vec<ZkpItems<G>>) -> Vec<ZkpItems<G>> {
    assert_eq!(public_data.len(), 4);
    let C1 = match public_data[2] {
        ZkpItems::CipherText(C1) => C1,
        _ => panic!("Invalid type"),
    };
    let C2 = match public_data[3] {
        ZkpItems::CipherText(C2) => C2,
        _ => panic!("Invalid type"),
    };
    vec![ZkpItems::Point(C1.0), ZkpItems::Point(C2.0), ZkpItems::Point(C1.1 - &C2.1)]
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use crate::primitives::zkp3::zkp_from_phi::{ZkpFromPhi, expected_output_know_dlp, expected_output_same_plaintext, phi_know_dlp, phi_same_plaintext, zeroG1_know_dlp, zeroG1_same_plaintext};
    use crate::primitives::zkp3::{InteractiveGenericZKP, ZkpItems};
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn prove_and_verify() {
        let mut rng = thread_rng();
        let el_gamal = ElGamal::<G>::default();
        let sk1 = el_gamal.generate_secret_key(&mut rng);
        let pk1 = el_gamal.derive_public_key(&sk1);

        let zkp_dl = ZkpFromPhi::new(phi_know_dlp::<G>, zeroG1_know_dlp(), expected_output_know_dlp::<G>);
        let zkp_eqm = ZkpFromPhi::new(phi_same_plaintext::<G>, zeroG1_same_plaintext(), expected_output_same_plaintext::<G>);

        let pub1 = vec![ZkpItems::Point(pk1)];
        let wit1 = vec![ZkpItems::Scalar(sk1)];
        let (commit, state) = zkp_dl.commit(&wit1, &pub1, &mut rng);
        let challenge = zkp_dl.get_challenge(&pub1, &commit);
        let response = zkp_dl.respond(&wit1, challenge, &state);
        assert!(zkp_dl.interactive_verify(&commit, challenge, &response, &pub1));
        let (commit, challenge, response) = zkp_dl.simulate(&pub1, None, &mut rng);
        assert!(zkp_dl.interactive_verify(&commit, challenge, &response, &pub1));

        let sk2 = el_gamal.generate_secret_key(&mut rng);
        let pk2 = el_gamal.derive_public_key(&sk2);

        let pub2 = vec![ZkpItems::Point(pk1)];
        let wit2 = vec![ZkpItems::Scalar(sk1)];
        let (commit, state) = zkp_dl.commit(&wit2, &pub2, &mut rng);
        let challenge = zkp_dl.get_challenge(&pub2, &commit);
        let response = zkp_dl.respond(&wit2, challenge, &state);
        assert!(zkp_dl.interactive_verify(&commit, challenge, &response, &pub2));

        let m = G::point_random(&mut rng);
        let r1 = G::scalar_random(&mut rng);
        let r2 = G::scalar_random(&mut rng);
        let enc_m1 = el_gamal.encrypt(&pk1, &r1, &m);
        let enc_m2 = el_gamal.encrypt(&pk2, &r2, &m);

        let pub3 = vec![ZkpItems::Point(pk1), ZkpItems::Point(pk2), ZkpItems::CipherText(enc_m1), ZkpItems::CipherText(enc_m2)];
        let wit3 = vec![ZkpItems::Scalar(r1), ZkpItems::Scalar(r2)];
        let (commit, state) = zkp_eqm.commit(&wit3, &pub3, &mut rng);
        let challenge = zkp_eqm.get_challenge(&pub3, &commit);
        let response = zkp_eqm.respond(&wit3, challenge, &state);
        assert!(zkp_eqm.interactive_verify(&commit, challenge, &response, &pub3));

        // a simulated proof with the same challenge.
        let (commit, challenge, response) = zkp_eqm.simulate(&pub3, Some(challenge), &mut rng);
        assert!(zkp_eqm.interactive_verify(&commit, challenge, &response, &pub3));
    }
}
