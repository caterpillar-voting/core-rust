use rand_core::{CryptoRng, RngCore};
use crate::foundation::group::Group;
use crate::foundation::hash::{ContextHash, GroupContextHash, VectorContextHash};
use crate::primitives::zkp3::{InteractiveGenericZKP, Maurer_Phi, Maurer_Phi_Expected_Output, ZKP_Items};

#[derive(Clone)]
pub struct ZKP_From_Phi<G: Group + Clone> {
    pub phi: Maurer_Phi<G>,
    pub zeroG1: Vec<ZKP_Items<G>>, // Gives the type of the witness.
    pub expected_output: Maurer_Phi_Expected_Output<G>, // Compute the expected output from the public data.
}

//////////////////////
// The following are basic group operations on ZKP_Items.
// They could go in a separate file, maybe override the Ops.
//////////////////////

fn random_with_same_structure<R: RngCore + CryptoRng, G: Group + Clone>(items: &Vec<ZKP_Items<G>>, rng: &mut R) -> Vec<ZKP_Items<G>> {
    let mut res = vec![];
    for item in items {
        let x = match item {
            ZKP_Items::Point(x) => {
                ZKP_Items::Point(G::point_random(rng))
            }
            ZKP_Items::Scalar(x) => {
                ZKP_Items::Scalar(G::scalar_random(rng))
            }
            ZKP_Items::CipherText(x) => {
                ZKP_Items::CipherText((G::point_random(rng), G::point_random(rng)))
            }
        };
        res.push(x);
    }
    res
}

fn add_items<G: Group + Clone>(items1: &Vec<ZKP_Items<G>>, items2: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
    let mut res = vec![];
    for (item1, item2) in items1.iter().zip(items2.iter()) {
        let x = match (item1, item2) {
            (ZKP_Items::Point(item1), ZKP_Items::Point(item2)) => {
                ZKP_Items::Point(*item1 + item2)
            }
            (ZKP_Items::Scalar(item1),ZKP_Items::Scalar(item2)) => {
                ZKP_Items::Scalar(*item1 + item2)
            }
            (ZKP_Items::CipherText(item1), ZKP_Items::CipherText(item2)) => {
                ZKP_Items::CipherText((item1.0 + &item2.0, item1.1 + &item2.1))
            }
            _ => panic!("Invalid type")
        };
        res.push(x);
    }
    res
}
fn sub_items<G: Group + Clone>(items1: &Vec<ZKP_Items<G>>, items2: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
    let mut res = vec![];
    for (item1, item2) in items1.iter().zip(items2.iter()) {
        let x = match (item1, item2) {
            (ZKP_Items::Point(item1), ZKP_Items::Point(item2)) => {
                ZKP_Items::Point(*item1 - item2)
            }
            (ZKP_Items::Scalar(item1),ZKP_Items::Scalar(item2)) => {
                ZKP_Items::Scalar(*item1 - item2)
            }
            (ZKP_Items::CipherText(item1), ZKP_Items::CipherText(item2)) => {
                ZKP_Items::CipherText((item1.0 - &item2.0, item1.1 - &item2.1))
            }
            _ => panic!("Invalid type")
        };
        res.push(x);
    }
    res
}

fn mul_items<G: Group + Clone>(items: &Vec<ZKP_Items<G>>, scal: G::Scalar) -> Vec<ZKP_Items<G>> {
    let mut res = vec![];
    for item in items {
        let x = match item {
            ZKP_Items::Point(item) => {
                ZKP_Items::Point(scal * item)
            }
            ZKP_Items::Scalar(item) => {
                ZKP_Items::Scalar(scal * item)
            }
            ZKP_Items::CipherText(item) => {
                ZKP_Items::CipherText((scal * &item.0, scal * &item.1))
            }
            _ => panic!("Invalid type")
        };
        res.push(x);
    }
    res
}

fn are_equal_items<G: Group + Clone>(items1: &Vec<ZKP_Items<G>>, items2: &Vec<ZKP_Items<G>>) -> bool {
    assert_eq!(items1.len(), items2.len());
    for (item1, item2) in items1.iter().zip(items2.iter()) {
        match (item1, item2) {
            (ZKP_Items::Point(item1), ZKP_Items::Point(item2)) => {
                if item1 != item2 { return false }
            }
            (ZKP_Items::Scalar(item1),ZKP_Items::Scalar(item2)) => {
                if item1 != item2 { return false }
            }
            (ZKP_Items::CipherText(item1), ZKP_Items::CipherText(item2)) => {
                if item1 != item2 { return false }
            }
            _ => panic!("Invalid type")
        };
    }
    true
}

//////////////////////
// The main construction of a Combinable ZKP from a Maurer-Phi function.
//////////////////////

impl<G: Group + Clone> ZKP_From_Phi<G> {
    pub fn new(phi: Maurer_Phi<G>, zeroG1: Vec<ZKP_Items<G>>, expected_output: Maurer_Phi_Expected_Output<G>) -> Self {
        Self { phi, zeroG1, expected_output }
    }
}
impl<G: Group + Clone> InteractiveGenericZKP<G> for ZKP_From_Phi<G> {
    fn commit<R: RngCore + CryptoRng>(&self, witness: &Vec<ZKP_Items<G>>, public_data: &Vec<ZKP_Items<G>>, rng: &mut R) -> (Vec<ZKP_Items<G>>, Vec<ZKP_Items<G>>)
    {
        let k = random_with_same_structure(witness, rng);
        let t = (self.phi)(&k, public_data);
        (t, k)
    }

    fn get_challenge(&self, public_data: &Vec<ZKP_Items<G>>, commit: &Vec<ZKP_Items<G>>) -> G::Scalar {
        // FIXME: Include context and domain separation, here.
        let mut buf = VectorContextHash::new(Vec::from("TODO_context"));
        for item in public_data.iter().chain(commit) {
            match item {
                ZKP_Items::Point(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, item);
                }
                ZKP_Items::Scalar(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_scalar(&mut buf, item);
                }
                ZKP_Items::CipherText(item) => {
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item.0);
                    <VectorContextHash as GroupContextHash<G>>::add_point(&mut buf, &item.1);
                }
            }
        }
        G::hash_to_scalar(<VectorContextHash as ContextHash<G>>::get_context(&buf).as_slice())
    }

    fn respond(&self, witness: &Vec<ZKP_Items<G>>, challenge: G::Scalar, state: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
        let wc = mul_items(witness, challenge);
        add_items(&wc, state)
    }

    fn interactive_verify(&self, commit: &Vec<ZKP_Items<G>>, challenge: G::Scalar, response: &Vec<ZKP_Items<G>>,
                              public_data: &Vec<ZKP_Items<G>>) -> bool {
        let public_output = (self.expected_output)(public_data);
        let tmp = mul_items(&public_output, challenge);
        let tmp = add_items(&tmp, commit);
        let phir = (self.phi)(&response, public_data);
        are_equal_items(&phir, &tmp)
    }

    fn simulate<R: RngCore + CryptoRng>(&self, public_data: &Vec<ZKP_Items<G>>, challenge: Option<G::Scalar>, rng: &mut R)
        -> (Vec<ZKP_Items<G>>, G::Scalar, Vec<ZKP_Items<G>>) {
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
pub fn phi_know_dlp<G: Group + Clone>(x: &Vec<ZKP_Items<G>>, public_data: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
    assert_eq!(x.len(), 1);
    assert_eq!(public_data.len(), 1);
    let z = match x[0] {
        ZKP_Items::Scalar(x) => {
            x * &G::basepoint()
        }
        _ => panic!("Invalid type")
    };
    vec![ZKP_Items::Point(z)]
}
pub fn zeroG1_know_dlp<G: Group + Clone>() -> Vec<ZKP_Items<G>> {
    vec![ZKP_Items::Scalar(G::Scalar::from(0))]
}

pub fn expected_output_know_dlp<G: Group + Clone>(public_data: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
    assert_eq!(public_data.len(), 1);
    assert!(matches!(public_data[0], ZKP_Items::Point(_)));
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
pub fn phi_same_plaintext<G: Group + Clone>(x: &Vec<ZKP_Items<G>>, public_data: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
    assert_eq!(x.len(), 2);
    assert_eq!(public_data.len(), 4);
    let pk1 = match public_data[0] { ZKP_Items::Point(pk1) => pk1, _ => panic!("Invalid type") };
    let pk2 = match public_data[1] { ZKP_Items::Point(pk2) => pk2, _ => panic!("Invalid type") };
    let r1 = match x[0] { ZKP_Items::Scalar(r1) => r1, _ => panic!("Invalid type") };
    let r2 = match x[1] { ZKP_Items::Scalar(r2) => r2, _ => panic!("Invalid type") };
    let res0 = ZKP_Items::Point(r1 * &G::basepoint());
    let res1 = ZKP_Items::Point(r2 * &G::basepoint());
    let res2 = ZKP_Items::Point(r1 * &pk1 - &(r2 * &pk2));
    vec![res0, res1, res2]
}

pub fn zeroG1_same_plaintext<G: Group + Clone>() -> Vec<ZKP_Items<G>> {
    vec![ZKP_Items::Scalar(G::Scalar::from(0)), ZKP_Items::Scalar(G::Scalar::from(0))]
}

pub fn expected_output_same_plaintext<G: Group + Clone>(public_data: &Vec<ZKP_Items<G>>) -> Vec<ZKP_Items<G>> {
    assert_eq!(public_data.len(), 4);
    let C1 = match public_data[2] { ZKP_Items::CipherText(C1) => C1, _ => panic!("Invalid type") };
    let C2 = match public_data[3] { ZKP_Items::CipherText(C2) => C2, _ => panic!("Invalid type") };
    vec![ZKP_Items::Point(C1.0), ZKP_Items::Point(C2.0), ZKP_Items::Point(C1.1 - &C2.1)]
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use rand::thread_rng;
    use crate::foundation::group::Group;
    use crate::primitives::zkp3::zkp_from_phi::{expected_output_know_dlp, expected_output_same_plaintext, phi_know_dlp, phi_same_plaintext, zeroG1_know_dlp, zeroG1_same_plaintext, ZKP_From_Phi};
    use crate::primitives::zkp3::{InteractiveGenericZKP, ZKP_Items};

    type G = RistrettoGroup;

    #[test]
    fn prove_and_verify() {
        let mut rng = thread_rng();
        let el_gamal = ElGamal::<G>::default();
        let sk1 = el_gamal.generate_secret_key(&mut rng);
        let pk1 = el_gamal.derive_public_key(&sk1);

        let zkp_dl = ZKP_From_Phi::new(phi_know_dlp::<G>, zeroG1_know_dlp(), expected_output_know_dlp::<G>);
        let zkp_eqm = ZKP_From_Phi::new(phi_same_plaintext::<G>, zeroG1_same_plaintext(), expected_output_same_plaintext::<G>);

        let pub1 = vec![ZKP_Items::Point(pk1)];
        let wit1 = vec![ZKP_Items::Scalar(sk1)];
        let (commit, state) = zkp_dl.commit(&wit1, &pub1, &mut rng);
        let challenge = zkp_dl.get_challenge(&pub1, &commit);
        let response = zkp_dl.respond(&wit1, challenge, &state);
        assert!(zkp_dl.interactive_verify(&commit, challenge, &response, &pub1));
        let (commit, challenge, response) = zkp_dl.simulate(&pub1, None, &mut rng);
        assert!(zkp_dl.interactive_verify(&commit, challenge, &response, &pub1));

        let sk2 = el_gamal.generate_secret_key(&mut rng);
        let pk2 = el_gamal.derive_public_key(&sk2);

        let pub2 = vec![ZKP_Items::Point(pk1)];
        let wit2 = vec![ZKP_Items::Scalar(sk1)];
        let (commit, state) = zkp_dl.commit(&wit2, &pub2, &mut rng);
        let challenge = zkp_dl.get_challenge(&pub2, &commit);
        let response = zkp_dl.respond(&wit2, challenge, &state);
        assert!(zkp_dl.interactive_verify(&commit, challenge, &response, &pub2));

        let m = G::point_random(&mut rng);
        let r1 = G::scalar_random(&mut rng);
        let r2 = G::scalar_random(&mut rng);
        let enc_m1 = el_gamal.encrypt(&pk1, &r1, &m);
        let enc_m2 = el_gamal.encrypt(&pk2, &r2, &m);

        let pub3 = vec![ZKP_Items::Point(pk1), ZKP_Items::Point(pk2), ZKP_Items::CipherText(enc_m1), ZKP_Items::CipherText(enc_m2)];
        let wit3 = vec![ZKP_Items::Scalar(r1), ZKP_Items::Scalar(r2)];
        let (commit, state) = zkp_eqm.commit(&wit3, &pub3, &mut rng);
        let challenge = zkp_eqm.get_challenge(&pub3, &commit);
        let response = zkp_eqm.respond(&wit3, challenge, &state);
        assert!(zkp_eqm.interactive_verify(&commit, challenge, &response, &pub3));

        // a simulated proof with the same challenge.
        let (commit, challenge, response) = zkp_eqm.simulate(&pub3, Some(challenge), &mut rng);
        assert!(zkp_eqm.interactive_verify(&commit, challenge, &response, &pub3));
    }
}
