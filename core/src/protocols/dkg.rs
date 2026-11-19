// Implementation of the FROST DKG. See Eprint 2020/852.
// Participants are numbered from 0 to n-1 (WARNING: the "value" at which we evaluate the polynomials is k+1, where k is the participant number. Evaluation at 0 is reserved for the global public key.)

// TODO: during step 1, we do l zkps, where l is the width of the multi-ElGamal. We could perhaps have a global dedicated zkp that is cheaper.
// FIXME: add asserts for lengths of vectors.

use crate::foundation::group::Group;
use crate::primitives::encryption::{PublicKey, SecretKey};
use crate::primitives::zkp::correct_exp::ZKPCorrectExp;
use crate::primitives::zkp::discrete_log::ZKPDiscreteLog;
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;
use crate::protocols::{BroadcastMessage, Message};

#[derive(Clone)]
pub struct DKGPubData {
    l: usize,     // width of the multi-ElGamal
    n: usize,     // number of participants
    t: usize,     // threshold (at least t participants are required to decrypt)
    ctx: Vec<u8>, // context
}

pub struct DKGProtocol<G: Group> {
    pub pub_data: DKGPubData,
    pub trustee_index: usize, // TODO: use naming of "i", or perhaps "participant_index", to remain closer to eprint?
    _marker: PhantomData<G>,
}

// Data types for step 1
pub struct DKGStateStep1<G: Group> {
    a_is: Vec<Vec<G::Scalar>>, // the coefficients of the l secret polynomials. len(a_is) = l, len(a_is[i]) = t
}
pub struct DKGMessageStep1<G: Group> {
    phi_is: Vec<Vec<G::Point>>,        // commitments to the secret polynomials. len(phi_is) = l, len(phi_is[i]) = t
    zkps: Vec<(G::Scalar, G::Scalar)>, // zkp that one knows the constant coefficient of the polynomials. len(zkps) = l
}
// This type serves for messages for a participant at the end of step 2, and for messages entering step 3.
// For the outgoing message, the f_is are the evaluations of the polynomials at the value k+1, where k is the recipient number seen as a G::Scalar. len(f_is) = n, len(f_is[i]) = l.
// For the ingoing message, the i-th entry of f_is comes from trustee i and contains the evaluations of the polynomials at the value k+1, where k is "self", i.e. the trustee that is currently running step 3.
#[derive(Clone)]
pub struct DKGMessageStep2<G: Group> {
    f_is: Vec<G::Scalar>,
}

// Data types for step 3
pub struct DKGResult<G: Group> {
    sk: SecretKey<G>,  // own secret key.
    pk: PublicKey<G>,  // own public key.
    gpk: PublicKey<G>, // global public key.
}

pub struct DKGFinalData<G: Group> {
    l: usize,               // width of the multi-ElGamal
    n: usize,               // number of participants
    t: usize,               // threshold (at least t participants are required to decrypt)
    pk: Vec<Vec<G::Point>>, // public key of each trustee. len(pk) = n, len(pk[i]) = l.
    gpk: Vec<G::Point>,     // global public key.
}

// Horner scheme for polynomial evaluation.
fn pol_eval<G: Group>(pol: &[G::Scalar], x: &G::Scalar) -> G::Scalar {
    let t = pol.len();
    let mut res = pol[t - 1].clone();
    for i in (0..(t - 1)).rev() {
        res = res * &x + &pol[i];
    }
    res
}

// Lagrange coefficients
fn lagrange_coeff<G: Group>(abscissae: &[G::Scalar]) -> Vec<G::Scalar> {
    let n = abscissae.len();
    for &x in abscissae {
        assert!(x != G::Scalar::from(0u64));
    }
    (0..n)
        .map(|i| {
            let mut denom = G::Scalar::from(1u64);
            let mut num = G::Scalar::from(1u64);
            for j in 0..n {
                if i == j {
                    continue;
                }
                assert!(abscissae[i] != abscissae[j]);
                denom = denom * &(abscissae[j] - &abscissae[i]);
                num = num * &abscissae[j];
            }
            assert!(denom != G::Scalar::from(0u64));
            denom = G::scalar_inverse(&denom).unwrap();
            num * &denom
        })
        .collect::<Vec<_>>()
}

impl<G: Group> DKGProtocol<G> {
    pub fn new(trustees_count: usize, trustee_threshold: usize, ctx: &[u8], trustee_index: usize) -> Self {
        let ctx = ctx.to_vec();
        // possibly check that trustee_threshold < trustees_count to nudge safe usage?
        Self {
            pub_data: DKGPubData {
                l: 1,
                n: trustees_count,
                t: trustee_threshold,
                ctx,
            },
            trustee_index,
            _marker: Default::default(),
        }
    }

    // Each participant/trustee generates its polynomial, commits to it, and add a zkp.
    // The parameter 'trustee' is the id of the trustee, i.e. an integer from 0 to n-1.
    pub fn step_1<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (DKGStateStep1<G>, BroadcastMessage<DKGMessageStep1<G>>) {
        let l = self.pub_data.l;
        let t = self.pub_data.t;
        let zkp: ZKPDiscreteLog<G> = ZKPDiscreteLog::default();

        let mut ctx = self.pub_data.ctx.clone();
        ctx.append(&mut self.trustee_index.to_le_bytes().to_vec());

        let a_is = (0..l).map(|_| (0..t).map(|_| G::scalar_random(rng)).collect::<Vec<_>>()).collect::<Vec<_>>();
        let phi_is = (0..l).map(|i| (0..t).map(|j| G::basepoint() * &a_is[i][j]).collect::<Vec<_>>()).collect::<Vec<_>>();
        let zkps = (0..l)
            .map(|i| {
                let mut ctxi = ctx.clone();
                ctxi.append(&mut i.to_le_bytes().to_vec());
                zkp.prove(&phi_is[i][0], &a_is[i][0], &mut ctxi, rng)
            })
            .collect::<Vec<_>>();

        (
            DKGStateStep1 { a_is },
            BroadcastMessage {
                payload: DKGMessageStep1 { phi_is, zkps },
                sender: self.trustee_index,
            }
        )
    }

    // Check the zkps of others, compute evaluations of our secret polynomials at other trustees' points.
    pub fn step_2(&self, state1: &DKGStateStep1<G>, messages1: &Vec<BroadcastMessage<DKGMessageStep1<G>>>) -> Vec<Message<DKGMessageStep2<G>>> {
        let l = self.pub_data.l;
        let n = self.pub_data.n;
        let zkp: ZKPDiscreteLog<G> = ZKPDiscreteLog::default();

        // check ZKPs of other participants
        for k in 0..n {
            if k == self.trustee_index {
                continue;
            }

            let mut ctx = self.pub_data.ctx.clone();
            ctx.append(&mut k.to_le_bytes().to_vec());

            let message1 = messages1.iter()
                .find(|m| m.sender == k)
                .expect(&format!("Missing message from {}", k));
            let payload = &message1.payload;
            assert_eq!(payload.phi_is.len(), l);
            assert_eq!(payload.zkps.len(), l);

            for i in 0..l {
                let mut ctxi = ctx.clone();
                ctxi.append(&mut i.to_le_bytes().to_vec());
                assert!(zkp.verify(&payload.phi_is[i][0], &payload.zkps[i].0, &payload.zkps[i].1, &mut ctxi));
            }
        }

        // evaluate polynomial for each trustee
        let mut messages: Vec<Message<DKGMessageStep2<G>>> = vec![];
        for k in 0..n {
            if k == self.trustee_index {
                continue;
            }

            let message = Message {
                payload: DKGMessageStep2 {
                    f_is: (0..l).map(|i| pol_eval::<G>(&*state1.a_is[i], &G::Scalar::from((k + 1) as u64))).collect::<Vec<_>>()
                },
                sender: self.trustee_index,
                receiver: vec![k]
            };
            messages.push(message)
        }

        messages
    }

    // Check received data against stuff committed at step 1, and compute own secret and partial public key.
    pub fn step_3(&self, state1: &DKGStateStep1<G>, messages1: &Vec<BroadcastMessage<DKGMessageStep1<G>>>, messages2: &Vec<Message<DKGMessageStep2<G>>>) -> DKGResult<G> {
        let l = self.pub_data.l;
        let t = self.pub_data.t;
        let n = self.pub_data.n;

        // verify shares of other participants
        for k in 0..n {
            if k == self.trustee_index {
                continue;
            }

            let message1 = messages1.iter()
                .find(|m| m.sender == k)
                .expect(&format!("Missing message 1 from {}", k));
            assert_eq!(message1.payload.phi_is.len(), l);
            assert_eq!(message1.payload.zkps.len(), l);

            let message2 = messages2.iter()
                .find(|m| m.sender == k)
                .expect(&format!("Missing message 2 from {}", k));
            assert_eq!(message2.payload.f_is.len(), l);

            for i in 0..l {
                let val = G::basepoint() * &message2.payload.f_is[i]; // g to the i-th polynomial of trustee k evaluated at my point (trustee+1).
                let mut val2 = G::identity();
                let mut ii = G::Scalar::from(1u64);
                for j in 0..t {
                    val2 = val2 + &(message1.payload.phi_is[i][j] * &ii);
                    ii = ii * &G::Scalar::from((self.trustee_index + 1) as u64);
                }
                assert_eq!(val, val2);
            }
        }
        // Secret key
        let sk = (0..l)
            .map(|i| {
                let mut ski = G::Scalar::from(0u64);
                for k in 0..n {
                    if k == self.trustee_index {
                        ski = ski + &pol_eval::<G>(&*state1.a_is[i], &G::Scalar::from((k + 1) as u64));
                    } else {
                        let message2 = messages2.iter()
                            .find(|m| m.sender == k).unwrap();
                        ski = ski + &message2.payload.f_is[i];
                    }
                }
                ski
            })
            .collect::<Vec<_>>();
        // Public key
        let pk = sk.iter().map(|s| G::basepoint() * &s).collect::<Vec<_>>();
        // Global public key
        let gpk = (0..l)
            .map(|i| {
                let mut gpki = G::identity();
                for k in 0..n {
                    let message1 = messages1.iter()
                        .find(|m| m.sender == k)
                        .unwrap();
                    gpki = gpki + &message1.payload.phi_is[i][0];
                }
                gpki
            })
            .collect::<Vec<_>>();
        DKGResult { sk: SecretKey(sk), pk, gpk }
    }
}

pub struct PartialDecryption<G: Group> {
    trustee: usize,
    part_dec: Vec<G::Point>,
    zkps: Vec<(G::Scalar, G::Scalar)>,
}

pub fn partial_decrypt<G: Group, R: RngCore + CryptoRng>(sk: &SecretKey<G>, trustee: usize, pk_data: &DKGFinalData<G>, c: &[G::Point], ctx: &[u8], rng: &mut R) -> PartialDecryption<G> {
    let l = pk_data.l;
    let zkp = ZKPCorrectExp::<G>::default();
    let (part_dec, zkps) = (0..l)
        .map(|i| {
            let mut ctxi = ctx.to_vec();
            ctxi.append(&mut trustee.to_le_bytes().to_vec());
            ctxi.append(&mut i.to_le_bytes().to_vec());
            let d = c[0] * &sk.0[i];
            let pi = zkp.prove(&pk_data.pk[trustee][i], &c[0], &d, &sk.0[i], &ctx, rng);
            (d, pi)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .unzip();
    PartialDecryption { trustee, part_dec, zkps }
}

pub fn collect_partial_dec<G: Group>(pk_data: &DKGFinalData<G>, c: &[G::Point], partial_dec: &[PartialDecryption<G>], ctx: &[u8]) -> Vec<G::Point> {
    let n = pk_data.n;
    let l = pk_data.l;
    let t = pk_data.t;
    assert!(partial_dec.len() >= t);
    let zkp = ZKPCorrectExp::<G>::default();
    let trustees = partial_dec.iter().map(|p| G::Scalar::from((1 + p.trustee) as u64)).collect::<Vec<_>>();
    let lagrange_coeff = lagrange_coeff::<G>(&trustees);
    for k in 0..n {
        let p = &partial_dec[k];
        for i in 0..l {
            let mut ctxi = ctx.to_vec();
            ctxi.append(&mut k.to_le_bytes().to_vec());
            ctxi.append(&mut i.to_le_bytes().to_vec());
            let d = p.part_dec[i];
            let pi = p.zkps[i];
            assert!(zkp.verify(&pk_data.pk[p.trustee][i], &c[0], &d, &pi.0, &pi.1, &ctx));
        }
    }
    (0..l)
        .map(|i| {
            let mut d = G::identity();
            for j in 0..partial_dec.len() {
                d = d + &(partial_dec[j].part_dec[i] * &lagrange_coeff[j]);
            }
            c[i + 1] - &d
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::encryption::el_gamal::ElGamal;
    use crate::protocols::dkg::{DKGFinalData, DKGProtocol, DKGPubData, collect_partial_dec, partial_decrypt};
    use rand::thread_rng;
    use std::marker::PhantomData;

    type G = RistrettoGroup;

    fn test_dkg_full_run_aux(l: usize) {
        let mut rng = thread_rng();
        let trustee_count = 3usize;
        let trustee_threshold = 2usize;
        let ctx = "test_dkg".as_bytes();

        // Define context for each trustee
        let dkg_pub_data = DKGPubData {
            l,
            n: trustee_count,
            t: trustee_threshold,
            ctx: ctx.to_vec(),
        };
        let mut dkgs = vec![];
        for i in 0..trustee_count {
            let dkg = DKGProtocol {
                pub_data: dkg_pub_data.clone(),
                trustee_index: i,
                _marker: PhantomData::<G>,
            };
            dkgs.push(dkg);
        }

        // All trustees run step 1 and we collect the output (broadcasted).
        let mut states_step1 = vec![];
        let mut messages_step1 = vec![];
        for i in 0..trustee_count {
            let (st1, mes1) = dkgs[i].step_1(&mut rng);
            states_step1.push(st1);
            messages_step1.push(mes1);
        }
        // All trustees run step 2. The output is a list of messages, one for each trustee.
        let mut messages_step2 = vec![];
        for i in 0..trustee_count {
            let mut mes2 = dkgs[i].step_2(&states_step1[i], &messages_step1);
            messages_step2.append(&mut mes2);
        }
        // Collect messages for each trustee.
        let mut collected_messages_step2 = vec![];
        for i in 0..trustee_count {
            let messages_for_trustee = messages_step2.iter()
                .filter(|m| m.receiver.contains(&i))
                .cloned()
                .collect::<Vec<_>>();
            collected_messages_step2.push(messages_for_trustee);
        }
        // All trustess run step 3
        let mut result = vec![];
        for i in 0..trustee_count {
            let resi = dkgs[i].step_3(&states_step1[i], &messages_step1, &collected_messages_step2[i]);
            result.push(resi);
        }
        // Check they agree on the global public key and collect the final data
        for i in 1..trustee_count {
            assert_eq!(result[i].gpk, result[0].gpk);
        }
        let pk_data: DKGFinalData<G> = DKGFinalData {
            l,
            n: trustee_count,
            t: trustee_threshold,
            pk: result.iter().map(|res| res.pk.clone()).collect(),
            gpk: result[0].gpk.clone(),
        };
        let sk: Vec<_> = result.iter().map(|res| res.sk.clone()).collect();

        // Prepare an encrypted message
        let el_gamal = ElGamal::<G>::new(l);
        let r = G::scalar_random(&mut rng);
        let m = (0..l).map(|_| G::point_random(&mut rng)).collect::<Vec<_>>();
        let c = el_gamal.encrypt(&pk_data.gpk, &r, &m);
        // Run partial decryptions
        let mut part_dec = vec![];
        for i in 0..trustee_count {
            let res = partial_decrypt(&sk[i], i, &pk_data, &c, ctx, &mut rng);
            part_dec.push(res);
        }
        // Recombine and check
        let recombined = collect_partial_dec(&pk_data, &c, &part_dec, ctx);
        assert_eq!(recombined, m);
    }

    #[test]
    pub fn test_dkg_full_run() {
        test_dkg_full_run_aux(1);
        test_dkg_full_run_aux(3);
    }
}
