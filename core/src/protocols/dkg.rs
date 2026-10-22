// Implementation of the FROST DKG. See Eprint 2020/852.
// Participants are numbered from 0 to n-1 (WARNING: the "value" at which we evaluate the polynomials is k+1, where k is the participant number. Evaluation at 0 is reserved for the global public key.)

// TODO: during step 1, we do l zkps, where l is the width of the multi-ElGamal. We could perhaps have a global dedicated zkp that is cheaper.
// FIXME: add asserts for lengths of vectors.

use crate::foundation::group::Group;
use crate::primitives::zkp::correct_exp::ZKPCorrectExp;
use crate::primitives::zkp::discrete_log::ZKPDiscreteLog;
use rand_core::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct DKGPubData<G: Group> {
    _marker: PhantomData<G>,
    l: usize,     // width of the multi-ElGamal
    n: usize,     // number of participants
    t: usize,     // threshold (at least t participants are required to decrypt)
    ctx: Vec<u8>, // context
}

pub struct DKGProtocol<G: Group> {
    pub pub_data: DKGPubData<G>,
}

// Data types for step 1
pub struct DKGStateStep1<G: Group> {
    a_is: Vec<Vec<G::Scalar>>, // the coefficients of the l secret polynomials. len(a_is) = l, len(a_is[i]) = t
}
pub struct DKGOutMessageStep1<G: Group> {
    phi_is: Vec<Vec<G::Point>>,        // commitments to the secret polynomials. len(phi_is) = l, len(phi_is[i]) = t
    zkps: Vec<(G::Scalar, G::Scalar)>, // zkp that one knows the constant coefficient of the polynomials. len(zkps) = l
}

// Data types for step 2
pub struct DKGStateStep2<G: Group> {
    phi_is: Vec<Vec<Vec<G::Point>>>, // remember the commitments to the secret polynomials, including our own. len(phi_is) = n, len(phi_is[i]) = l, len(phi_is[i][j]) = t
}
pub type DKGInMessageStep2<G: Group> = Vec<DKGOutMessageStep1<G>>; // same as out message from step 1, because this is a broadcast. len is n (we also receive our own message).
pub struct DKGOutMessageStep2<G: Group> {
    f_is: Vec<Vec<G::Scalar>>, // Evaluations of the polynomials at the value k+1, where k is the recipient number seen as a G::Scalar. We also "send" to ourself, instead of storing in State, to simplify the code. len(f_is) = n, len(f_is[i]) = l.
}

// Data types for step 3
pub struct DKGStateStep3<G: Group> {
    sk: Vec<G::Scalar>, // own secret key.
    pk: Vec<G::Point>,  // own public key.
    gpk: Vec<G::Point>, // global public key.
}
pub struct DKGInMessageStep3<G: Group> {
    f_is: Vec<Vec<G::Scalar>>, // Evaluations of polynomials for me. len(f_is) = n, len(f_is[i]) = l.
}
pub struct DKGOutMessageStep3<G: Group> {
    _marker: PhantomData<G>,
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
    for i in (0..(t - 2)).rev() {
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
                num = num * &G::Scalar::from(j as u64);
            }
            assert!(denom != G::Scalar::from(0u64));
            denom = G::scalar_inverse(&denom).unwrap();
            num * &denom
        })
        .collect::<Vec<_>>()
}

impl<G: Group> DKGProtocol<G> {
    pub fn new(l: usize, n: usize, t: usize, ctx: Vec<u8>) -> Self {
        Self {
            pub_data: DKGPubData {
                _marker: Default::default(),
                l,
                n,
                t,
                ctx,
            },
        }
    }

    // Each participant/trustee generates its polynomial, commits to it, and add a zkp.
    // The parameter 'trustee' is the id of the trustee, i.e. an integer from 0 to n-1.
    pub fn step_1<R: RngCore + CryptoRng>(&self, trustee: usize, rng: &mut R) -> (DKGStateStep1<G>, DKGOutMessageStep1<G>) {
        let l = self.pub_data.l;
        let t = self.pub_data.t;
        let mut ctx = self.pub_data.ctx.clone();
        ctx.append(&mut trustee.to_le_bytes().to_vec());
        let zkp: ZKPDiscreteLog<G> = ZKPDiscreteLog::default();
        let a_is = (0..l).map(|_| (0..t).map(|_| G::scalar_random(rng)).collect::<Vec<_>>()).collect::<Vec<_>>();
        let phi_is = (0..l).map(|i| (0..t).map(|j| G::basepoint() * &a_is[i][j]).collect::<Vec<_>>()).collect::<Vec<_>>();
        let zkps = (0..l)
            .map(|i| {
                let mut ctxi = ctx.clone();
                ctxi.append(&mut i.to_le_bytes().to_vec());
                zkp.prove(&phi_is[i][0], &a_is[i][0], &mut ctxi, rng)
            })
            .collect::<Vec<_>>();
        (DKGStateStep1 { a_is }, DKGOutMessageStep1 { phi_is, zkps })
    }

    // Check the zkps of others, compute evaluations of our secret polynomials at other trustees' points.
    pub fn step_2(&self, trustee: usize, state1: &DKGStateStep1<G>, messages1: &DKGInMessageStep2<G>) -> (DKGStateStep2<G>, DKGOutMessageStep2<G>) {
        let l = self.pub_data.l;
        let n = self.pub_data.n;
        let zkp: ZKPDiscreteLog<G> = ZKPDiscreteLog::default();
        for k in 0..n {
            if k == trustee {
                continue;
            }
            let mut ctx = self.pub_data.ctx.clone();
            ctx.append(&mut k.to_le_bytes().to_vec());
            let mes = &messages1[k];
            for i in 0..l {
                let mut ctxi = ctx.clone();
                ctxi.append(&mut i.to_le_bytes().to_vec());
                assert!(zkp.verify(&mes.phi_is[i][0], &mes.zkps[i].0, &mes.zkps[i].1, &mut ctxi));
            }
        }
        let f_is = (0..n)
            .map(|_| (0..l).map(|i| pol_eval::<G>(&*state1.a_is[i], &G::Scalar::from((i + 1) as u64))).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let state2 = (0..n).map(|k| messages1[k].phi_is.clone()).collect::<Vec<_>>();
        (DKGStateStep2 { phi_is: state2 }, DKGOutMessageStep2 { f_is })
    }

    // Check received data against stuff committed at step 1, and compute own secret and partial public key.
    pub fn step_3(&self, trustee: usize, state2: &DKGStateStep2<G>, messages3: &DKGInMessageStep3<G>) -> (DKGStateStep3<G>, DKGOutMessageStep3<G>) {
        let l = self.pub_data.l;
        let t = self.pub_data.t;
        let n = self.pub_data.n;
        let f_is = &messages3.f_is;
        for k in 0..n {
            // messages3[k] comes from trustee k.
            if k == trustee {
                continue;
            } // don't need to check our own data.
            let f_i = &f_is[k];
            for i in 0..l {
                let val = G::basepoint() * &f_i[i]; // g to the i-th polynomial of trustee k evaluated at my point (trustee+1).
                let mut val2 = G::identity();
                let mut ii = G::Scalar::from(1u64);
                for j in 0..t {
                    val2 = val2 + &(state2.phi_is[k][i][j] * &ii);
                    ii = ii * &G::Scalar::from((trustee + 1) as u64);
                }
                assert_eq!(val, val2);
            }
        }
        // Secret key
        let sk = (0..l)
            .map(|i| {
                let mut ski = G::Scalar::from(0u64);
                for k in 0..n {
                    ski = ski + &f_is[k][i];
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
                    gpki = gpki + &state2.phi_is[k][i][0];
                }
                gpki
            })
            .collect::<Vec<_>>();
        (DKGStateStep3 { sk, pk, gpk }, DKGOutMessageStep3 { _marker: Default::default() })
    }
}

pub struct PartialDecryption<G: Group> {
    trustee: usize,
    part_dec: Vec<G::Point>,
    zkps: Vec<(G::Scalar, G::Scalar)>,
}

pub fn partial_decrypt<G: Group, R: RngCore + CryptoRng>(
    sk: &Vec<G::Scalar>,
    trustee: usize,
    pk_data: &DKGFinalData<G>,
    c: &[G::Point],
    ctx: &[u8],
    rng: &mut R,
) -> Vec<(G::Point, (G::Scalar, G::Scalar))> {
    let l = pk_data.l;
    let n = pk_data.n;
    let t = pk_data.t;
    let zkp = ZKPCorrectExp::<G>::default();
    (0..l)
        .map(|i| {
            let d = c[0] * &sk[i];
            let pi = zkp.prove(&pk_data.pk[trustee][i], &c[0], &d, &sk[i], &ctx, rng); // FIXME: context should be bound to i and l.
            (d, pi)
        })
        .collect::<Vec<_>>()
}

pub fn collect_partial_dec<G: Group>(pk_data: &DKGFinalData<G>, c: &[G::Point], partial_dec: &[PartialDecryption<G>], ctx: &[u8]) -> Vec<G::Point> {
    let l = pk_data.l;
    let t = pk_data.t;
    assert!(partial_dec.len() >= t);
    let zkp = ZKPCorrectExp::<G>::default();
    let trustees = partial_dec.iter().map(|p| G::Scalar::from((1 + p.trustee) as u64)).collect::<Vec<_>>();
    let lagrange_coeff = lagrange_coeff::<G>(&trustees);
    for p in partial_dec {
        for i in 0..l {
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
