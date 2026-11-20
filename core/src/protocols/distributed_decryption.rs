use crate::foundation::group::Group;
use crate::primitives::encryption::SecretKey;
use crate::primitives::zkp::correct_exp::ZKPCorrectExp;
use crate::protocols::dkg::DKGFinalData;
use rand_core::{CryptoRng, RngCore};

// TODO FM: refactor to proper protocol abstraction

#[allow(dead_code)]
pub struct PartialDecryption<G: Group> {
    trustee: usize,
    part_dec: Vec<G::Point>,
    zkps: Vec<(G::Scalar, G::Scalar)>,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

// Lagrange coefficients
#[allow(dead_code)]
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