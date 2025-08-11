use ark_ec::{pairing::Pairing, PrimeGroup, VariableBaseMSM};
use ark_ff::Field;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::*;
use ark_std::Zero;
use std::collections::BTreeMap;

use crate::{
    crsgen::CRS,    
    encryption::Ciphertext,
    utils::{hash_to_bytes, bipart_lagrange_interp_eval, open_all_values, xor},
};

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<E: Pairing> {
    sk_share: E::ScalarField,
}

impl<E: Pairing> SecretKey<E> {
    pub fn new(sk_share: E::ScalarField) -> Self {
        SecretKey { sk_share }
    }

    //pub fn get_pk(&self) -> E::G2 {
    //    E::G2::generator() * self.sk_share
    //}

    /// each party in the committee computes a partial decryption
    pub fn partial_decrypt(
        &self,
        digest: E::G1,
    ) -> E::G1 {
        let pd = digest * self.sk_share;
        pd
    }
}

pub fn get_digest<E: Pairing>(
        ct: &Vec<Ciphertext<E>>,
        crs: &CRS<E>,
    ) -> E::G1 {
        let batch_size = crs.powers_of_g.len();
        let tx_domain = Radix2EvaluationDomain::<E::ScalarField>::new(batch_size).unwrap();

        let mut fevals = vec![E::ScalarField::zero(); batch_size];
        for i in 0..batch_size {
            let tg_bytes = hash_to_bytes(ct[i].sig_pk);
            fevals[i] = E::ScalarField::from_random_bytes(&tg_bytes).unwrap();
        }
        let fcoeffs = tx_domain.ifft(&fevals);
        let com = <E::G1 as VariableBaseMSM>::msm(&crs.powers_of_g, &fcoeffs).unwrap();

        com
}
/// aggregate partial decryptions into a signature on H(id)/com
pub fn aggregate_partial_decryptions<G: PrimeGroup>(partial_decryptions: &BTreeMap<usize, (G, bool)>) ->(G,G)  {
    // interpolate partial decryptions to recover the signature
    let mut evals = Vec::new();
    let mut eval_points = Vec::new();
    let mut flags = Vec::new();
    // Iterate over the map and collect keys and values
    for (&key, &(g_elem, flag)) in partial_decryptions.iter() {
        evals.push(g_elem);
        flags.push(flag);
        eval_points.push(G::ScalarField::from(key as u64));
    }

    let sigma = bipart_lagrange_interp_eval(&eval_points, &vec![G::ScalarField::zero()], &evals,&flags);
    (sigma[0].clone(), sigma[1].clone())
}

/// decrypts all the ciphertexts in a batch
pub fn decrypt_all<E: Pairing>(
    sigma_left: E::G1,
    sigma_right: E::G1,
    ct: &Vec<Ciphertext<E>>,
    h_j_bid: E::G1,
    crs: &CRS<E>,
) -> Vec<[u8; 32]> {
    let batch_size = ct.len();

    let tx_domain = Radix2EvaluationDomain::<E::ScalarField>::new(batch_size).unwrap();

    // compute fevals by hashing gs of the ciphertexts to get fevals
    let mut fevals = vec![E::ScalarField::zero(); batch_size];
    for i in 0..batch_size {
        let tg_bytes = hash_to_bytes(ct[i].sig_pk);
        fevals[i] = E::ScalarField::from_random_bytes(&tg_bytes).unwrap();
    }

    let fcoeffs = tx_domain.ifft(&fevals);

    let com = <E::G1 as VariableBaseMSM>::msm(&crs.powers_of_g, &fcoeffs).unwrap();
    let delta = h_j_bid + com;

    // use FK22 to get all the KZG proofs in O(nlog n) time =======================
    let pi = open_all_values::<E>(&crs.y, &fcoeffs, &tx_domain);

    // now decrypt each of the ciphertexts as m = ct(1) xor H(e(delta,ct2).e(pi,ct3)e(-sigma,ct4))
    let mut m = vec![[0u8; 32]; batch_size];
    for i in 0..batch_size {
        let mask = E::multi_miller_loop([com,pi[i], sigma_left, sigma_right], [ct[i].ct1, ct[i].ct2, ct[i].ct3, ct[i].ct4]);
        let mask = E::final_exponentiation(mask).unwrap();
        let hmask = hash_to_bytes(mask);
        //dbg!("Final mask in decryption: {:?}", hmask);
        m[i] = xor(&ct[i].ct5, &hmask).as_slice().try_into().unwrap();
    }

    m
}
