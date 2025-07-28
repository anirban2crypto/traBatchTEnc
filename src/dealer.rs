use ark_ec::{pairing::Pairing, scalar_mul::ScalarMul, PrimeGroup};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::*;
use ark_std::{rand::RngCore, One, UniformRand, Zero};
use rand::thread_rng;
use std::{iter, vec};
use crate::utils::lagrange_interp_eval;
use std::ops::MulAssign;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct CRS<E: Pairing> {
    pub powers_of_g: Vec<E::G1Affine>,
    pub htau: E::G2,

    pub y: Vec<E::G1Affine>, // Preprocessed Toeplitz matrix to compute opening proofs at all points
}


#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SkCombined<E: Pairing> {
    pub index: usize,
    pub sk_alpha: E::ScalarField,
    pub sk_y: E::ScalarField,
    pub sk_z: E::ScalarField,
}

/// Dealer sets up the CRS and secret shares sk. Assumes the shares are over (1..n) and the secret key is stored at 0
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Dealer<E: Pairing> {
    pub batch_size: usize,
    pub n: usize,
    pub t: usize,
    pub code_len: usize,
    pub sk_combined: Vec<SkCombined<E>>,
}

impl<E> Dealer<E>
where
    E: Pairing,
{
    pub fn new(batch_size: usize, n: usize, t: usize, code_len: usize) -> Self {
        let rng = &mut thread_rng();
        let sk_combined = (0..code_len)
            .map(|i| SkCombined {
                index: i,
                sk_alpha: E::ScalarField::rand(rng),
                sk_y: E::ScalarField::rand(rng),
                sk_z: E::ScalarField::rand(rng),
            })
            .collect();

        Self {
            batch_size,
            n,
            t,
            code_len,
            sk_combined,
        }
    }


    // Returns the public key as a vector of tuples (pk_alpha_y_z, pk_y, pk_z)
    pub fn get_pk(&self) -> Vec<(E::G2, E::G2, E::G2)> {
    self.sk_combined
        .iter()
        .map(|sk| {
            let pk_alpha_y_z = E::G2::generator() * (sk.sk_alpha * sk.sk_y * sk.sk_z);
            let pk_y = E::G2::generator() * sk.sk_y;
            let pk_z = E::G2::generator() * sk.sk_z;
            (pk_alpha_y_z, pk_y, pk_z)
        })
        .collect()
    }

    pub fn setup<R: RngCore>(&mut self, rng: &mut R) -> (CRS<E>, Vec<Vec<E::ScalarField>>, Vec<Vec<E::ScalarField>>) {
        // Sample tau and compute its powers ==========================================================
        let tau = E::ScalarField::rand(rng);
        let powers_of_tau: Vec<E::ScalarField> =
            iter::successors(Some(E::ScalarField::one()), |p| Some(*p * tau))
                .take(self.batch_size)
                .collect();

        let g = E::G1::generator();
        let h = E::G2::generator();

        let powers_of_g = g.batch_mul(&powers_of_tau);

        let mut top_tau = powers_of_tau.clone();
        top_tau.truncate(self.batch_size);
        top_tau.reverse();
        top_tau.resize(2 * self.batch_size, E::ScalarField::zero());

        let top_domain =
            Radix2EvaluationDomain::<E::ScalarField>::new(2 * self.batch_size).unwrap();
        let top_tau = top_domain.fft(&top_tau);
        let y = g.batch_mul(&top_tau);

        // --------------------------------------------------------------------------
        // Generate and Scale Secret Shares from SkCombined struct entries
        // --------------------------------------------------------------------------
        let share_domain = (1..=self.n)
            .map(|j| E::ScalarField::from(j as u64))
            .collect::<Vec<_>>();

        let eval_domain = (0..=self.t)
            .map(|j| -E::ScalarField::from(j as u64))
            .collect::<Vec<_>>();

        let mut all_sk_shares_1 = Vec::new();
        let mut all_sk_shares_2 = Vec::new();

        for sk in &self.sk_combined {
            let mut sk_poly = vec![E::ScalarField::zero(); self.t + 1];
            sk_poly[0] = sk.sk_alpha;
            for j in 1..=self.t {
                sk_poly[j] = E::ScalarField::rand(rng);
            }

            let sk_shares = lagrange_interp_eval(&eval_domain, &share_domain, &sk_poly);

            let mut sk_shares_1 = Vec::with_capacity(sk_shares.len());
            let mut sk_shares_2 = Vec::with_capacity(sk_shares.len());

            for share in sk_shares.iter() {
                let mut scaled_y = *share;
                scaled_y.mul_assign(sk.sk_y);
                sk_shares_1.push(scaled_y);

                let mut scaled_z = *share;
                scaled_z.mul_assign(sk.sk_z);
                sk_shares_2.push(scaled_z);
            }

            all_sk_shares_1.push(sk_shares_1);
            all_sk_shares_2.push(sk_shares_2);
        }

        let crs = CRS::<E> {
            powers_of_g,
            htau: h * tau,
            y,
        };

        (crs, all_sk_shares_1, all_sk_shares_2)
    }
}    
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    type G2 = <E as Pairing>::G2;

    #[test]
    fn test_dealer() {
        let mut rng = ark_std::test_rng();
        let batch_size = 1 << 5;
        let n = 1 << 4;
        let t = n / 2 - 1;
        let code_len = 1; // Number of secret keys to combine

        let mut dealer = Dealer::<E>::new(batch_size, n, t, code_len);
        let (crs, all_sk_shares_1,all_sk_shares_2) = dealer.setup(&mut rng);

        // Check that all_sk_shares_1 and all_sk_shares_2 have length equal to code_len
        assert_eq!(all_sk_shares_1.len(), code_len);
        assert_eq!(all_sk_shares_2.len(), code_len);

        // loop i from 0 to code_len - 1 

        for (idx, (sk_shares_1, sk_shares_2)) in all_sk_shares_1.iter().zip(all_sk_shares_2.iter()).enumerate() {
            // Check that the shares have length equal to n
            assert_eq!(sk_shares_1.len(), n);
            assert_eq!(sk_shares_2.len(), n);

            let share_domain = (1..=n).map(|j| Fr::from(j as u64)).collect::<Vec<_>>();
            let recovered_sk_alpha_y = lagrange_interp_eval(&share_domain, &vec![Fr::zero()], sk_shares_1)[0];
            let recovered_sk_alpha_z = lagrange_interp_eval(&share_domain, &vec![Fr::zero()], sk_shares_2)[0];

            let sk = &dealer.sk_combined[idx];
            let expected_y = sk.sk_alpha * sk.sk_y;
            let expected_z = sk.sk_alpha * sk.sk_z;

            //  Log recovered and expected values
            println!("\n--- Secret Share Group [{}] ---", idx);
            println!("Recovered a·y: {}", recovered_sk_alpha_y);
            println!("Expected  a·y: {}", expected_y);
            println!("Recovered a·z: {}", recovered_sk_alpha_z);
            println!("Expected  a·z: {}", expected_z);

            assert_eq!(recovered_sk_alpha_y, expected_y);
            assert_eq!(recovered_sk_alpha_z, expected_z);

            let (pk_alpha_y_z, pk_y, pk_z) = dealer.get_pk()[idx];
            let expected_pk_1 = pk_z * recovered_sk_alpha_y;
            let expected_pk_2 = pk_y * recovered_sk_alpha_z;

            println!("Recovered PK:     {}", pk_alpha_y_z);
            println!("Expected PK_y⋅a·z: {}", expected_pk_2);
            println!("Expected PK_z⋅a·y: {}", expected_pk_1);

            assert_eq!(pk_alpha_y_z, expected_pk_1);
            assert_eq!(pk_alpha_y_z, expected_pk_2);


        }

        // Check that the CRS is correctly formed
        assert_eq!(crs.powers_of_g.len(), batch_size);
        assert_eq!(crs.y.len(), 2 * batch_size);
        assert!(!crs.htau.is_zero());
    }
}
