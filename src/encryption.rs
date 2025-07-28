use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::*;
use ark_std::UniformRand;
use merlin::Transcript;
use retry::{delay::NoDelay, retry};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand_core::OsRng;
use crate::utils::{add_to_transcript, hash_to_bytes, xor,sign_OTS,verify_OTS};



#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Ciphertext<E: Pairing> {
    pub ct1: [u8; 32],
    pub ct2: E::G2,
    pub ct3: E::G2,
    pub ct4: E::G2,
    pub sig_pk: E::G2,
    pub id_x: E::ScalarField,    
}

impl<E: Pairing> Ciphertext<E> {
    /// panicks if ciphertext does not verify
    pub fn verify(&self, htau: E::G2, pk: E::G2) {
        let g = E::G1::generator();
        let h = E::G2::generator();

        // k2.ct2^c = h^{(tau-x)*z_alpha}, k3.ct3^c = h^{z_alpha} * pk^{z_beta}, k4.ct4^c = h^{z_beta}, and k_s.gs^c = g^{z_s}
        let minus_c = -self.pi.c;
        let recovered_k2 = (htau - (h * self.x)) * self.pi.z_alpha + (self.ct2 * minus_c);
        let recovered_k3 = h * self.pi.z_alpha + pk * self.pi.z_beta + (self.ct3 * minus_c);
        let recovered_k4 = h * self.pi.z_beta + (self.ct4 * minus_c);
        let recovered_k_s = g * self.pi.z_s + (self.gs * minus_c);

        let mut ts: Transcript = Transcript::new(&[0u8]);
        add_to_transcript(&mut ts, b"ct1", self.ct1);
        add_to_transcript(&mut ts, b"ct2", self.ct2);
        add_to_transcript(&mut ts, b"ct3", self.ct3);
        add_to_transcript(&mut ts, b"ct4", self.ct4);
        add_to_transcript(&mut ts, b"gs", self.gs);
        add_to_transcript(&mut ts, b"x", self.x);

        add_to_transcript(&mut ts, b"k2", recovered_k2);
        add_to_transcript(&mut ts, b"k3", recovered_k3);
        add_to_transcript(&mut ts, b"k4", recovered_k4);
        add_to_transcript(&mut ts, b"k_s", recovered_k_s);

        // Fiat-Shamir to get challenge
        let mut c_bytes = [0u8; 31];
        ts.challenge_bytes(&[8u8], &mut c_bytes);
        let c = E::ScalarField::from_random_bytes(&c_bytes).unwrap();

        // assert that the recomputed challenge matches
        assert_eq!(self.pi.c, c);
    }
}

pub fn encrypt<E: Pairing>(
    msg: [u8; 32],
    id_x: E::ScalarField,  
    j_number: usize,  
    batch_level: E::G1,
    tau_in_g2: E::G2,
    pk: Vec<(E::G2, E::G2, E::G2)>,
    rng: &mut impl rand::Rng,
) -> Ciphertext<E> {
    let g = E::G1::generator();
    let h = E::G2::generator();

    // hash element S to curve to get tg
    // retry if bytes cannot be converted to a field element
    let result = retry(NoDelay, || {
        let sig_sk = E::ScalarField::rand(rng);
        let sig_pk = h * sig_sk;
        let sig_pk_hash = hash_to_bytes(sig_pk);
        let id_y_option = E::ScalarField::from_random_bytes(&sig_pk_hash);

        match id_y_option {
            Some(id_y) => Ok((sig_sk, sig_pk, id_y)),
            None => {
                #[cfg(debug_assertions)]
                {
                    dbg!("Failed to hash to field element, retrying...");
                }
                Err(())
            }
        }
    });

    let (sig_sk, sig_pk, id_y) = result.unwrap();

    // compute mask
    let alpha = E::ScalarField::rand(rng);
    let beta = E::ScalarField::rand(rng);
    let mask = E::pairing(hid - (g * id_y), h) * alpha; //e(H(id)/g^tg, h)^alpha
    let hmask = hash_to_bytes(mask);

    // xor msg and hmask
    let ct1: [u8; 32] = xor(&msg, &hmask).as_slice().try_into().unwrap();
    let ct2 = (htau - (h * x)) * alpha; //h^{(tau-x)*alpha}
    let ct3 = h * alpha + pk * beta; //h^alpha * pk^beta
    let ct4 = h * beta; //h^beta


    let mut ts: Transcript = Transcript::new(&[0u8]);
    add_to_transcript(&mut ts, b"ct1", ct1);
    add_to_transcript(&mut ts, b"ct2", ct2);
    add_to_transcript(&mut ts, b"ct3", ct3);
    add_to_transcript(&mut ts, b"ct4", ct4);
    add_to_transcript(&mut ts, b"id_y_gs", sig_pk);
    add_to_transcript(&mut ts, b"id_x", id_x);
    let sig = sign(sig_sk, &mut ts);
    //let is_valid = verify(msg, sig, pk);


    Ciphertext {
        ct1,
        ct2,
        ct3,
        ct4,
        sig_pk,
        id_x,
    }
}

#[cfg(test_encryption)]
mod tests {
    use crate::dealer::Dealer;

    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use rand::thread_rng;

    type E = Bls12_381;
    type Fr = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;
    type G1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1;
    type G2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2;

    #[test_encryption]
    fn test_encryption() {
        let mut rng = thread_rng();

        let batch_size = 1 << 5;
        let n = 1 << 4;
        let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();

        let mut dealer = Dealer::<E>::new(batch_size, n, n / 2 - 1);
        let (crs, _) = dealer.setup(&mut rng);
        let pk = dealer.get_pk();

        let msg = [1u8; 32];
        let x = tx_domain.group_gen;

        let hid = G1::rand(&mut rng);
        let rng = &mut thread_rng();
        let ct = encrypt::<Bls12_381>(msg, x, hid, crs.htau, pk, rng);

        let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes).unwrap();
        println!("Compressed ciphertext: {} bytes", ct_bytes.len());

        let mut ct_bytes = Vec::new();
        ct.serialize_uncompressed(&mut ct_bytes).unwrap();
        println!("Uncompressed ciphertext: {} bytes", ct_bytes.len());

        let mut g1_bytes = Vec::new();
        let mut g2_bytes = Vec::new();
        let mut fr_bytes = Vec::new();

        let g = G1::generator();
        let h = G2::generator();
        let x = tx_domain.group_gen;

        g.serialize_compressed(&mut g1_bytes).unwrap();
        h.serialize_compressed(&mut g2_bytes).unwrap();
        x.serialize_compressed(&mut fr_bytes).unwrap();

        println!("G1 len: {} bytes", g1_bytes.len());
        println!("G2 len: {} bytes", g2_bytes.len());
        println!("Fr len: {} bytes", fr_bytes.len());

        ct.verify(crs.htau, pk);
    }
}
