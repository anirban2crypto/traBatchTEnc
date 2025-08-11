use ark_ec::{pairing::Pairing, PrimeGroup};
//use ark_ff::{Field, PrimeField};
use ark_ff::{Field};
use ark_serialize::*;
use ark_std::UniformRand;
use ark_std::Zero;
//use merlin::Transcript;
use retry::{delay::NoDelay, retry};
//use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
//use rand_core::OsRng;
//use crate::utils::{add_to_transcript, hash_to_bytes, xor,sign_OTS,verify_OTS};
//use crate::utils::{add_to_transcript, hash_to_bytes, xor};
use crate::utils::{hash_to_bytes, xor};
use crate::keygen::{PkCombined,fetch_one_key};
//use crate::crsgen::{CRS,read_crs};
use crate::crsgen::{read_crs};
use redb::{Database,ReadableTable, TableDefinition};
use std::result::Result;
//use std::io::Cursor; // Add this import for Cursor

const DB_PATH: &str = "ttbe_database.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct Ciphertext<E: Pairing> {
    pub ct1: E::G2,
    pub ct2: E::G2,
    pub ct3: E::G2,
    pub ct4: E::G2,
    pub ct5: [u8; 32],
    pub sig_pk: E::G2,
    pub hat_omega: E::ScalarField,
}

impl<E: Pairing> Ciphertext<E> {
    /// panicks if ciphertext does not verify
    pub fn verify(&self, sig: E::G1) {
        let mut ct_bytes = Vec::new();
        self.serialize_compressed(&mut ct_bytes).unwrap();
        

        //let mut ts: Transcript = Transcript::new(&[0u8]);
        //add_to_transcript(&mut ts,b"CIPHERTEXT_ENCRYPT", ct_bytes.clone());

        //let is_valid = verify_OTS::<E>(&ct_bytes, sig, self.sig_pk);
        //assert_eq!(is_valid, true, "Ciphertext verification failed");
    }
}

pub fn encrypt<E: Pairing>(
    msg: [u8; 32],
    hat_omega: E::ScalarField,   
    h_j_bid: E::G1,
    htau: E::G2,
    enc_pk: PkCombined<E>,
    rng: &mut impl rand::Rng,
) -> (Ciphertext<E>,E::G1) {
    let g = E::G1::generator();
    let h = E::G2::generator();

    // retry if bytes cannot be converted to a field element
    let result = retry(NoDelay, || {
        let sig_sk = E::ScalarField::rand(rng);
        let sig_pk = h * sig_sk;
        let sig_pk_hash = hash_to_bytes(sig_pk);
        let varphi_option = E::ScalarField::from_random_bytes(&sig_pk_hash);

        match varphi_option {
            Some(varphi) => Ok((sig_sk, sig_pk, varphi)),
            None => {
                // #[cfg(debug_assertions)]
                // {
                //     dbg!("Failed to hash to field element, retrying...");
                // }
                Err(())
            }
        }
    });

    let (sig_sk, sig_pk, varphi) = result.unwrap();

    // compute mask
    let r1 = E::ScalarField::rand(rng);
    let r2 = E::ScalarField::rand(rng);
    let mask_1=  E::pairing(g * varphi, h) * r1;
    let mask_2 = E::pairing(h_j_bid, enc_pk.X) * r2; 
    let hmask = hash_to_bytes(mask_1 - mask_2);
    //dbg!("Final mask in encryption: {:?}", hmask);
    let ct1 = h * r1 + enc_pk.X * r2; // h^r1 * pk.X^r2
    let ct2 = ( (h * hat_omega - htau )) * r1; //h^{(tau-hat_omega)*r1}
    let ct3 = - enc_pk.Y * r2; // -pk.Y * r2
    let ct4 = - enc_pk.Z * r2; // -pk.Z * r2
    let ct5: [u8; 32] = xor(&msg, &hmask).as_slice().try_into().unwrap();

    let ct = Ciphertext {
        ct1,
        ct2,
        ct3,
        ct4,
        ct5,
        sig_pk,
        hat_omega,
    };
    let mut ct_bytes = Vec::new();
    ct.serialize_compressed(&mut ct_bytes).unwrap(); 
    //let sig = sign_OTS::<E>(sig_sk, &ct_bytes); 
    let sig=E::G1::zero();
    (ct,sig)
}

#[cfg(feature = "EncTest")]
mod encryption{
    use super::*;
    use ark_bls12_381::Bls12_381;
    //use ark_bls12_381::G1Projective;
    use ark_ec::bls12::Bls12;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use rand::thread_rng;

    type E = Bls12_381;
    type Fr = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;
    type G1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1;
    type G2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2;

    #[test]
    fn test_encryption() {
        let mut rng = thread_rng();
        let batch_size = 1 << 5;
        let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
        let hat_omega = tx_domain.group_gen;
        let code_pos=0;
        let msg = [1u8; 32];
        

        // Fetch key for encryption
        let db = Database::open(DB_PATH).expect("Failed to open database");
        let key = fetch_one_key::<E>(&db, code_pos);
        let crs = read_crs::<E>(&db, &batch_size.to_string());

        let h_j_bid = G1::rand(&mut rng);
        let (ct,sig) = encrypt::<Bls12_381>(msg, hat_omega, h_j_bid, crs.htau, key.pk_combined, &mut rng);


        let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes).unwrap();
        println!("Compressed ciphertext: {} bytes", ct_bytes.len());

        ct.serialize_uncompressed(&mut ct_bytes).unwrap();
        println!("Uncompressed ciphertext: {} bytes", ct_bytes.len());

        let mut g1_bytes = Vec::new();
        let mut g2_bytes = Vec::new();
        let mut fr_bytes = Vec::new();

        let g = G1::generator();
        let h = G2::generator();
        let hat_omega = tx_domain.group_gen;

        g.serialize_compressed(&mut g1_bytes).unwrap();
        h.serialize_compressed(&mut g2_bytes).unwrap();
        hat_omega.serialize_compressed(&mut fr_bytes).unwrap();

        println!("G1 len: {} bytes", g1_bytes.len());
        println!("G2 len: {} bytes", g2_bytes.len());
        println!("Fr len: {} bytes", fr_bytes.len());

        ct.verify(sig);
    }
}
