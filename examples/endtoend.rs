use std::collections::BTreeMap;
use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, PrimeGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand,Zero};
use ark_ff::Field;
use traceable_batch_threshold::{
    keygen::{OneKey,fetch_one_key,PkCombined},
    crsgen::{CRS,read_crs},
    decryption::{aggregate_partial_decryptions, decrypt_all,get_digest, SecretKey},
    encryption::{encrypt, Ciphertext},
    utils::{hash_to_bytes, bipart_lagrange_interp_eval, lagrange_interp_eval, open_all_values, xor},
};
use redb::{Database,ReadableTable, TableDefinition};
use std::result::Result;
use ark_std::rand::Rng;

const DB_PATH: &str = "ttbe_database.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");


type E = Bls12_381;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;

fn main() {
    let mut rng = ark_std::test_rng();
    //let batch_size = 1 << 5;
    let batch_size = 4;
    let code_pos = 0;
    let n = 1 << 4;
    let t = n / 2 - 1;    
    // debug 
    let bip_flags_at_code_pos: Vec<bool> = (0..n).map(|_| rng.gen_bool(0.5)).collect();
    //let bip_flags_at_code_pos: Vec<bool> = vec![false; n];
    //let bip_flags_at_code_pos: Vec<bool> = vec![true; n];


    println!("Batch size: {}, n:{}", batch_size, n);
    // Fetch key for encryption
    let db = Database::open(DB_PATH).expect("Failed to open database");
    let key = fetch_one_key::<E>(&db, code_pos);
    let crs = read_crs::<E>(&db, &batch_size.to_string());



    let h_j_bid = G1::rand(&mut rng);
    let mut secret_key: Vec<SecretKey<E>> = Vec::new();
    for i in 0..n {
        if bip_flags_at_code_pos[i] {
            secret_key.push(SecretKey::new(key.sk_combined.sk_shares_y1[i]));
        } else {
            secret_key.push(SecretKey::new(key.sk_combined.sk_shares_z0[i]));
            
        }
    }

    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let msg = [2u8; 32];


    // generate ciphertexts for all points in tx_domain
    let mut ct: Vec<Ciphertext<E>> = Vec::new();
    for x in tx_domain.elements() {
        let (cxt,sig) = encrypt::<E>(msg, x, h_j_bid, crs.htau, key.pk_combined.clone(), &mut rng);
        //// invalid right ciphertexts
        //    let mut cxt_r_invalid =cxt.clone();
        //    cxt_r_invalid.ct4 = G2::rand(&mut rng); // make ct4 invalid
        //    ct.push(cxt_r_invalid);
        ct.push(cxt);
    }

    //generate the digest
    let com=get_digest(&ct,  &crs);

    // generate partial decryptions
    let mut partial_decryptions: BTreeMap<usize, (G1,bool)> = BTreeMap::new();
    for i in 0..n / 2 {
        //let partial_decryption = secret_key[i].partial_decrypt(&ct, h_j_bid, pk, &crs);
        let digest = com +h_j_bid;
        let wit_sig = secret_key[i].partial_decrypt(digest);
        partial_decryptions.insert(i + 1, (wit_sig,bip_flags_at_code_pos[i]));
    }

    let dec_timer = start_timer!(|| "Decryption");
    let (sigma_left,sigma_right) = aggregate_partial_decryptions(&partial_decryptions);  

    let messages = decrypt_all(sigma_left,sigma_right, &ct, h_j_bid, &crs);
    for i in 0..batch_size {
        assert_eq!(msg, messages[i], "Decryption failed for message at index {}", i);
    }
    end_timer!(dec_timer);
}
