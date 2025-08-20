use std::path::Path;
use std::collections::BTreeMap;
use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, PrimeGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand,Zero};
use ark_ff::Field;
use crate::{
    keygen::{OneKey,fetch_one_key,PkCombined,gen_batch_keys},
    crsgen::{CRS,read_crs,insert_crs},
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

pub fn decoder<E: Pairing>(
    db: &Database,
    code_pos: usize,
    ct: &Vec<Ciphertext<E>>,
    h_j_bid: E::G1,
    coalition_size: usize,
    batch_size: usize,
    corrupt_indices: &Vec<usize>, // indices start from 0
    bip_flags: &Vec<bool>,
    msg: &Vec<[u8; 32]>,
) -> bool {
       
    assert_eq!(corrupt_indices.len(), coalition_size); 
    assert_eq!(bip_flags.len(), coalition_size);
    assert_eq!(msg.len(), batch_size);

   
    // Fetch key for encryption
    //let db = Database::open(DB_PATH).expect("Failed to open database");
    let key = fetch_one_key::<E>(&db, code_pos);
    let crs = read_crs::<E>(&db, &batch_size.to_string());


    let mut secret_key: Vec<SecretKey<E>> = Vec::new();
    for i in 0..coalition_size {
        if bip_flags[i] {
            secret_key.push(SecretKey::new(key.sk_combined.sk_shares_y1[corrupt_indices[i]]));
        } else {
            secret_key.push(SecretKey::new(key.sk_combined.sk_shares_z0[corrupt_indices[i]]));
            
        }
    }

    //generate the digest
    let com=get_digest(&ct,  &crs);

    // generate partial decryptions
    let mut pd_list: BTreeMap<usize, (<E as Pairing>::G1, bool)> = BTreeMap::new();
    for i in 0..coalition_size {
        let digest = com + h_j_bid;
        let pd = secret_key[i].partial_decrypt(digest);
        pd_list.insert(corrupt_indices[i] + 1, (pd, bip_flags[i]));
    }
    
    let (sigma_left,sigma_right) = aggregate_partial_decryptions(&pd_list);  

    let recovered_msg = decrypt_all(sigma_left,sigma_right, &ct, h_j_bid, &crs);

    // return tree if the recovered message matches the original message for all indices
    for i in 0..batch_size {
        if recovered_msg[i] != msg[i] {
            return false; // Decryption failed for at least one message
        }
    }
    true // All messages were successfully decrypted
    
}

#[cfg(feature = "DecoderTest")]
mod DecoderTest{
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
    fn test_decoder() {
        let mut rng = thread_rng();
        let batch_size = 4;
        let code_pos = 0;
        let n = 1 << 4;
        let t = n / 2 - 1;
        let coalition_size=n/2; 
        let corrupt_indices: Vec<usize> = (0..coalition_size).collect();          
        let bip_flags: Vec<bool> = (0..coalition_size).map(|_| rng.gen_bool(0.5)).collect();        
        
        // Fetch key for encryption
        let mut db: Database;
        if !Path::new(DB_PATH).exists(){
             db = Database::create(DB_PATH).expect("Failed to create database");
        } else {
             db = Database::open(DB_PATH).expect("Failed to open database");
        }
        let crs = CRS::<E>::new(batch_size);
        insert_crs::<E>(&db, &batch_size.to_string(), &crs).expect("Failed to insert CRS into database");
        gen_batch_keys::<E>(&db, n, t, 0, n).expect("Failed to generate batch keys");
        let key = fetch_one_key::<E>(&db, code_pos);
        let crs = read_crs::<E>(&db, &batch_size.to_string());
        //drop(db);

        let h_j_bid = G1::rand(&mut rng);
        let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
        let msg = [2u8; 32];

        // generate ciphertexts for all points in tx_domain
        let mut ct: Vec<Ciphertext<E>> = Vec::new();
        for x in tx_domain.elements() {
            let (cxt,sig) = encrypt::<E>(msg, x, h_j_bid, crs.htau, key.pk_combined.clone(), &mut rng);
            ct.push(cxt);
        }
        let output=decoder::<Bls12_381>(&db,code_pos,&ct, h_j_bid, coalition_size,
             batch_size, &corrupt_indices, &bip_flags, &vec![msg; batch_size]);
        println!("Decoder output: {}", output);
        assert!(output, "Decoder failed to recover the original messages");
    }
}