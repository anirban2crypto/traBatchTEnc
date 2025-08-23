//use rand::Rng;
use std::fs;
use std::path::Path;
use std::collections::BTreeMap;
use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, PrimeGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand,Zero};
use ark_ff::Field;
use traceable_batch_threshold::{
    keygen::{OneKey,fetch_one_key,PkCombined,gen_batch_keys, fetch_batch_of_keys},
    crsgen::{CRS,read_crs,insert_crs},
    decryption::{aggregate_partial_decryptions, decrypt_all,get_digest, SecretKey},
    encryption::{encrypt, Ciphertext},
    fincode::{code_generator,tracing_algorithm},
    decoder::{decoder},
    utils::{hash_to_bytes, bipart_lagrange_interp_eval, lagrange_interp_eval, open_all_values, xor},
};
use redb::{Database,ReadableTable, TableDefinition};
use std::result::Result;
use ark_std::rand::Rng;

const DB_PATH: &str = "ttbe_database_ete.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");


type E = Bls12_381;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;

fn main() {
    let mut rng = ark_std::test_rng();
    let mut batch_size = 4;
    let mut n = 1 << 4;       // number of users
    let mut t = n / 2 - 1;    // threshold <=t secret sharing can not decrypt
    let coalition_size= n / 2;          
    let start_pos = 0;
    let mut key_batch_size = 500;  // generate keys in batches    
    let mut corrupt_indices: Vec<usize> = (0..coalition_size).collect();

    //----------------------------------------------------------------------------------------------
    //                   Key Generation
    //----------------------------------------------------------------------------------------------   
    let kg_timer = start_timer!(|| "Key Generation");
    let (p_array, x_matrix, f_array, x_bar_matrix)=code_generator(n, coalition_size);
    let total_keys = x_bar_matrix[0].len();  //code length
    let crs = CRS::<E>::new(batch_size);
    let mut db: Database;
    if !Path::new(DB_PATH).exists(){
            db = Database::create(DB_PATH).expect("Failed to create database");
    } else {
            db = Database::open(DB_PATH).expect("Failed to open database");
    }
    if total_keys < key_batch_size {
        key_batch_size = total_keys;
    } 
    for num_iter in 0..(total_keys / key_batch_size)+1 {
        let start_pos = num_iter * key_batch_size;
        let key_batch_size = if (num_iter + 1) * key_batch_size > total_keys {
            total_keys - start_pos
        } else {
            key_batch_size
        };
        //println!("Generating keys from position {} to {}", start_pos, start_pos + key_batch_size);
        gen_batch_keys::<E>(&db, n, t, start_pos, key_batch_size)
            .expect("Failed to generate batch keys");
    }        
    insert_crs::<E>(&db, &batch_size.to_string(), &crs).expect("Failed to insert CRS into database");  
    end_timer!(kg_timer);   
    //----------------------------------------------------------------------------------------------
    //                   Fetching key for Encryption and Decryption at code_pos
    //----------------------------------------------------------------------------------------------
    let mut rrng = rand::thread_rng();
    let code_pos = rrng.gen_range(0..total_keys-1);
    let mut bip_flags_at_code_pos: Vec<bool> = Vec::with_capacity(coalition_size);
    for &corr_indx in &corrupt_indices {
        let flag = x_bar_matrix[corr_indx][code_pos] == 1;
        bip_flags_at_code_pos.push(flag);
    }
    let key = fetch_one_key::<E>(&db, code_pos);
    let crs = read_crs::<E>(&db, &batch_size.to_string());
    let h_j_bid = G1::rand(&mut rng);
    let mut secret_key: Vec<SecretKey<E>> = Vec::new();
    for i in 0..coalition_size {
        if bip_flags_at_code_pos[i] {
            secret_key.push(SecretKey::new(key.sk_combined.sk_shares_y1[corrupt_indices[i]]));
        } else {
            secret_key.push(SecretKey::new(key.sk_combined.sk_shares_z0[corrupt_indices[i]]));
            
        }
    }
    //----------------------------------------------------------------------------------------------
    //                   Encryption
    //----------------------------------------------------------------------------------------------    
    let ec_timer = start_timer!(|| "Encryption");
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let msg = [2u8; 32];
    // generate ciphertexts for all points in tx_domain
    let mut ct: Vec<Ciphertext<E>> = Vec::new();
    for x in tx_domain.elements() {
        let (cxt,sig) = encrypt::<E>(msg, x, h_j_bid, crs.htau, key.pk_combined.clone(), &mut rng);
        ct.push(cxt);
    }
    end_timer!(ec_timer); 
    //----------------------------------------------------------------------------------------------
    //                   Partial Decryption
    //----------------------------------------------------------------------------------------------
    let pd_timer = start_timer!(|| "Partial Decryptions");
    let com=get_digest(&ct,  &crs);
    let mut pd_list: BTreeMap<usize, (<E as Pairing>::G1, bool)> = BTreeMap::new();
    for i in 0..coalition_size {
        let digest = com + h_j_bid;
        let pd = secret_key[i].partial_decrypt(digest);
        pd_list.insert(corrupt_indices[i] + 1, (pd, bip_flags_at_code_pos[i]));
    }
    end_timer!(pd_timer); 
    //----------------------------------------------------------------------------------------------
    //                    Combine
    //----------------------------------------------------------------------------------------------    
    let com_timer = start_timer!(|| "Combine");
    let (sigma_left,sigma_right) = aggregate_partial_decryptions(&pd_list); 
    end_timer!(com_timer); 
    //----------------------------------------------------------------------------------------------
    //                    Decryption
    //----------------------------------------------------------------------------------------------
    let dec_timer = start_timer!(|| "Decryption");
    let messages = decrypt_all(sigma_left,sigma_right, &ct, h_j_bid, &crs);
    for i in 0..batch_size {
        assert_eq!(msg, messages[i], "Decryption failed for message at index {}", i);
    }
    end_timer!(dec_timer);
    //----------------------------------------------------------------------------------------------
    //                    Cleanup
    //----------------------------------------------------------------------------------------------
    drop(db);
    fs::remove_file(DB_PATH).expect("Failed to delete database file");
}
