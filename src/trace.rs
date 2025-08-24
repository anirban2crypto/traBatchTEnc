use std::path::Path;
use std::collections::BTreeMap;
use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, PrimeGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand,Zero};
use ark_ff::Field;
use crate::{
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
use rand::thread_rng;

const DB_PATH: &str = "ttbe_database.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");






pub fn trace<E: Pairing>(
    db: &Database,
    n: usize,
    t: usize,
    batch_size: usize,
    coalition_size: usize,
    total_keys: usize,
)-> Vec<usize>{
        let mut rng = thread_rng();        
        let mut corrupt_indices: Vec<usize> = (0..coalition_size).collect();
        println!("Corrupt indices: {:?}", corrupt_indices);
        let h_j_bid = E::G1::rand(&mut rng);
        let tx_domain = Radix2EvaluationDomain::<E::ScalarField>::new(batch_size).unwrap();
        let msg = [2u8; 32];
        let crs = read_crs::<E>(&db, &batch_size.to_string());        
        let mut key_batch_size = 500; // read keys in batches
        //start Debug trace with hard coded values   
        //coalition_size = 3     
        // corrupt_indices = vec![1, 2, 3];
        // println!("Corrupt indices: {:?}", corrupt_indices);
        // let x_bar_matrix: Vec<Vec<u8>> = vec![
        //     vec![0, 1, 0, 0, 1, 1],
        //     vec![0, 0, 1, 0, 0, 1],
        //     vec![0, 0, 1, 0, 0, 1],
        //     vec![0, 0, 1, 0, 1, 1],
        // ];
        // // print x_bar_matrix for each row
        // println!("x_bar_matrix:");
        // for row in &x_bar_matrix {
        //     println!("{:?}", row);
        // }        
        // end Debug trace with hard coded values


        let (p_array, x_matrix, f_array, x_bar_matrix)=code_generator(n, coalition_size);
        let code_len = x_bar_matrix[0].len();

        //check code_len is equal to total_keys, if not print code_len and total_keys
        if code_len != total_keys {
            println!("Code length: {}, Total keys: {}", code_len, total_keys);
            return vec![];
        }                        
        let mut w_star = Vec::with_capacity(code_len);




        // Loop over code lengths
        let mut key_list: Vec<OneKey<E>>=Vec::new();
        for code_pos in 0..code_len {
            if code_pos % key_batch_size == 0 {                 
                //println!("Processing code position: {}", code_pos);
                let mut fetch_batch_size = key_batch_size;
                if code_pos + key_batch_size > code_len {
                    fetch_batch_size = code_len - code_pos;
                }
                else {
                    fetch_batch_size = key_batch_size;
                }
                key_list = fetch_batch_of_keys::<E>(&db,code_pos,fetch_batch_size).expect("Failed to fetch batch of keys");
            }            
            let mut bip_flags_at_code_pos: Vec<bool> = Vec::with_capacity(coalition_size);
            for &corr_indx in &corrupt_indices {
                let flag = x_bar_matrix[corr_indx][code_pos] == 1;
                bip_flags_at_code_pos.push(flag);
            }
            // Fetch details for encryption
            //let db = Database::open(DB_PATH).expect("Failed to open database");
            //let key = fetch_one_key::<E>(&db, code_pos);
            let key = &key_list[code_pos % key_batch_size];
            
            //drop(db);
            // generate valid left ciphertext and an invalid right ciphertext
            // generate with invalid left and right ciphertexts
            // generate valid left and right ciphertexts
            let mut val_l_inval_r_ct: Vec<Ciphertext<E>> = Vec::new();
            let mut inval_l_r_ct: Vec<Ciphertext<E>> = Vec::new();
            let mut valid_l_r_ct: Vec<Ciphertext<E>> = Vec::new();

            //Generate batch of ciphertexts
            for x in tx_domain.elements() {
                let (cxt,sig) = encrypt::<E>(msg, x, h_j_bid, crs.htau, key.pk_combined.clone(), &mut rng);
                valid_l_r_ct.push(cxt.clone());

                //valid left and invalid right ciphertexts 
                let mut cxt_r_invalid =cxt.clone();
                cxt_r_invalid.ct4 = E::G2::rand(&mut rng); // make ct4 invalid
                val_l_inval_r_ct.push(cxt_r_invalid);

                let mut cxt_l_r_invalid = cxt.clone();
                cxt_l_r_invalid.ct3 = E::G2::rand(&mut rng); // make ct3 invalid
                cxt_l_r_invalid.ct4 = E::G2::rand(&mut rng); // make ct4 invalid
                inval_l_r_ct.push(cxt_l_r_invalid);    

            } 
                   
            // Run the decoder valid left and invalid right ciphertexts           
            let dec_suc_001=decoder::<E>(
                &db,
                code_pos,
                &val_l_inval_r_ct,
                h_j_bid,
                coalition_size,
                batch_size,
                &corrupt_indices,
                &bip_flags_at_code_pos,
                &vec![[2u8; 32]; batch_size],
            );
            //println!("Decoder success for valid left and invalid right ciphertexts: {}", dec_suc_001);

            // Run the decoder invalid left and  right ciphertexts
            // Assuming symantic security, the decoder should fail
            let dec_suc_100=false;
            // let dec_suc_100=decoder::<E>(
            //     &db,
            //     code_pos,
            //     &inval_l_r_ct,
            //     h_j_bid,
            //     coalition_size,
            //     batch_size,
            //     &corrupt_indices,
            //     &bip_flags_at_code_pos,
            //     &vec![[2u8; 32]; batch_size],
            // );
            //println!("Decoder success for invalid left and right ciphertexts: {}", dec_suc_100);

            // Run the decoder valid left and right ciphertexts
            // assuming the perfect decoder should succeed always
             let dec_suc_111=true;
            // let dec_suc_111=decoder::<E>(
            //     &db,
            //     code_pos,
            //     &valid_l_r_ct,
            //     h_j_bid,
            //     coalition_size,
            //     batch_size,
            //     &corrupt_indices,
            //     &bip_flags_at_code_pos,
            //     &vec![[2u8; 32]; batch_size],
            // );
            //println!("Decoder success for valid left and right ciphertexts: {}", dec_suc_111);
            
            // if (dec_suc_001 xor  dec_suc_100) is true then   w_star.push('0');
            // if (dec_suc_001 xor  dec_suc_111) is true then   w_star.push('1');
            // if both condition above are false then   w_star.push('?');
            if dec_suc_001 ^ dec_suc_100 {
                w_star.push('0');
            } else if dec_suc_001 ^ dec_suc_111 {
                w_star.push('1');
            } else {
                // If none of the conditions are met, we can push a value '?'
                w_star.push('?'); 
            }                                    
        }                               
        //println!("w_star: {:?}", w_star);  
        let delta = 0.5;  
        let accused_users=tracing_algorithm(delta, coalition_size, n, w_star, x_matrix, p_array, f_array);
        accused_users
}

#[cfg(feature = "TraceTest")]
mod TraceTest {
    use super::*;
    use ark_bls12_381::Bls12_381;
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    type G2 = <E as Pairing>::G2;

    #[test]
    fn test_trace() {
    
        let mut batch_size = 4;
        let mut n = 1 << 4;       // number of users
        let mut t = n / 2 - 1;    // threshold <=t secret sharing can not decrypt
        let coalition_size= n / 2;        
        let log_c = (coalition_size as f64).ln(); 
        let x = (log_c * log_c).floor() as usize;        
        let total_keys = 5 * coalition_size*coalition_size* x ; // code length
        let start_pos = 0;
        let mut key_batch_size = 500;  // generate keys in batches
        if total_keys < key_batch_size {
            key_batch_size = total_keys;
        } 
        // generate crs and keys and insert into DB
        // print generation of crs and keys stated
        //println!("Generating CRS and keys for batch size: {}, total keys: {}", batch_size, total_keys);
        let crs = CRS::<E>::new(batch_size);
        let mut db: Database;
        if !Path::new(DB_PATH).exists(){
             db = Database::create(DB_PATH).expect("Failed to create database");
        } else {
             db = Database::open(DB_PATH).expect("Failed to open database");
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

        // Run the trace
        let trace_result = trace::<E>(&db, n, t, batch_size,coalition_size,total_keys);

        //close the database
        drop(db);
    }
}    
