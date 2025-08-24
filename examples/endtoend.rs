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
    keygen::{SkCombined,PkCombined,OneKey,fetch_one_key,gen_batch_keys, fetch_batch_of_keys},
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
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;

const DB_PATH: &str = "ttbe_database_ete.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");


type E = Bls12_381;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;

fn main() {
    let args: Vec<String> = std::env::args().collect();    
    let mut rng = thread_rng();   
    //let mut batch_size = 8;   // batch size for encryption
    //let mut n = 1 << 4;       // number of users
    let batch_size: usize = if args.len() > 2 {
        args[2].parse().expect("Please provide a valid number for batch size")
    } else {
        4
    };
    let n: usize = if args.len() > 3 {
        args[3].parse().expect("Please provide a valid number for n")
    } else {
        8
    };
    let mut code_constant: usize = if args.len() > 4 {
        args[4].parse().expect("Please provide a valid number for code_constant")
    } else {
        10   // coalition size   
    };
    let mut coalition_size: usize = if args.len() > 5 {
        args[5].parse().expect("Please provide a valid number for coalition_size")
    } else {
        n / 2   // coalition size   
    };
    println!("Batch size: {}, Number of users: {},code_constant: {} ,coalition size: {}", batch_size, n,code_constant,coalition_size);
    
              
    let mut t = coalition_size - 1;    // threshold <=t secret sharing can not decrypt
    let start_pos = 0;
    let mut key_batch_size = 500;  // generate keys in batches    
    let mut corrupt_indices: Vec<usize> = (0..coalition_size).collect();
    

    //----------------------------------------------------------------------------------------------
    //                   Key Generation
    //----------------------------------------------------------------------------------------------   
    let kg_timer = start_timer!(|| "Key Generation");
    let (p_array, x_matrix, f_array, x_bar_matrix)=code_generator(n, coalition_size, code_constant);
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
    
    let mut com_sk_bytes = Vec::new();
    let sk_key :SkCombined<E>;
    sk_key=key.sk_combined.clone(); 
    sk_key.serialize_compressed(&mut com_sk_bytes).unwrap();
    let sk_size=com_sk_bytes.len();
    

    let mut com_crs_bytes = Vec::new();
    let crs_value :CRS<E>;
    crs_value=crs.clone(); 
    crs_value.serialize_compressed(&mut com_crs_bytes).unwrap();
    let crs_size=com_crs_bytes.len();
    
    let mut com_pk_bytes = Vec::new();
    let pk_key :PkCombined<E>;
    pk_key=key.pk_combined.clone(); 
    pk_key.serialize_compressed(&mut com_pk_bytes).unwrap();
    let pk_size=com_pk_bytes.len() ;
    

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

    let mut com_ct_bytes = Vec::new();
    let ct_value=ct[0].clone(); 
    ct_value.serialize_compressed(&mut com_ct_bytes).unwrap();
    let ct_size=com_ct_bytes.len();
    //println!("Ciphertext size: {} bytes", ct_size);
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
    let mut total_pd_size=0;
    if let Some((key, (g1, flag))) = pd_list.iter_mut().next() {
        let mut com_pd_bytes = Vec::new();
        key.serialize_compressed(&mut com_pd_bytes).unwrap();
        let pd_key_size=com_pd_bytes.len();
        g1.serialize_compressed(&mut com_pd_bytes).unwrap();
        let pd_g1_size=com_pd_bytes.len() - pd_key_size;
        let pd_flag_size=std::mem::size_of_val(flag);
        total_pd_size=pd_key_size + pd_g1_size + pd_flag_size;        
    }
    //----------------------------------------------------------------------------------------------
    //                    Combine
    //----------------------------------------------------------------------------------------------    
    let com_timer = start_timer!(|| "Combine");
    let (sigma_left,sigma_right) = aggregate_partial_decryptions(&pd_list); 
    end_timer!(com_timer); 
    let mut compress_sigma_bytes = Vec::new();
    sigma_left.serialize_compressed(&mut compress_sigma_bytes).unwrap();
    let sigma_left_size=compress_sigma_bytes.len(); 
    sigma_right.serialize_compressed(&mut compress_sigma_bytes).unwrap();
    let sigma_right_size=compress_sigma_bytes.len() - sigma_left_size;
    let sigma_size=sigma_left_size + sigma_right_size;

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
    let mut total_sk_size=sk_size * total_keys;
    if sk_size * total_keys < 1024 {
        println!("Secret key size: {} bytes", total_sk_size);
    } else if sk_size * total_keys < 1048576 {
        total_sk_size=total_sk_size/1024;
        println!("Secret key size: {} KB", total_sk_size);
    } else {
        total_sk_size=total_sk_size/1048576;
        println!("Secret key size: {} MB", total_sk_size);
    }    
    let mut total_pk_size=pk_size * total_keys + crs_size;
    if total_pk_size < 1024 {
        println!("Public key size: {} bytes", total_pk_size);
    } else if total_pk_size < 1048576 {
        total_pk_size=total_pk_size/1024;
        println!("Public key size: {} KB", total_pk_size);
    } else {
        total_pk_size=total_pk_size/1048576;
        println!("Public key size: {} MB", total_pk_size);
    }
    println!("Ciphertext size: {} bytes", ct_size);
    println!("Partial Decryption size: {} bytes", total_pd_size);
    println!("Sigma size: {} bytes", sigma_size);

}
