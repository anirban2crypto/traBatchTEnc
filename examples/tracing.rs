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
    trace::{trace},
};
use redb::{Database,ReadableTable, TableDefinition};
use std::result::Result;
use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;

const DB_PATH: &str = "ttbe_database_tr.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");


type E = Bls12_381;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1;
type G2 = <E as Pairing>::G2;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut rng = rand::thread_rng();
    
    //let b_power = rng.gen_range(1..=4);
    //let batch_size = 1 << b_power; // Bit shift is equivalent to 2^b_power
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
    let code_constant: usize = if args.len() > 4 {
        args[4].parse().expect("Please provide a valid number for code_constant")
    } else {
        10   // coalition size   
    };    
    let coalition_size: usize = if args.len() > 5 {
        args[5].parse().expect("Please provide a valid number for coalition_size")
    } else {
        n / 2   // coalition size   
    }; 
    
    if coalition_size >= n {
        panic!("Coalition size must be less than the number of users (n).");
    }    
    let mut t = coalition_size - 1;    //  Less than coalition size can not decrypt
    let start_pos = 0;
    let mut key_batch_size = 500;  // generate keys in batches    
    let mut corrupt_indices: Vec<usize> = (0..coalition_size).collect();
    //----------------------------------------------------------------------------------------------
    //                   Key Generation
    //----------------------------------------------------------------------------------------------   
    //let kg_timer = start_timer!(|| "Key Generation");
    let log_c = (coalition_size as f64).ln(); 
    let x = (log_c * log_c).floor() as usize;        
    let total_keys = code_constant * coalition_size*coalition_size* x ; // code length   
    println!("Batch size: {}, Number of users: {}, coalition size: {},code_constant: {}, total_keys {}",
     batch_size, n,coalition_size,code_constant,total_keys);
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
    //end_timer!(kg_timer); 

    //----------------------------------------------------------------------------------------------
    //                   Run the trace
    //----------------------------------------------------------------------------------------------
    let trace_timer = start_timer!(|| "Tracing");
    let trace_result = trace::<E>(&db, n, t, batch_size,coalition_size,total_keys,code_constant);
    end_timer!(trace_timer);
    // if there exist a users in trace_result 
    // who is not in corrupt_indices  print trace unsuccessful
    // else print trace_result
    if trace_result.is_empty() {
        println!("Tracing unsuccessful: No accused users.");
    } else {
        let mut tracing_successful = true;
        for &user in &trace_result {
            if !corrupt_indices.contains(&(user)) {
                tracing_successful = false;
                break;
            }
        }
        if tracing_successful {
            println!("Tracing successful: Atleast one accused users are in the coalition.");
        } else {
            println!("Tracing unsuccessful: Some accused users are not in the coalition.");
        }
    }
    println!("Trace result: {:?}", trace_result);

    //close the database
    drop(db);
    fs::remove_file(DB_PATH).expect("Failed to delete database file");
}