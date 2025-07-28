use ark_ec::{pairing::Pairing, scalar_mul::ScalarMul, PrimeGroup};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::*;
use ark_std::{One, UniformRand, Zero};
use rand::thread_rng;
use std::iter;
use redb::{Database,ReadableTable, TableDefinition};
use std::result::Result;
use std::io::Cursor; // Add this import for Cursor

const DB_PATH: &str = "ttbe_database.redb";
const CRS_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");








#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct CRS<E: Pairing> {
    pub batch_size: usize,
    pub powers_of_g: Vec<E::G1Affine>,
    pub htau: E::G2,
    pub y: Vec<E::G1Affine>,
}

impl<E: Pairing> CRS<E> {
    pub fn new(batch_size: usize) -> Self {
        let tau = E::ScalarField::rand(&mut thread_rng());
        let powers_of_tau = iter::successors(Some(E::ScalarField::one()), |p| Some(*p * tau))
            .take(batch_size)
            .collect::<Vec<_>>();

        let g = E::G1::generator();
        let h = E::G2::generator();
        let powers_of_g = g.batch_mul(&powers_of_tau);

        let mut top_tau = powers_of_tau.clone();
        top_tau.truncate(batch_size);
        top_tau.reverse();
        top_tau.resize(2 * batch_size, E::ScalarField::zero());

        let top_domain = Radix2EvaluationDomain::<E::ScalarField>::new(2 * batch_size).unwrap();
        let top_tau = top_domain.fft(&top_tau);
        let y = g.batch_mul(&top_tau);
        let htau = h * tau;

        CRS {
            batch_size,
            powers_of_g,
            htau,
            y,
        }
    }
    pub fn default() -> Self {
        CRS {
            batch_size: 0,
            powers_of_g: Vec::new(),
            htau: E::G2::zero(), // The additive identity for the G2 group
            y: Vec::new(),
        }
    }
}





pub fn insert_crs<E: Pairing>(db: &Database, key: &str, crs: &CRS<E>) -> Result<(), redb::Error> {

    let mut serialized_bytes = Vec::new(); // Create a buffer to serialize into
    crs.serialize_compressed(&mut serialized_bytes).unwrap(); // Serialize into the Vec<u8>


    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(CRS_TABLE_DEF)?;
        table.insert(key, &serialized_bytes)?;

    }
    write_txn.commit()?;
    Ok(())
}

pub fn read_crs<E: Pairing>(db: &Database, key: &str) -> CRS<E> {
    // 1. Begin a read transaction
    let read_txn = match db.begin_read() {
        Ok(txn) => txn,
        Err(e) => {
            eprintln!("Error beginning read transaction for key '{}'", key);
            return CRS::<E>::default(); // Return default on error
        }
    };

    // 2. Open the table within the read transaction
    let table = match read_txn.open_table(CRS_TABLE_DEF) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error opening table for key '{}'", key);
            return CRS::<E>::default(); // Return default on error
        }
    };

    // 3. Get the value from the table
    let value_result = table.get(key);
    let value_option = match value_result {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error getting value for key '{}'", key);
            return CRS::<E>::default(); // Return default on error
        }
    };

    // 4. Handle the Option: Check if the key was found
    let serialized_bytes_access_guard = match value_option {
        Some(guard) => guard,
        None => {
            eprintln!("Key '{}' not found in CRS table.", key);
            return CRS::<E>::default(); // Return default on key not found
        }
    };

    // 5. Extract the serialized bytes and create a Cursor for deserialization
    let serialized_bytes = serialized_bytes_access_guard.value();
    let cursor = Cursor::new(serialized_bytes);

    // 6. Deserialize the CRS
    match CRS::<E>::deserialize_compressed(cursor) {
        Ok(crs) => crs, // Return the deserialized CRS on success
        Err(e) => {
            eprintln!("Error deserializing CRS for key '{}'", key);
            CRS::<E>::default() // Return default on deserialization failure
        }
    }
}

#[cfg(feature = "CRSTest")]
mod crsgen {
    use super::*;
    use ark_bls12_381::Bls12_381;
    type E = Bls12_381;


    #[test]
    fn test_crs_gen() {
        let batch_size = 1 << 5;
        let crs = CRS::<E>::new(batch_size);
        // Check that the CRS is correctly formed
        println!("CRS generated with batch size: {}", crs.batch_size);
        assert_eq!(crs.powers_of_g.len(), batch_size, "Incorrect powers_of_g length");
        assert_eq!(crs.y.len(), 2 * batch_size, "Incorrect y length");
        assert!(!crs.htau.is_zero(), "htau should not be zero");
        assert_eq!(crs.y.len(), 2 * batch_size, "y should have double the batch size length");
        let db = Database::open(DB_PATH).unwrap();
        insert_crs::<E>(&db, &batch_size.to_string(), &crs)
            .expect("Failed to insert CRS into database");
        let crs_read = read_crs::<E>(&db, &batch_size.to_string());
        println!("Read CRS with batch size: {}", crs_read.batch_size);
        println!("HTau: {:?}", crs_read.htau);
        assert_eq!(crs.powers_of_g, crs_read.powers_of_g);
        assert_eq!(crs.y, crs_read.y);
        assert_eq!(crs.htau, crs_read.htau);
        assert_eq!(crs.batch_size, crs_read.batch_size);
        println!("CRS read successfully from database.");
    }
}
