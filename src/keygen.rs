use ark_ec::{pairing::Pairing, scalar_mul::ScalarMul, PrimeGroup};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::*;
use ark_std::{rand::RngCore, One, UniformRand, Zero};
use rand::thread_rng;
use std::{iter, vec};
use crate::utils::lagrange_interp_eval;
use std::ops::MulAssign;
use redb::{Database,ReadableTable, TableDefinition};
use std::result::Result;
use std::io::Cursor; // Add this import for Cursor

const DB_PATH: &str = "ttbe_database.redb";
const KEY_TABLE_DEF: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");



#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SkCombined<E: Pairing> {
    pub sk_alpha: E::ScalarField,
    pub sk_y: E::ScalarField,
    pub sk_z: E::ScalarField,
    pub sk_shares_z0: Vec<E::ScalarField>,
    pub sk_shares_y1: Vec<E::ScalarField>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PkCombined<E: Pairing> {
    pub X: E::G2,
    pub Y: E::G2,
    pub Z: E::G2,
}

/// Dealer sets up the CRS and secret shares sk. Assumes the shares are over (1..n) and the secret key is stored at 0
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct OneKey<E: Pairing> {
    pub n: usize,
    pub t: usize,
    pub code_pos: usize,
    pub sk_combined: SkCombined<E>,
    pub pk_combined: PkCombined<E>,
}

impl<E> OneKey<E>
where
    E: Pairing,
{
    pub fn new(n: usize, t: usize, code_pos: usize,rng: &mut impl RngCore) -> Self {
        // --------------------------------------------------------------------------
        // Sample generators and secret keys 
        // --------------------------------------------------------------------------        
        let g = E::G1::generator(); // g is not used, consider removing if it's not needed later.
        let h = E::G2::generator();       
        let sk_alpha = E::ScalarField::rand(rng);
        let sk_y = E::ScalarField::rand(rng);
        let sk_z = E::ScalarField::rand(rng);
        // --------------------------------------------------------------------------
        // Generate and Scale Secret Shares from SkCombined struct entries
        // --------------------------------------------------------------------------
        let share_domain = (1..=n)
            .map(|j| E::ScalarField::from(j as u64))
            .collect::<Vec<_>>();
        let eval_domain = (0..=t)
            .map(|j| -E::ScalarField::from(j as u64))
            .collect::<Vec<_>>();        
        let mut sk_poly = vec![E::ScalarField::zero(); t + 1];
        sk_poly[0] = sk_alpha;
        for j in 1..=t {
            sk_poly[j] = E::ScalarField::rand(rng);
        }
        let sk_shares = lagrange_interp_eval(&eval_domain, &share_domain, &sk_poly);
        let mut sk_shares_z0 = Vec::with_capacity(sk_shares.len());
        let mut sk_shares_y1 = Vec::with_capacity(sk_shares.len());
        for share in sk_shares.iter() {
            let mut scaled_y = *share;
            scaled_y.mul_assign(sk_y);
            sk_shares_y1.push(scaled_y);

            let mut scaled_z = *share;
            scaled_z.mul_assign(sk_z);
            sk_shares_z0.push(scaled_z);
        }

        // Define sk_combined and pk_combined as local variables
        let sk_combined_val = SkCombined {
            sk_alpha,
            sk_y,
            sk_z,
            sk_shares_z0,
            sk_shares_y1,
        };

        let X = E::G2::generator() * (sk_alpha * sk_y * sk_z);
        let Y = E::G2::generator() * sk_y;
        let Z = E::G2::generator() * sk_z;

        let pk_combined_val = PkCombined {
            X,
            Y,
            Z,
        };

        Self {
            n,
            t,
            code_pos,
            sk_combined: sk_combined_val, // Assign the local variable
            pk_combined: pk_combined_val, // Assign the local variable
        }
    }
}  

impl<E: Pairing> Default for SkCombined<E> {
    fn default() -> Self {
        Self {
            sk_alpha: E::ScalarField::zero(),
            sk_y: E::ScalarField::zero(),
            sk_z: E::ScalarField::zero(),
            sk_shares_z0: vec![],
            sk_shares_y1: vec![],
        }
    }
}

impl<E: Pairing> Default for PkCombined<E> {
    fn default() -> Self {
        Self {
            X: E::G2::zero(),
            Y: E::G2::zero(),
            Z: E::G2::zero(),
        }
    }
}

impl<E: Pairing> Default for OneKey<E> {
    fn default() -> Self {
        Self {
            n: 0,
            t: 0,
            code_pos: 0,
            sk_combined: SkCombined::default(),
            pk_combined: PkCombined::default(),
        }
    }
}

pub fn gen_batch_keys<E: Pairing>(
    db: &Database,
    n: usize,
    t: usize,
    start_pos: usize,
    key_batch_size: usize,
) -> Result<(), redb::Error> {
    let mut rng = thread_rng();
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(KEY_TABLE_DEF)?;
        for pos in start_pos..(start_pos + key_batch_size) {
            let onekey = OneKey::<E>::new(n, t, pos, &mut rng);
            let mut serialized_bytes = Vec::new();
            onekey.serialize_compressed(&mut serialized_bytes).unwrap();
            table.insert(pos.to_string().as_str(), &serialized_bytes)?;
        }
    }

    write_txn.commit()?;
    Ok(())
}

pub fn fetch_one_key<E: Pairing>(db: &Database, pos: usize) -> OneKey<E> {

      // 1. Begin a read transaction
    let read_txn = match db.begin_read() {
        Ok(txn) => txn,
        Err(e) => {
            eprintln!("Error beginning read transaction ");
            return OneKey::<E>::default(); // Return default on error
        }
    };

    // 2. Open the table within the read transaction
    let table = match read_txn.open_table(KEY_TABLE_DEF) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error opening table ");
            return OneKey::<E>::default(); // Return default on error
        }
    };

    // 3. Get the value from the table
    let value_result = table.get(pos.to_string().as_str());
    let value_option = match value_result {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error getting value for key '{}'", pos);
            return OneKey::<E>::default(); // Return default on error
        }
    };

    // 4. Handle the Option: Check if the key was found
    let serialized_bytes_access_guard = match value_option {
        Some(guard) => guard,
        None => {
            eprintln!("Key '{}' not found in CRS table.", pos);
            return OneKey::<E>::default(); // Return default on error
        }
    };

    // 5. Extract the serialized bytes and create a Cursor for deserialization
    let serialized_bytes = serialized_bytes_access_guard.value();
    let cursor = Cursor::new(serialized_bytes);

    // 6. Deserialize the OneKey
    match OneKey::<E>::deserialize_compressed(cursor) {
        Ok(okey) => okey, // Return the deserialized CRS on success
        Err(e) => {
            eprintln!("Error deserializing CRS for key '{}'", pos);
            return OneKey::<E>::default(); // Return default on error
        }
    }
}


#[cfg(feature = "KeyTest")]
mod keygen {
    use super::*;
    use ark_bls12_381::Bls12_381;
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    type G2 = <E as Pairing>::G2;

    #[test]
    fn test_key_gen_and_fetch() {
        let key_batch_size = 1 << 5;
        let n = 1 << 4;
        let t = n / 2 - 1;

        let db = Database::open(DB_PATH).expect("Failed to open database");

        // Generate keys and insert into DB
        gen_batch_keys::<E>(&db, n, t, 0, key_batch_size)
            .expect("Failed to generate batch keys");

        // Fetch and verify the first key
        let key = fetch_one_key::<E>(&db, 0);
        assert_eq!(key.n, n);
        assert_eq!(key.t, t);
        assert_eq!(key.code_pos, 0);
        assert!(!key.sk_combined.sk_shares_z0.is_empty());
        assert!(!key.pk_combined.X.is_zero());
        assert!(!key.pk_combined.Y.is_zero());
        assert!(!key.pk_combined.Z.is_zero());
        println!("Key fetched successfully: n={}, t={}, code_pos={}", key.n, key.t, key.code_pos);
    
        assert_eq!(key.sk_combined.sk_shares_z0.len(), n);
        assert_eq!(key.sk_combined.sk_shares_y1.len(), n);

        // Recover sk_alpha * sk_y and sk_alpha * sk_z
        let share_domain = (1..=n).map(|j| Fr::from(j as u64)).collect::<Vec<_>>();
        
        let recovered_sk_alpha_y = lagrange_interp_eval(&share_domain, &vec![Fr::zero()], &key.sk_combined.sk_shares_y1)[0];
        let recovered_sk_alpha_z = lagrange_interp_eval(&share_domain, &vec![Fr::zero()], &key.sk_combined.sk_shares_z0)[0];

        // Expected values directly from the secret keys
        let expected_alpha_y = key.sk_combined.sk_alpha * key.sk_combined.sk_y;
        let expected_alpha_z = key.sk_combined.sk_alpha * key.sk_combined.sk_z;

        // Log recovered and expected scalar values
        println!("Recovered a·y: {}", recovered_sk_alpha_y);
        println!("Expected  a·y: {}", expected_alpha_y);
        println!("Recovered a·z: {}", recovered_sk_alpha_z);
        println!("Expected  a·z: {}", expected_alpha_z);

        assert_eq!(recovered_sk_alpha_y, expected_alpha_y);
        assert_eq!(recovered_sk_alpha_z, expected_alpha_z);

        // Destructure pk_combined correctly
        let PkCombined { X, Y, Z } = key.pk_combined;

        // Verify Public Keys using scalar multiplication
        let expected_X_from_Y_alpha_z = Y * recovered_sk_alpha_z;
        let expected_X_from_Z_alpha_y = Z * recovered_sk_alpha_y;

        println!("Original PK.X: {}", X);
        println!("Derived PK.X from Y and recovered a·z: {}", expected_X_from_Y_alpha_z);
        println!("Derived PK.X from Z and recovered a·y: {}", expected_X_from_Z_alpha_y);

        assert_eq!(X, expected_X_from_Y_alpha_z);
        assert_eq!(X, expected_X_from_Z_alpha_y);
        println!("Key generation and verification successful.");
    }
}