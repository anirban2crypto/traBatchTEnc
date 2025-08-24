use rand::Rng;
use rand::thread_rng;

use std::f64::consts::PI;

/// Step 2: Generate bias values P = [p1, ..., p_ell]
fn generate_p_array(c: usize, ell: usize) -> Vec<f64> {
    let t = 1.0 / (300.0 * 300.0 * c as f64 * c as f64);  
    let sqrt_t = t.sqrt();
    let t_prime = sqrt_t.asin();
    let lower_bound = t_prime;
    let upper_bound = (PI / 2.0) - t_prime;

    let mut rng = rand::thread_rng();
    (0..ell)
        .map(|_| {
            let r = rng.gen_range(lower_bound..upper_bound);
            r.sin().powi(2)
        })
        .collect()
}

/// Step 3: Generate binary matrix X of size N × ell using P
fn generate_x_matrix(n: usize, ell: usize, p: &[f64]) -> Vec<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut x_matrix = vec![vec![0u8; ell]; n];

    for i in 0..ell {
        for j in 0..n {
            let bit = if rng.r#gen::<f64>() < p[i] { 1 } else { 0 };
            x_matrix[j][i] = bit;
        }
    }

    x_matrix
}

/// Step 4: Generate binary array F of length ell, each bit is 1 with probability 1/2
fn generate_f_array(ell: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..ell).map(|_| if rng.gen_bool(0.5) { 1 } else { 0 }).collect()
}


/// Step 5: Generate X_bar matrix based on X, F and P
fn generate_x_bar_matrix(x: &[Vec<u8>], f: &[u8], c: usize) -> Vec<Vec<u8>> {
    let n = x.len();
    let ell = x[0].len();
    let mut rng = rand::thread_rng();  
    let t = 1.0 / (300.0 * 300.0 * c as f64 * c as f64);  
    let sqrt_t = t.sqrt();
    let t_prime = sqrt_t.asin();
    let lower_bound = t_prime;
    let upper_bound = std::f64::consts::PI / 2.0 - t_prime;

    let mut x_bar = x.to_vec(); // Start by copying X

    for i in 0..ell {
        // Sample r and compute p = sin²r
        let r = rng.gen_range(lower_bound..upper_bound);
        let p = r.sin().powi(2);

        for j in 0..n {
            if x_bar[j][i] == 1 && rng.r#gen::<f64>() < p {
                x_bar[j][i] = 0;
            }
        }

        // If f[i] == 1, invert the column
        if f[i] == 1 {
            for j in 0..n {
                x_bar[j][i] ^= 1;
            }
        }
    }

    x_bar
}
pub fn code_generator(n: usize, c: usize) 
-> (Vec<f64>, Vec<Vec<u8>>, Vec<u8>, Vec<Vec<u8>>)
{
    // n: number of users
    // c: collusion size 
    let log_c = (c as f64).ln(); 
    let x = (log_c * log_c).floor() as usize;
    // calulate code length ell
    let ell = 5 * c*c* x ;
    //print code lengthe as the value of ell
    //println!("Code length (ell)= 5 * c *c *log_c*log_c: {}", ell);

    let p_array = generate_p_array(c, ell);
    let x_matrix = generate_x_matrix(n, ell, &p_array);
    let f_array = generate_f_array(ell);
    let x_bar_matrix =generate_x_bar_matrix(&x_matrix, &f_array, c);
    // println!("First 10 values of P:");
    // for i in 0..10 {
    //     println!("p[{}] = {:.6}", i + 1, p_array[i]);
    // }

    // println!("\nFirst 5 rows of X:");
    // for row in x_matrix.iter().take(5) {
    //     println!("{:?}", &row[..10]); // print first 10 bits
    // }

    // println!("\nFirst 10 values of F:");
    // for i in 0..10 {
    //     println!("f[{}] = {}", i + 1, f_array[i]);
    // }

    // println!("\nFirst 5 codewords (rows of x_bar_matrix):");
    // for i in 0..5 {
    //     println!("bar_X[{}] = {:?}", i + 1, &x_bar_matrix[i][..10]); // first 10 bits
    // }
    // return the following (p_array,x_matrix, f_array, x_bar_matrix)
    (p_array, x_matrix, f_array, x_bar_matrix)
}


/// Step 1: Pad with '?' to ensure δℓ markings
fn pad_w_star(mut w_star: Vec<char>, delta: f64) -> Vec<char> {
    let ell = w_star.len();
    let target_marks = (delta * ell as f64).ceil() as usize;
    let mut rng = rand::thread_rng();
    let current_marks = w_star.iter().filter(|&&b| b == '?').count();

    while w_star.iter().filter(|&&b| b == '?').count() < target_marks {
        let i = rng.gen_range(0..ell);
        if w_star[i] != '?' {
            w_star[i] = '?';
        }
    }

    w_star
}

/// Step 2–4: Remove all ?-bits and adjust w_star, X, P, F
fn prune_components(
    w_star: &[char],
    x_matrix: &[Vec<u8>],
    p_array: &[f64],
    f_array: &[u8],
) -> (Vec<u8>, Vec<Vec<u8>>, Vec<f64>, Vec<u8>) {
    let mut w_clean = Vec::new();
    let mut x_clean = vec![Vec::new(); x_matrix.len()];
    let mut p_clean = Vec::new();
    let mut f_clean = Vec::new();

    for (i, &bit) in w_star.iter().enumerate() {
        if bit != '?' {
            if let Some(digit) = bit.to_digit(10) {
                w_clean.push(digit as u8);
                for j in 0..x_matrix.len() {
                    x_clean[j].push(x_matrix[j][i]);
                }
                p_clean.push(p_array[i]);
                f_clean.push(f_array[i]);
            } else {
                panic!("Invalid character '{}' at index {} in w_star", bit, i);
            }
        }
    }

    (w_clean, x_clean, p_clean, f_clean)
}

/// Step 5: Flip bits in w_star if f_i == 1
fn flip_marked_bits(w_clean: &mut Vec<u8>, f_clean: &[u8]) {
    for i in 0..w_clean.len() {
        if f_clean[i] == 1 {
            w_clean[i] ^= 1;
        }
    }
}

/// Step 6–7: Construct U matrix and compute scores
fn compute_scores(
    w_clean: &[u8],
    x_clean: &[Vec<u8>],
    p_clean: &[f64],
) -> Vec<f64> {
    let mut scores = Vec::new();
    let ell = w_clean.len();

    for j in 0..x_clean.len() {
        let mut sum = 0.0;
        for i in 0..ell {
            let q = ((1.0 - p_clean[i]) / p_clean[i]).sqrt();
            let u_ji = if x_clean[j][i] == 1 {
                q
            } else {
                -1.0 / q
            };
            sum += w_clean[i] as f64 * u_ji;
        }        
       println!("Score for user {}: {}", j, sum);
       scores.push(sum);
    }

    scores
}




// Helper function for percentile
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = p / 100.0 * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let weight = rank - lower as f64;
    sorted[lower] * (1.0 - weight) + sorted[upper] * weight
}



/// Step 8: Accuse if score exceeds threshold
// fn accuse(
//     scores: &[f64],
//     c: usize,
//     n: usize,
// ) -> Vec<usize> {    
//     let threshold = 20.0 * (c as f64).ln() * ((n as f64)).ln();
//     //println!("Threshold for accusation: {}", threshold);    
//     scores
//         .iter()
//         .copied()
//         .enumerate()
//         .filter(|(_, s)| s > &threshold)
//         .map(|(j, _)| j)
//         .collect()     
  
// }

fn accuse(scores: &[f64], _c: usize, _n: usize) -> Vec<usize> {
    //let mean = scores.iter().sum::<f64>() / scores.len() as f64;
    //let std_dev = (scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / scores.len() as f64).sqrt();
    //let mut threshold = 1.0; // Example threshold for Z-score
    let max = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let mut threshold = max.floor(); // Example threshold for Z-score
    scores
        .iter()
        .copied()
        .enumerate()
        //.filter(|(_, s)| (*s - mean) / std_dev > threshold)
        .filter(|(_, s)| *s  > threshold)
        .map(|(j, _)| j)
        .collect()
}

pub fn tracing_algorithm(
    delta: f64,                // fraction of '?' markings
    c: usize,                  // parameter for code
    n: usize,                  // number of users
    w_star: Vec<char>,         // marked word
    x_matrix: Vec<Vec<u8>>,    // previously generated X matrix
    p_array: Vec<f64>,         // previously computed P
    f_array: Vec<u8>,          // previously generated F
) -> Vec<usize>{
    let padded = pad_w_star(w_star, delta);
    let (mut w_clean, x_clean, p_clean, f_clean) = prune_components(&padded, &x_matrix, &p_array, &f_array);
    flip_marked_bits(&mut w_clean, &f_clean);
    let scores = compute_scores(&w_clean, &x_clean, &p_clean);
    let accused_users = accuse(&scores, c, n);
    //println!("Accused users: {:?}", accused_users);
    accused_users
}

#[cfg(feature = "CodeTest")]
mod code_test {
    use super::*;
    
    #[test]
    fn test_code_gen_and_trace() {
        let n = 1 << 5; // number of users
        let c = n / 2;  // collusion size

        
        //let corrupt_indices = vec![1, 2, 3, 4, 5, 12, 13, 14]; // or any number of indices        
        let mut corrupt_indices: Vec<usize> = (0..c).collect();



        // Generate code components
        let (p_array, x_matrix, f_array, x_bar_matrix)=code_generator(n, c);
        let mut w_star: Vec<char> = vec![];

        
        // print all corrupt indices
        println!("Corrupt indices: {:?}", corrupt_indices);

        // Generate w_star based on x_bar_matrix
        let num_cols = x_bar_matrix[0].len();
        let num_rows = x_bar_matrix.len();
        let mut w_star = Vec::with_capacity(num_cols);

        for col in 0..num_cols {
            let mut all_zero = true;
            let mut all_one = true;

            for row in 0..num_rows {
                if corrupt_indices.contains(&row) {
                    match x_bar_matrix[row][col] {
                        0 => all_one = false,
                        1 => all_zero = false,
                        _ => {
                            all_zero = false;
                            all_one = false;
                        }
                    }                  
                }                
            }
            let symbol = if all_zero {
                '0'
            } else if all_one {
                '1'
            } else {
                let mut rng = rand::thread_rng();
                if rng.gen_bool(0.5) { '1' } else {'0' }
                //'?'
            };

            w_star.push(symbol);
        }




        // Fraction of '?' markings
        //let mismatch_count = w_star.iter().filter(|&&c| c == '?').count();
        //let delta = mismatch_count as f64 / x_bar_matrix[0].len() as f64;
        let delta = 0.5; // Example value for delta
        println!("Fraction of '?' markings (delta): {}", delta);      

        tracing_algorithm(delta, c, n, w_star, x_matrix, p_array, f_array);
    }
}