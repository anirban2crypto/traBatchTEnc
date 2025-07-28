use rand::Rng;
use std::f64::consts::PI;

/// Step 2: Generate bias values P = [p1, ..., p_ell]
fn generate_p_array(c: usize, ell: usize, c2: f64) -> Vec<f64> {
    let t = c2 / (c * c) as f64;
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
            let bit = if rng.gen::<f64>() < p[i] { 1 } else { 0 };
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
fn generate_x_bar_matrix(x: &[Vec<u8>], f: &[u8], c: usize, c2: f64) -> Vec<Vec<u8>> {
    let n = x.len();
    let ell = x[0].len();

    let mut rng = rand::thread_rng();
    let t = c2 / ((c * c) as f64);
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
            if x_bar[j][i] == 1 && rng.gen::<f64>() < p {
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
fn code_generator(n: usize, c: usize, ell: usize, c2: f64) {
    //let c = 4;
    //let n = 10;
    //let ell = 1000;
    //let c2 = 1.0;

    let p_array = generate_p_array(c, ell, c2);
    let x_matrix = generate_x_matrix(n, ell, &p_array);
    let f_array = generate_f_array(ell);
    let x_bar_matrix =generate_x_bar_matrix(&x_matrix, &f_array, c, c2);
    println!("First 10 values of P:");
    for i in 0..10 {
        println!("p[{}] = {:.6}", i + 1, p_array[i]);
    }

    println!("\nFirst 5 rows of X:");
    for row in x_matrix.iter().take(5) {
        println!("{:?}", &row[..10]); // print first 10 bits
    }

    println!("\nFirst 10 values of F:");
    for i in 0..10 {
        println!("f[{}] = {}", i + 1, f_array[i]);
    }

    println!("\nFirst 5 codewords (rows of bar_X):");
    for i in 0..5 {
        println!("bar_X[{}] = {:?}", i + 1, &x_bar[i][..10]); // first 10 bits
    }
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
            w_clean.push(bit.to_digit(10).unwrap() as u8);
            for j in 0..x_matrix.len() {
                x_clean[j].push(x_matrix[j][i]);
            }
            p_clean.push(p_array[i]);
            f_clean.push(f_array[i]);
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
        scores.push(sum);
    }

    scores
}

/// Step 8: Accuse if score exceeds threshold
fn accuse(
    scores: &[f64],
    c: usize,
    n: usize,
    epsilon: f64,
    c3: f64,
) -> Vec<usize> {
    let threshold = c3 * (c as f64).ln() * (n as f64 / epsilon).ln();
    scores
        .iter()
        .enumerate()
        .filter(|(_, &s)| s > threshold)
        .map(|(j, _)| j)
        .collect()
}
fn tracing_algorithm(
    delta: f64,                // fraction of '?' markings
    epsilon: f64,              // error tolerance
    c3: f64,                   // threshold constant
    c: usize,                  // parameter for code
    n: usize,                  // number of users
    w_star: Vec<char>,         // marked word
    x_matrix: Vec<Vec<u8>>,    // previously generated X matrix
    p_array: Vec<f64>,         // previously computed P
    f_array: Vec<u8>,          // previously generated F
) {
    let padded = pad_w_star(w_star, delta);
    let (mut w_clean, x_clean, p_clean, f_clean) = prune_components(&padded, &x_matrix, &p_array, &f_array);
    flip_marked_bits(&mut w_clean, &f_clean);
    let scores = compute_scores(&w_clean, &x_clean, &p_clean);
    let accused_users = accuse(&scores, c, n, epsilon, c3);

    println!("Accused users: {:?}", accused_users);
}