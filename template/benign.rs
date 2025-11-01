// =======================================================================================================
// BENIGN FUNCTIONS - Legitimate-looking code
// Include your custom benign code here
// =======================================================================================================

use std::thread;
use std::time::Duration;
use std::fs::{remove_file, File};
use std::io::{self, Read, Write};
use rand::{thread_rng, Rng};

// =======================================================================
/// Wrapper function that runs all benign code recursively in background thread
// Include all of your function calls here
// =======================================================================

fn benign_wrapper_internal() {
    calculate();
    calc_primes(3000);
    api_hammering(2000).expect("Error during API hammering");
    // Add more benign functions here as needed
    //

}

/// The thread will continue running until the main thread exits
pub fn start_benign_thread() {
    thread::spawn(move || {
        loop {
            benign_wrapper_internal();
            // Small delay to prevent excessive CPU usage
            thread::sleep(Duration::from_millis(100));
        }
    });
}

// =======================================================================
// Add your custom benign function code here
// =======================================================================

fn calculate() {
    let mut result = 0;
    for i in 0..10000 {
        result += i;
    }
    println!("Result: {}", result);
}

fn calc_primes(iterations: usize) {
    let mut prime = 2;
    let mut i = 0;
    while i < iterations {
        if (2..prime).all(|j| prime % j != 0) {
            i += 1;
        }
        prime += 1;
    }
}

fn api_hammering(num: usize) -> io::Result<()> {
    let dir = std::env::temp_dir();
    let path = dir.as_path().join("file.tmp");
    let size = 0xFFFFF;

    for _ in 0..num {
        // Creates the file and writes random data
        let mut file = File::create(&path)?;
        let mut rng = thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.r#gen()).collect();
        file.write_all(&data)?;

        // Read written data
        let mut file = File::open(&path)?;
        let mut buffer = vec![0; size];
        file.read_exact(&mut buffer)?;
    }

    remove_file(path)?;

    Ok(())
}