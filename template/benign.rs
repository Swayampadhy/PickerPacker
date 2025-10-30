// =======================================================================================================
// BENIGN FUNCTIONS - Legitimate-looking code
// Include your custom benign code here
// =======================================================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

// =======================================================================
/// Wrapper function that runs all benign code recursively in background thread
// Include all of your function calls here
// =======================================================================

fn benign_wrapper_internal() {
    calculate();
    // Add more benign functions here as needed


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