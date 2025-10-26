pub mod injection;
pub mod execution;

#[cfg(feature = "ShellcodeExecuteDefault")]
pub use execution::shellcode_execute_default;

#[cfg(feature = "ShellcodeExecuteFiber")]
pub use execution::shellcode_execute_fiber;
