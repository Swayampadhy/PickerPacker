// =======================================================================================================
// EVASION MODULE - Exports evasion techniques
// =======================================================================================================

#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionNtdllUnhooking"))]
pub mod amsi;

#[cfg(feature = "EvasionETWSimple")]
pub mod etw;
