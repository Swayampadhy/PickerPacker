// =======================================================================================================
// EVASION MODULE - Exports evasion techniques
// =======================================================================================================

#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionNtdllUnhooking", feature = "EvasionAMSIHwbp"))]
pub mod amsi;

#[cfg(feature = "EvasionETWSimple")]
pub mod etw;
