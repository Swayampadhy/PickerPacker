// =======================================================================================================
// EVASION MODULE - Exports evasion techniques
// =======================================================================================================

#[cfg(feature = "EvasionAMSISimplePatch")]
pub mod amsi;

#[cfg(feature = "EvasionETWSimple")]
pub mod etw;
