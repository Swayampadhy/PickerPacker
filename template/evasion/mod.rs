// =======================================================================================================
// EVASION MODULE - Exports evasion techniques
// =======================================================================================================

#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionAMSIHwbp"))]
pub mod amsi;

#[cfg(any(feature = "EvasionETWSimple", feature = "EvasionETWWinAPI", feature = "EvasionETWpEventWrite"))]
pub mod etw;

#[cfg(any(feature = "EvasionSelfDeletion", feature = "EvasionNtdllUnhooking"))]
pub mod misc;
