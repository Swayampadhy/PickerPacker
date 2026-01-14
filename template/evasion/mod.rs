// =======================================================================================================
// EVASION MODULE - Exports evasion techniques
// =======================================================================================================

#[cfg(any(feature = "EvasionAMSISimplePatch", feature = "EvasionAMSIHwbp", feature = "EvasionAMSIPageGuard"))]
pub mod amsi;

#[cfg(any(feature = "EvasionETWSimple", feature = "EvasionETWWinAPI", feature = "EvasionETWpEventWrite", feature = "EvasionETWpEventWrite2"))]
pub mod etw;

#[cfg(any(feature = "EvasionSelfDeletion", feature = "EvasionNtdllUnhooking"))]
pub mod misc;
