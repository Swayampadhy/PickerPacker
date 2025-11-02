// =======================================================================================================
// MISCELLANEOUS CHECKS
// Other environment checks (domain join, sandbox, etc.)
// =======================================================================================================

#[cfg(feature = "CheckDomainJoined")]
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetGetJoinInformation,
    NetApiBufferFree,
    NETSETUP_JOIN_STATUS,
};

// =======================================================================================================
// DOMAIN JOIN CHECK
// =======================================================================================================

/// Check if the machine is joined to a domain
#[cfg(feature = "CheckDomainJoined")]
pub fn is_domain_joined() -> bool {
    const NetSetupUnknownStatus: NETSETUP_JOIN_STATUS = 0;
    const NetSetupDomainName: NETSETUP_JOIN_STATUS = 3;
    
    let mut join_status = NetSetupUnknownStatus;
    let mut name_buffer = std::ptr::null_mut::<u16>();

    // Check the domain join information
    if unsafe {
        NetGetJoinInformation(
            std::ptr::null(),
            &mut name_buffer,
            &mut join_status
        )
    } != 0 {
        return false;
    }

    // Free the buffer that `NetGetJoinInformation` allocated
    unsafe { NetApiBufferFree(name_buffer as *const _) };

    // Return true if the machine is joined to a domain
    join_status == NetSetupDomainName
}
