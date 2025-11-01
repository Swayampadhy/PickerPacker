// ============================================================================
// Features Module - Display configured features
// ============================================================================

use crate::config::PackerConfig;

/// Display all enabled features in the packer configuration
pub fn display_feature_summary(config: &PackerConfig) {
    println!("\n[*] ============================");
    println!("[*] FEATURES ENABLED:");
    println!("[*] ============================");
    
    let mut features = Vec::new();
    
    for utility in &config.utils {
        features.push(utility.display_name());
    }
    
    for check in &config.checks {
        features.push(check.display_name());
    }
    
    for evasion in &config.evasion {
        features.push(evasion.display_name());
    }
    
    features.push(config.execution.display_name());
    features.push(config.injection.display_name());
    
    if let Some(encryption) = config.encrypt {
        features.push(encryption.display_name());
    }
    
    if features.is_empty() {
        println!("[*] No additional features enabled");
    } else {
        for feature in features {
            println!("[+] {}", feature);
        }
    }
    
    println!("[*] ============================\n");
}
