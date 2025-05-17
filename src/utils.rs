use anyhow::Result;
use std::path::Path;
use zeroize::Zeroize;

/// Securely overwrite and delete a file
pub fn secure_delete_file(path: &Path) -> Result<()> {
    if path.exists() {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)?;
            
        // Get file size
        let metadata = file.metadata()?;
        let size = metadata.len();
        
        // Overwrite with random data
        let mut buffer = vec![0u8; size as usize];
        rand::thread_rng().fill_bytes(&mut buffer);
        file.write_all(&buffer)?;
        buffer.zeroize();
        
        // Overwrite with zeros
        file.set_len(0)?;
        file.write_all(&vec![0u8; size as usize])?;
        
        // Delete the file
        std::fs::remove_file(path)?;
    }
    
    Ok(())
}

/// Create a temporary file with secure permissions
pub fn create_secure_temp_file() -> Result<tempfile::NamedTempFile> {
    let temp_file = tempfile::NamedTempFile::new()?;
    
    // Set secure permissions (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_file.path(), std::fs::Permissions::from_mode(0o600))?;
    }
    
    Ok(temp_file)
}

/// Validate that a path is within a base directory (prevents path traversal)
pub fn validate_path(base: &Path, path: &Path) -> Result<()> {
    let canonical_base = base.canonicalize()?;
    let canonical_path = path.canonicalize()?;
    
    if !canonical_path.starts_with(&canonical_base) {
        anyhow::bail!("Path traversal attempt detected");
    }
    
    Ok(())
}

/// Constant-time comparison of byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
} 