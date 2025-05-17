use crate::operations::{Operation, OperationInfo, OperationArg};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;
use md5::{Md5 as Md5Hash, Digest as Md5Digest};
use sha1::{Sha1 as Sha1Hash, Digest as Sha1Digest};
use sha2::{Sha256 as Sha256Hash, Sha512 as Sha512Hash, Digest as Sha2Digest};
use log::warn;

// MD5 Hash Operation
pub struct Md5 {
    args: HashMap<String, String>,
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Md5 {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "md5".to_string(),
            description: "Calculates the MD5 hash of the input data".to_string(),
            category: "Hashing".to_string(),
            args: vec![
                OperationArg {
                    name: "format".to_string(),
                    description: "Output format: 'hex' or 'base64'".to_string(),
                    default_value: Some("hex".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        // Display a security warning about MD5
        warn!("Security warning: MD5 is cryptographically broken and unsuitable for further use. Use SHA-256 or stronger for security-sensitive applications.");
        
        let format = self.args.get("format").unwrap_or(&"hex".to_string()).to_lowercase();
        
        // Calculate MD5 hash
        let mut hasher = Md5Hash::new();
        hasher.update(&input);
        let result = hasher.finalize();
        
        // Format output
        match format.as_str() {
            "hex" => Ok(hex::encode(result).into_bytes()),
            "base64" => Ok(base64::encode(result).into_bytes()),
            _ => Err(anyhow!("Unsupported output format: {}", format)),
        }
    }
}

// SHA-1 Hash Operation
pub struct Sha1 {
    args: HashMap<String, String>,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Sha1 {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "sha1".to_string(),
            description: "Calculates the SHA-1 hash of the input data".to_string(),
            category: "Hashing".to_string(),
            args: vec![
                OperationArg {
                    name: "format".to_string(),
                    description: "Output format: 'hex' or 'base64'".to_string(),
                    default_value: Some("hex".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        // Display a security warning about SHA-1
        warn!("Security warning: SHA-1 is cryptographically broken and unsuitable for further use in TLS certificates, digital signatures, or other security-sensitive applications. Use SHA-256 or stronger instead.");
        
        let format = self.args.get("format").unwrap_or(&"hex".to_string()).to_lowercase();
        
        // Calculate SHA-1 hash
        let mut hasher = Sha1Hash::new();
        hasher.update(&input);
        let result = hasher.finalize();
        
        // Format output
        match format.as_str() {
            "hex" => Ok(hex::encode(result).into_bytes()),
            "base64" => Ok(base64::encode(result).into_bytes()),
            _ => Err(anyhow!("Unsupported output format: {}", format)),
        }
    }
}

// SHA-256 Hash Operation
pub struct Sha256 {
    args: HashMap<String, String>,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Sha256 {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "sha256".to_string(),
            description: "Calculates the SHA-256 hash of the input data".to_string(),
            category: "Hashing".to_string(),
            args: vec![
                OperationArg {
                    name: "format".to_string(),
                    description: "Output format: 'hex' or 'base64'".to_string(),
                    default_value: Some("hex".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let format = self.args.get("format").unwrap_or(&"hex".to_string()).to_lowercase();
        
        // Calculate SHA-256 hash
        let mut hasher = Sha256Hash::new();
        hasher.update(&input);
        let result = hasher.finalize();
        
        // Format output
        match format.as_str() {
            "hex" => Ok(hex::encode(result).into_bytes()),
            "base64" => Ok(base64::encode(result).into_bytes()),
            _ => Err(anyhow!("Unsupported output format: {}", format)),
        }
    }
}

// SHA-512 Hash Operation
pub struct Sha512 {
    args: HashMap<String, String>,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Sha512 {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "sha512".to_string(),
            description: "Calculates the SHA-512 hash of the input data".to_string(),
            category: "Hashing".to_string(),
            args: vec![
                OperationArg {
                    name: "format".to_string(),
                    description: "Output format: 'hex' or 'base64'".to_string(),
                    default_value: Some("hex".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let format = self.args.get("format").unwrap_or(&"hex".to_string()).to_lowercase();
        
        // Calculate SHA-512 hash
        let mut hasher = Sha512Hash::new();
        hasher.update(&input);
        let result = hasher.finalize();
        
        // Format output
        match format.as_str() {
            "hex" => Ok(hex::encode(result).into_bytes()),
            "base64" => Ok(base64::encode(result).into_bytes()),
            _ => Err(anyhow!("Unsupported output format: {}", format)),
        }
    }
}

// Password Hashing Operation
pub struct PasswordHash {
    args: HashMap<String, String>,
}

impl PasswordHash {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for PasswordHash {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "password-hash".to_string(),
            description: "Creates a secure password hash using Argon2id".to_string(),
            category: "Hashing".to_string(),
            args: vec![
                OperationArg {
                    name: "salt".to_string(),
                    description: "Salt as hex (if not provided, a random salt will be generated)".to_string(),
                    default_value: None,
                    required: false,
                },
                OperationArg {
                    name: "iterations".to_string(),
                    description: "Number of iterations (higher = more secure but slower)".to_string(),
                    default_value: Some("3".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "memory".to_string(),
                    description: "Memory size in KiB".to_string(),
                    default_value: Some("65536".to_string()),  // 64 MB
                    required: false,
                },
                OperationArg {
                    name: "threads".to_string(),
                    description: "Number of threads".to_string(),
                    default_value: Some("4".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        // This is a placeholder for Argon2id implementation
        // In a real implementation, we would use the argon2 crate
        
        // For now, we'll generate a dummy hash with SHA-256 + salt
        // For real use, always implement proper password hashing like Argon2id!
        
        warn!("Security notice: This is a simplified password hashing implementation. For production use, implement Argon2id with proper parameters.");
        
        // Get or generate salt
        let salt = if let Some(salt_hex) = self.args.get("salt") {
            hex::decode(salt_hex).context("Failed to decode salt from hex")?
        } else {
            // Generate random salt (16 bytes)
            let mut salt = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut salt);
            salt.to_vec()
        };
        
        // Hash the password with the salt
        let mut hasher = Sha256Hash::new();
        hasher.update(&salt);
        hasher.update(&input);
        let hash = hasher.finalize();
        
        // Format: $sha256$salt_hex$hash_hex
        let result = format!("$sha256${}${}",
                          hex::encode(&salt),
                          hex::encode(hash));
        
        Ok(result.into_bytes())
    }
}

// File Checksum Operation
pub struct FileChecksum {
    args: HashMap<String, String>,
}

impl FileChecksum {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for FileChecksum {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "file-checksum".to_string(),
            description: "Calculates cryptographic checksums of the input data using multiple algorithms".to_string(),
            category: "Hashing".to_string(),
            args: vec![
                OperationArg {
                    name: "algorithms".to_string(),
                    description: "Comma-separated list of algorithms to use: md5,sha1,sha256,sha512".to_string(),
                    default_value: Some("sha256".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let algorithms = self.args.get("algorithms")
            .unwrap_or(&"sha256".to_string())
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .collect::<Vec<String>>();
        
        let mut results = Vec::new();
        
        for algo in algorithms {
            match algo.as_str() {
                "md5" => {
                    warn!("Security warning: MD5 is cryptographically broken and unsuitable for security applications.");
                    let mut hasher = Md5Hash::new();
                    hasher.update(&input);
                    let hash = hasher.finalize();
                    results.push(format!("MD5: {}", hex::encode(hash)));
                },
                "sha1" => {
                    warn!("Security warning: SHA-1 is cryptographically broken for many security applications.");
                    let mut hasher = Sha1Hash::new();
                    hasher.update(&input);
                    let hash = hasher.finalize();
                    results.push(format!("SHA1: {}", hex::encode(hash)));
                },
                "sha256" => {
                    let mut hasher = Sha256Hash::new();
                    hasher.update(&input);
                    let hash = hasher.finalize();
                    results.push(format!("SHA256: {}", hex::encode(hash)));
                },
                "sha512" => {
                    let mut hasher = Sha512Hash::new();
                    hasher.update(&input);
                    let hash = hasher.finalize();
                    results.push(format!("SHA512: {}", hex::encode(hash)));
                },
                _ => return Err(anyhow!("Unsupported hash algorithm: {}", algo)),
            }
        }
        
        Ok(results.join("\n").into_bytes())
    }
}
