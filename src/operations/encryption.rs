use crate::operations::{Operation, OperationInfo, OperationArg};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;
use aes::{Aes128, Aes192, Aes256};
use block_modes::{BlockMode, Cbc, Ecb};
use block_modes::block_padding::{Pkcs7, NoPadding};
use rand::{Rng, thread_rng};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac, NewMac};
use log::warn;

// Type aliases for AES modes
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes192Cbc = Cbc<Aes192, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type Aes128Ecb = Ecb<Aes128, Pkcs7>;
type Aes192Ecb = Ecb<Aes192, Pkcs7>;
type Aes256Ecb = Ecb<Aes256, Pkcs7>;

// AES Encrypt Operation
pub struct AesEncrypt {
    args: HashMap<String, String>,
}

impl AesEncrypt {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }

    // Derive key from password using PBKDF2
    fn derive_key(password: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
        let mut key = vec![0u8; key_size];
        
        // In a real implementation, we would use PBKDF2 with a high iteration count
        // This is a simplified version for demonstration
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        let result = hasher.finalize();
        
        // Ensure the key is the right size
        key[..key_size.min(result.len())].copy_from_slice(&result[..key_size.min(result.len())]);
        
        key
    }
    
    // Generate random IV
    fn generate_iv(size: usize) -> Vec<u8> {
        let mut iv = vec![0u8; size];
        thread_rng().fill(&mut iv[..]);
        iv
    }
}

impl Operation for AesEncrypt {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "aes-encrypt".to_string(),
            description: "Encrypts data with AES".to_string(),
            category: "Encryption".to_string(),
            args: vec![
                OperationArg {
                    name: "key".to_string(),
                    description: "The encryption key as hex".to_string(),
                    default_value: None,
                    required: false,
                },
                OperationArg {
                    name: "password".to_string(),
                    description: "Password to derive key from".to_string(),
                    default_value: None,
                    required: false,
                },
                OperationArg {
                    name: "mode".to_string(),
                    description: "Block mode: CBC or ECB".to_string(),
                    default_value: Some("CBC".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "key_size".to_string(),
                    description: "Key size in bits: 128, 192, or 256".to_string(),
                    default_value: Some("256".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "iv".to_string(),
                    description: "Initialization vector as hex (if not provided, random IV will be used)".to_string(),
                    default_value: None,
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        // Get key or password (at least one is required)
        let key_hex = self.args.get("key");
        let password = self.args.get("password");
        
        if key_hex.is_none() && password.is_none() {
            return Err(anyhow!("Either 'key' or 'password' must be provided"));
        }
        
        // Get mode and key size
        let mode = self.args.get("mode").unwrap_or(&"CBC".to_string()).to_uppercase();
        let key_size = self.args.get("key_size").unwrap_or(&"256".to_string()).parse::<usize>()
            .map_err(|_| anyhow!("Invalid key size"))?;
        
        // Validate key size
        if key_size != 128 && key_size != 192 && key_size != 256 {
            return Err(anyhow!("Key size must be 128, 192, or 256 bits"));
        }
        
        let key_bytes = key_size / 8;
        
        // Get or derive the key
        let key = if let Some(key_hex) = key_hex {
            let decoded = hex::decode(key_hex)
                .context("Failed to decode key from hex")?;
            
            if decoded.len() != key_bytes {
                return Err(anyhow!("Key length mismatch: expected {} bytes, got {}", 
                                 key_bytes, decoded.len()));
            }
            
            decoded
        } else if let Some(password) = password {
            // Generate salt or use provided salt
            // For simplicity, we're using a fixed salt here
            // In a real implementation, this should be random and stored with the ciphertext
            let salt = b"cyberchefsalt";
            
            Self::derive_key(password.as_bytes(), salt, key_bytes)
        } else {
            return Err(anyhow!("Either 'key' or 'password' must be provided"));
        };
        
        // Get or generate IV (for CBC mode)
        let iv = if mode == "CBC" {
            if let Some(iv_hex) = self.args.get("iv") {
                hex::decode(iv_hex).context("Failed to decode IV from hex")?
            } else {
                // Generate random IV
                Self::generate_iv(16)
            }
        } else {
            Vec::new() // Not used in ECB mode
        };
        
        // Warn if ECB mode is used
        if mode == "ECB" {
            warn!("ECB mode is not recommended for secure encryption as it does not hide data patterns");
        }
        
        // Encrypt the data
        let encrypted = match (mode.as_str(), key_bytes) {
            ("CBC", 16) => {
                let cipher = Aes128Cbc::new_from_slices(&key, &iv)
                    .context("Failed to initialize AES-128-CBC cipher")?;
                cipher.encrypt_vec(&input)
            },
            ("CBC", 24) => {
                let cipher = Aes192Cbc::new_from_slices(&key, &iv)
                    .context("Failed to initialize AES-192-CBC cipher")?;
                cipher.encrypt_vec(&input)
            },
            ("CBC", 32) => {
                let cipher = Aes256Cbc::new_from_slices(&key, &iv)
                    .context("Failed to initialize AES-256-CBC cipher")?;
                cipher.encrypt_vec(&input)
            },
            ("ECB", 16) => {
                let cipher = Aes128Ecb::new_from_slices(&key, &[])
                    .context("Failed to initialize AES-128-ECB cipher")?;
                cipher.encrypt_vec(&input)
            },
            ("ECB", 24) => {
                let cipher = Aes192Ecb::new_from_slices(&key, &[])
                    .context("Failed to initialize AES-192-ECB cipher")?;
                cipher.encrypt_vec(&input)
            },
            ("ECB", 32) => {
                let cipher = Aes256Ecb::new_from_slices(&key, &[])
                    .context("Failed to initialize AES-256-ECB cipher")?;
                cipher.encrypt_vec(&input)
            },
            _ => return Err(anyhow!("Unsupported mode or key size")),
        };
        
        // For CBC mode, prepend the IV to the encrypted data
        if mode == "CBC" {
            let mut result = Vec::with_capacity(iv.len() + encrypted.len());
            result.extend_from_slice(&iv);
            result.extend_from_slice(&encrypted);
            Ok(result)
        } else {
            Ok(encrypted)
        }
    }
}

// AES Decrypt Operation
pub struct AesDecrypt {
    args: HashMap<String, String>,
}

impl AesDecrypt {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
    
    // Derive key from password (same as in AesEncrypt)
    fn derive_key(password: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
        AesEncrypt::derive_key(password, salt, key_size)
    }
}

impl Operation for AesDecrypt {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "aes-decrypt".to_string(),
            description: "Decrypts AES encrypted data".to_string(),
            category: "Encryption".to_string(),
            args: vec![
                OperationArg {
                    name: "key".to_string(),
                    description: "The encryption key as hex".to_string(),
                    default_value: None,
                    required: false,
                },
                OperationArg {
                    name: "password".to_string(),
                    description: "Password to derive key from".to_string(),
                    default_value: None,
                    required: false,
                },
                OperationArg {
                    name: "mode".to_string(),
                    description: "Block mode: CBC or ECB".to_string(),
                    default_value: Some("CBC".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "key_size".to_string(),
                    description: "Key size in bits: 128, 192, or 256".to_string(),
                    default_value: Some("256".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "iv".to_string(),
                    description: "Initialization vector as hex (for CBC mode, if not provided, first block of input is used)".to_string(),
                    default_value: None,
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        // Get key or password (at least one is required)
        let key_hex = self.args.get("key");
        let password = self.args.get("password");
        
        if key_hex.is_none() && password.is_none() {
            return Err(anyhow!("Either 'key' or 'password' must be provided"));
        }
        
        // Get mode and key size
        let mode = self.args.get("mode").unwrap_or(&"CBC".to_string()).to_uppercase();
        let key_size = self.args.get("key_size").unwrap_or(&"256".to_string()).parse::<usize>()
            .map_err(|_| anyhow!("Invalid key size"))?;
        
        // Validate key size
        if key_size != 128 && key_size != 192 && key_size != 256 {
            return Err(anyhow!("Key size must be 128, 192, or 256 bits"));
        }
        
        let key_bytes = key_size / 8;
        
        // Get or derive the key
        let key = if let Some(key_hex) = key_hex {
            let decoded = hex::decode(key_hex)
                .context("Failed to decode key from hex")?;
            
            if decoded.len() != key_bytes {
                return Err(anyhow!("Key length mismatch: expected {} bytes, got {}", 
                                 key_bytes, decoded.len()));
            }
            
            decoded
        } else if let Some(password) = password {
            // Generate salt or use provided salt
            // For simplicity, we're using a fixed salt here
            // In a real implementation, this should be stored with the ciphertext
            let salt = b"cyberchefsalt";
            
            Self::derive_key(password.as_bytes(), salt, key_bytes)
        } else {
            return Err(anyhow!("Either 'key' or 'password' must be provided"));
        };
        
        // For CBC mode, get IV from input or argument
        let (iv, ciphertext) = if mode == "CBC" {
            if let Some(iv_hex) = self.args.get("iv") {
                // Get IV from argument
                let decoded_iv = hex::decode(iv_hex)
                    .context("Failed to decode IV from hex")?;
                
                if decoded_iv.len() != 16 {
                    return Err(anyhow!("IV must be 16 bytes (32 hex characters)"));
                }
                
                (decoded_iv, input)
            } else {
                // Get IV from first block of input
                if input.len() < 16 {
                    return Err(anyhow!("Input too short to contain IV (min 16 bytes)"));
                }
                
                let iv = input[..16].to_vec();
                let ciphertext = input[16..].to_vec();
                
                (iv, ciphertext)
            }
        } else {
            (Vec::new(), input) // No IV for ECB mode
        };
        
        // Warn if ECB mode is used
        if mode == "ECB" {
            warn!("ECB mode is not recommended for secure encryption as it does not hide data patterns");
        }
        
        // Decrypt the data
        let decrypted = match (mode.as_str(), key_bytes) {
            ("CBC", 16) => {
                let cipher = Aes128Cbc::new_from_slices(&key, &iv)
                    .context("Failed to initialize AES-128-CBC cipher")?;
                cipher.decrypt_vec(&ciphertext)
                    .context("Failed to decrypt data (AES-128-CBC)")?
            },
            ("CBC", 24) => {
                let cipher = Aes192Cbc::new_from_slices(&key, &iv)
                    .context("Failed to initialize AES-192-CBC cipher")?;
                cipher.decrypt_vec(&ciphertext)
                    .context("Failed to decrypt data (AES-192-CBC)")?
            },
            ("CBC", 32) => {
                let cipher = Aes256Cbc::new_from_slices(&key, &iv)
                    .context("Failed to initialize AES-256-CBC cipher")?;
                cipher.decrypt_vec(&ciphertext)
                    .context("Failed to decrypt data (AES-256-CBC)")?
            },
            ("ECB", 16) => {
                let cipher = Aes128Ecb::new_from_slices(&key, &[])
                    .context("Failed to initialize AES-128-ECB cipher")?;
                cipher.decrypt_vec(&ciphertext)
                    .context("Failed to decrypt data (AES-128-ECB)")?
            },
            ("ECB", 24) => {
                let cipher = Aes192Ecb::new_from_slices(&key, &[])
                    .context("Failed to initialize AES-192-ECB cipher")?;
                cipher.decrypt_vec(&ciphertext)
                    .context("Failed to decrypt data (AES-192-ECB)")?
            },
            ("ECB", 32) => {
                let cipher = Aes256Ecb::new_from_slices(&key, &[])
                    .context("Failed to initialize AES-256-ECB cipher")?;
                cipher.decrypt_vec(&ciphertext)
                    .context("Failed to decrypt data (AES-256-ECB)")?
            },
            _ => return Err(anyhow!("Unsupported mode or key size")),
        };
        
        Ok(decrypted)
    }
}

// HMAC Operation
pub struct HmacOperation {
    args: HashMap<String, String>,
}

impl HmacOperation {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for HmacOperation {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "hmac".to_string(),
            description: "Generates HMAC authentication code".to_string(),
            category: "Encryption".to_string(),
            args: vec![
                OperationArg {
                    name: "key".to_string(),
                    description: "The HMAC key (hex or raw string)".to_string(),
                    default_value: None,
                    required: true,
                },
                OperationArg {
                    name: "key_format".to_string(),
                    description: "Format of the key: 'hex' or 'raw'".to_string(),
                    default_value: Some("raw".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "hash".to_string(),
                    description: "Hash algorithm: 'sha256', 'sha512'".to_string(),
                    default_value: Some("sha256".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "output".to_string(),
                    description: "Output format: 'hex' or 'base64'".to_string(),
                    default_value: Some("hex".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        // Get required parameters
        let key = self.args.get("key")
            .ok_or_else(|| anyhow!("Key is required"))?;
        
        let key_format = self.args.get("key_format").unwrap_or(&"raw".to_string()).to_lowercase();
        let hash_alg = self.args.get("hash").unwrap_or(&"sha256".to_string()).to_lowercase();
        let output_format = self.args.get("output").unwrap_or(&"hex".to_string()).to_lowercase();
        
        // Parse key based on format
        let key_bytes = match key_format.as_str() {
            "hex" => hex::decode(key).context("Failed to decode key from hex")?,
            "raw" => key.as_bytes().to_vec(),
            _ => return Err(anyhow!("Unsupported key format: {}", key_format)),
        };
        
        // Compute HMAC based on hash algorithm
        let hmac_result = match hash_alg.as_str() {
            "sha256" => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
                    .map_err(|_| anyhow!("Failed to initialize HMAC-SHA256"))?;
                mac.update(&input);
                mac.finalize().into_bytes().to_vec()
            },
            // Add other hash algorithms as needed
            _ => return Err(anyhow!("Unsupported hash algorithm: {}", hash_alg)),
        };
        
        // Format output
        match output_format.as_str() {
            "hex" => Ok(hex::encode(hmac_result).into_bytes()),
            "base64" => Ok(base64::encode(hmac_result).into_bytes()),
            _ => Err(anyhow!("Unsupported output format: {}", output_format)),
        }
    }
}
