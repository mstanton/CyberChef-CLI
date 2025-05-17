pub mod encoding;
pub mod encryption;
pub mod hashing;
pub mod compression;
pub mod analysis;

use std::collections::HashMap;
use anyhow::{Result, anyhow};
use std::fmt;

#[derive(Debug, Clone)]
pub struct OperationArg {
    pub name: String,
    pub description: String,
    pub default_value: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone)]
pub struct OperationInfo {
    pub name: String,
    pub description: String,
    pub category: String,
    pub args: Vec<OperationArg>,
}

pub trait Operation {
    fn info(&self) -> OperationInfo;
    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>>;
}

// Registry for all available operations
struct OperationRegistry {
    operations: HashMap<String, Box<dyn Operation>>,
}

// Singleton instance for the operation registry
static mut REGISTRY: Option<OperationRegistry> = None;

// Initialize the registry with all available operations
pub fn init_registry() -> &'static OperationRegistry {
    unsafe {
        if REGISTRY.is_none() {
            let mut ops = HashMap::new();
            
            // Register encoding operations
            ops.insert("base64-encode".to_string(), Box::new(encoding::Base64Encode::new()) as Box<dyn Operation>);
            ops.insert("base64-decode".to_string(), Box::new(encoding::Base64Decode::new()) as Box<dyn Operation>);
            ops.insert("hex-encode".to_string(), Box::new(encoding::HexEncode::new()) as Box<dyn Operation>);
            ops.insert("hex-decode".to_string(), Box::new(encoding::HexDecode::new()) as Box<dyn Operation>);
            ops.insert("url-encode".to_string(), Box::new(encoding::UrlEncode::new()) as Box<dyn Operation>);
            ops.insert("url-decode".to_string(), Box::new(encoding::UrlDecode::new()) as Box<dyn Operation>);
            
            // Register encryption operations
            ops.insert("aes-encrypt".to_string(), Box::new(encryption::AesEncrypt::new()) as Box<dyn Operation>);
            ops.insert("aes-decrypt".to_string(), Box::new(encryption::AesDecrypt::new()) as Box<dyn Operation>);
            
            // Register hashing operations
            ops.insert("md5".to_string(), Box::new(hashing::Md5::new()) as Box<dyn Operation>);
            ops.insert("sha1".to_string(), Box::new(hashing::Sha1::new()) as Box<dyn Operation>);
            ops.insert("sha256".to_string(), Box::new(hashing::Sha256::new()) as Box<dyn Operation>);
            
            // Register compression operations
            ops.insert("gzip-compress".to_string(), Box::new(compression::GzipCompress::new()) as Box<dyn Operation>);
            ops.insert("gzip-decompress".to_string(), Box::new(compression::GzipDecompress::new()) as Box<dyn Operation>);
            
            // Register analysis operations
            ops.insert("entropy".to_string(), Box::new(analysis::Entropy::new()) as Box<dyn Operation>);
            
            REGISTRY = Some(OperationRegistry { operations: ops });
        }
        
        REGISTRY.as_ref().unwrap()
    }
}

// Get an operation by name
pub fn get_operation(name: &str, args: &[String]) -> Result<Box<dyn Operation>> {
    let registry = init_registry();
    
    let op = registry.operations.get(name)
        .ok_or_else(|| anyhow!("Operation '{}' not found", name))?
        .clone();
    
    // Parse operation arguments
    // TODO: Implement argument parsing
    
    Ok(op)
}

// List all operations, optionally filtered by category
pub fn list_operations(category: Option<&str>) -> Result<()> {
    let registry = init_registry();
    
    let mut categories = HashMap::new();
    
    // Group operations by category
    for op in registry.operations.values() {
        let info = op.info();
        categories.entry(info.category.clone())
            .or_insert_with(Vec::new)
            .push(info);
    }
    
    // Print operations by category
    for (cat, ops) in categories {
        if category.is_none() || category.unwrap() == cat {
            println!("Category: {}", cat);
            for op in ops {
                println!("  {} - {}", op.name, op.description);
            }
            println!();
        }
    }
    
    Ok(())
}

// Helper function to parse operation arguments from key=value pairs
pub fn parse_args(args: &[String]) -> HashMap<String, String> {
    let mut result = HashMap::new();
    
    for arg in args {
        if let Some(pos) = arg.find('=') {
            let (key, value) = arg.split_at(pos);
            result.insert(key.to_string(), value[1..].to_string());
        }
    }
    
    result
}
