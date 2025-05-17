use crate::operations::{Operation, OperationInfo, OperationArg};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;
use std::io::{Read, Write};
use flate2::Compression;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression as BzCompression;

// GZip Compress Operation
pub struct GzipCompress {
    args: HashMap<String, String>,
}

impl GzipCompress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for GzipCompress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "gzip-compress".to_string(),
            description: "Compresses data using GZIP".to_string(),
            category: "Compression".to_string(),
            args: vec![
                OperationArg {
                    name: "level".to_string(),
                    description: "Compression level (0-9, 0=none, 9=best)".to_string(),
                    default_value: Some("6".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let level_str = self.args.get("level").unwrap_or(&"6".to_string());
        let level = level_str.parse::<u32>()
            .map_err(|_| anyhow!("Invalid compression level: {}", level_str))?;
        
        if level > 9 {
            return Err(anyhow!("Compression level must be between 0 and 9"));
        }
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(&input)
            .context("Failed to compress data with GZIP")?;
        
        encoder.finish().context("Failed to finish GZIP compression")
    }
}

// GZip Decompress Operation
pub struct GzipDecompress {
    args: HashMap<String, String>,
}

impl GzipDecompress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for GzipDecompress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "gzip-decompress".to_string(),
            description: "Decompresses GZIP data".to_string(),
            category: "Compression".to_string(),
            args: vec![],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(&input[..]);
        let mut result = Vec::new();
        
        decoder.read_to_end(&mut result)
            .context("Failed to decompress GZIP data")?;
        
        Ok(result)
    }
}

// Zlib Compress Operation
pub struct ZlibCompress {
    args: HashMap<String, String>,
}

impl ZlibCompress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for ZlibCompress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "zlib-compress".to_string(),
            description: "Compresses data using Zlib".to_string(),
            category: "Compression".to_string(),
            args: vec![
                OperationArg {
                    name: "level".to_string(),
                    description: "Compression level (0-9, 0=none, 9=best)".to_string(),
                    default_value: Some("6".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let level_str = self.args.get("level").unwrap_or(&"6".to_string());
        let level = level_str.parse::<u32>()
            .map_err(|_| anyhow!("Invalid compression level: {}", level_str))?;
        
        if level > 9 {
            return Err(anyhow!("Compression level must be between 0 and 9"));
        }
        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(&input)
            .context("Failed to compress data with Zlib")?;
        
        encoder.finish().context("Failed to finish Zlib compression")
    }
}

// Zlib Decompress Operation
pub struct ZlibDecompress {
    args: HashMap<String, String>,
}

impl ZlibDecompress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for ZlibDecompress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "zlib-decompress".to_string(),
            description: "Decompresses Zlib data".to_string(),
            category: "Compression".to_string(),
            args: vec![],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(&input[..]);
        let mut result = Vec::new();
        
        decoder.read_to_end(&mut result)
            .context("Failed to decompress Zlib data")?;
        
        Ok(result)
    }
}

// BZip2 Compress Operation
pub struct Bzip2Compress {
    args: HashMap<String, String>,
}

impl Bzip2Compress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Bzip2Compress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "bzip2-compress".to_string(),
            description: "Compresses data using BZip2".to_string(),
            category: "Compression".to_string(),
            args: vec![
                OperationArg {
                    name: "level".to_string(),
                    description: "Compression level (1-9, 1=fastest, 9=best)".to_string(),
                    default_value: Some("6".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let level_str = self.args.get("level").unwrap_or(&"6".to_string());
        let level = level_str.parse::<u32>()
            .map_err(|_| anyhow!("Invalid compression level: {}", level_str))?;
        
        if level < 1 || level > 9 {
            return Err(anyhow!("Compression level must be between 1 and 9"));
        }
        
        let mut encoder = BzEncoder::new(Vec::new(), BzCompression::new(level));
        encoder.write_all(&input)
            .context("Failed to compress data with BZip2")?;
        
        encoder.finish().context("Failed to finish BZip2 compression")
    }
}

// BZip2 Decompress Operation
pub struct Bzip2Decompress {
    args: HashMap<String, String>,
}

impl Bzip2Decompress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Bzip2Decompress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "bzip2-decompress".to_string(),
            description: "Decompresses BZip2 data".to_string(),
            category: "Compression".to_string(),
            args: vec![],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let mut decoder = BzDecoder::new(&input[..]);
        let mut result = Vec::new();
        
        decoder.read_to_end(&mut result)
            .context("Failed to decompress BZip2 data")?;
        
        Ok(result)
    }
}

// Auto Decompress Operation
pub struct AutoDecompress {
    args: HashMap<String, String>,
}

impl AutoDecompress {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
    
    fn is_gzip(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B
    }
    
    fn is_zlib(data: &[u8]) -> bool {
        data.len() >= 2 && (data[0] & 0x0F) == 0x08 && (data[0] & 0xF0) <= 0x70 && 
            (data[0] * 256 + data[1]) % 31 == 0
    }
    
    fn is_bzip2(data: &[u8]) -> bool {
        data.len() >= 3 && data[0] == 0x42 && data[1] == 0x5A && data[2] == 0x68
    }
}

impl Operation for AutoDecompress {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "auto-decompress".to_string(),
            description: "Automatically detects and decompresses data".to_string(),
            category: "Compression".to_string(),
            args: vec![
                OperationArg {
                    name: "attempt_all".to_string(),
                    description: "Attempt all decompression methods even if format detection fails".to_string(),
                    default_value: Some("false".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let attempt_all = self.args.get("attempt_all").unwrap_or(&"false".to_string()) == "true";
        
        // Try to detect the compression format
        if Self::is_gzip(&input) || (attempt_all && input.len() >= 2) {
            // Try GZIP
            if let Ok(result) = GzipDecompress::new().run(input.clone()) {
                return Ok(result);
            }
        }
        
        if Self::is_zlib(&input) || (attempt_all && input.len() >= 2) {
            // Try Zlib
            if let Ok(result) = ZlibDecompress::new().run(input.clone()) {
                return Ok(result);
            }
        }
        
        if Self::is_bzip2(&input) || (attempt_all && input.len() >= 3) {
            // Try BZip2
            if let Ok(result) = Bzip2Decompress::new().run(input.clone()) {
                return Ok(result);
            }
        }
        
        // If we get here, either no compression was detected or decompression failed
        Err(anyhow!("Unable to decompress data: no recognized compression format detected or decompression failed"))
    }
}
