use crate::operations::{Operation, OperationInfo, OperationArg};
use anyhow::{Result, anyhow, Context};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use regex::Regex;
use std::str::FromStr;
use std::fmt::Write;

// Entropy Calculation Operation
pub struct Entropy {
    args: HashMap<String, String>,
}

impl Entropy {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
    
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        // Count occurrences of each byte
        let mut counts = [0; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        // Calculate entropy
        let data_len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let probability = count as f64 / data_len;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
}

impl Operation for Entropy {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "entropy".to_string(),
            description: "Calculates the Shannon entropy of the input data".to_string(),
            category: "Analysis".to_string(),
            args: vec![
                OperationArg {
                    name: "base".to_string(),
                    description: "Entropy base: 2, e, or 10".to_string(),
                    default_value: Some("2".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "bytes".to_string(),
                    description: "Show entropy for each byte range".to_string(),
                    default_value: Some("false".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let base = self.args.get("base").unwrap_or(&"2".to_string());
        let show_bytes = self.args.get("bytes").unwrap_or(&"false".to_string()) == "true";
        
        let entropy = Self::calculate_entropy(&input);
        
        let adjusted_entropy = match base.as_str() {
            "2" => entropy,
            "e" => entropy * 2.0_f64.log2() / std::f64::consts::E.log2(),
            "10" => entropy * 2.0_f64.log2() / 10.0_f64.log2(),
            _ => return Err(anyhow!("Invalid entropy base: {}", base)),
        };
        
        let mut result = format!("Entropy (base {}): {:.6}", base, adjusted_entropy);
        
        if show_bytes {
            result.push_str("\n\nEntropy by byte ranges:\n");
            
            // Analyze entropy in chunks of 256 bytes
            let chunk_size = 256;
            for (i, chunk) in input.chunks(chunk_size).enumerate() {
                let chunk_entropy = Self::calculate_entropy(chunk);
                let adjusted_chunk_entropy = match base.as_str() {
                    "2" => chunk_entropy,
                    "e" => chunk_entropy * 2.0_f64.log2() / std::f64::consts::E.log2(),
                    "10" => chunk_entropy * 2.0_f64.log2() / 10.0_f64.log2(),
                    _ => unreachable!(),
                };
                
                let _ = writeln!(result, "Bytes {}-{}: {:.6}", 
                               i * chunk_size, 
                               i * chunk_size + chunk.len() - 1,
                               adjusted_chunk_entropy);
            }
        }
        
        Ok(result.into_bytes())
    }
}

// File Type Detection Operation
pub struct FileType {
    args: HashMap<String, String>,
}

impl FileType {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
    
    fn detect_file_type(data: &[u8]) -> Vec<String> {
        let mut types = Vec::new();
        
        if data.len() < 4 {
            return vec!["Unknown (file too small)".to_string()];
        }
        
        // Check for common file signatures (magic numbers)
        if data.starts_with(b"\x89PNG\r\n\x1A\n") {
            types.push("PNG image".to_string());
        }
        else if data.starts_with(b"\xFF\xD8\xFF") {
            types.push("JPEG image".to_string());
        }
        else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
            types.push("GIF image".to_string());
        }
        else if data.starts_with(b"BM") {
            types.push("BMP image".to_string());
        }
        else if data.starts_with(b"%PDF") {
            types.push("PDF document".to_string());
        }
        else if data.starts_with(b"PK\x03\x04") {
            // ZIP, JAR, APK, DOCX, XLSX, PPTX, etc.
            types.push("ZIP archive or Office Open XML document".to_string());
            
            // Check for specific Office formats based on internal files
            // This is a simplified version; a real implementation would parse the ZIP
            if String::from_utf8_lossy(data).contains("[Content_Types].xml") {
                if String::from_utf8_lossy(data).contains("word/") {
                    types.push("Microsoft Word document (.docx)".to_string());
                }
                if String::from_utf8_lossy(data).contains("xl/") {
                    types.push("Microsoft Excel spreadsheet (.xlsx)".to_string());
                }
                if String::from_utf8_lossy(data).contains("ppt/") {
                    types.push("Microsoft PowerPoint presentation (.pptx)".to_string());
                }
            }
        }
        else if data.starts_with(b"\x1F\x8B\x08") {
            types.push("GZIP compressed data".to_string());
        }
        else if data.starts_with(b"BZh") {
            types.push("BZIP2 compressed data".to_string());
        }
        else if data.starts_with(b"\xFD\x37\x7A\x58\x5A\x00") {
            types.push("XZ compressed data".to_string());
        }
        else if data.starts_with(b"\x7FELF") {
            types.push("ELF executable".to_string());
        }
        else if data.starts_with(b"MZ") {
            types.push("DOS/Windows executable (.exe)".to_string());
        }
        else if data.starts_with(b"\xCA\xFE\xBA\xBE") {
            types.push("Java class file".to_string());
        }
        else if data.len() >= 512 && &data[257..257+5] == b"ustar" {
            types.push("TAR archive".to_string());
        }
        
        // Check for text-based formats
        if let Ok(text) = std::str::from_utf8(&data[0..data.len().min(1024)]) {
            // Check for XML
            if text.trim_start().starts_with("<?xml") {
                types.push("XML document".to_string());
                
                // Check for specific XML-based formats
                if text.contains("<svg") {
                    types.push("SVG image".to_string());
                }
                if text.contains("<html") || text.contains("<HTML") {
                    types.push("HTML document".to_string());
                }
            }
            // Check for JSON
            else if text.trim_start().starts_with("{") && text.trim_end().ends_with("}") {
                types.push("JSON data".to_string());
            }
            // Check for HTML
            else if text.contains("<html") || text.contains("<HTML") {
                types.push("HTML document".to_string());
            }
            // Check for script formats
            else if text.starts_with("#!/bin/bash") || text.starts_with("#!/bin/sh") {
                types.push("Bash shell script".to_string());
            }
            else if text.starts_with("#!/usr/bin/env python") || text.starts_with("#!/usr/bin/python") {
                types.push("Python script".to_string());
            }
            else if text.contains("function ") && (text.contains("var ") || text.contains("const ") || text.contains("let ")) {
                types.push("JavaScript code".to_string());
            }
            // Check for plain text
            else {
                let ascii_ratio = data.iter().take(1024).filter(|&&b| b >= 32 && b <= 126).count() as f64 / data.len().min(1024) as f64;
                if ascii_ratio > 0.9 {
                    types.push("Plain text".to_string());
                }
            }
        }
        
        // Based on entropy, check for encrypted or compressed data
        if types.is_empty() {
            let entropy = Entropy::calculate_entropy(data);
            if entropy > 7.9 {
                types.push("Possibly encrypted or compressed data (high entropy)".to_string());
            }
        }
        
        if types.is_empty() {
            types.push("Unknown file type".to_string());
        }
        
        types
    }
}

impl Operation for FileType {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "file-type".to_string(),
            description: "Detects the file type of the input data".to_string(),
            category: "Analysis".to_string(),
            args: vec![
                OperationArg {
                    name: "include_entropy".to_string(),
                    description: "Include entropy calculation in the output".to_string(),
                    default_value: Some("true".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let include_entropy = self.args.get("include_entropy").unwrap_or(&"true".to_string()) == "true";
        
        let file_types = Self::detect_file_type(&input);
        
        let mut result = String::new();
        result.push_str("Detected file type(s):\n");
        
        for file_type in file_types {
            result.push_str(&format!("- {}\n", file_type));
        }
        
        if include_entropy {
            let entropy = Entropy::calculate_entropy(&input);
            result.push_str(&format!("\nEntropy: {:.6}\n", entropy));
            
            if entropy < 1.0 {
                result.push_str("Very low entropy: possibly a repeating pattern or mostly one byte value.\n");
            } else if entropy < 3.0 {
                result.push_str("Low entropy: possibly a limited character set or highly structured data.\n");
            } else if entropy > 7.8 {
                result.push_str("Very high entropy: possibly encrypted, compressed, or random data.\n");
            }
        }
        
        // Add file size
        result.push_str(&format!("\nFile size: {} bytes\n", input.len()));
        
        Ok(result.into_bytes())
    }
}

// Magic Operation (Auto-detect and process)
pub struct Magic {
    args: HashMap<String, String>,
}

impl Magic {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
    
    fn detect_encoding(data: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut results = Vec::new();
        let input_string = String::from_utf8_lossy(data).to_string();
        
        // Try to detect Base64
        if data.len() % 4 == 0 && data.iter().all(|&b| 
            (b >= b'A' && b <= b'Z') || 
            (b >= b'a' && b <= b'z') || 
            (b >= b'0' && b <= b'9') || 
            b == b'+' || b == b'/' || b == b'=') {
            
            // Check if it has a reasonable number of padding characters
            let padding_count = data.iter().rev().take_while(|&&b| b == b'=').count();
            if padding_count <= 2 {
                if let Ok(decoded) = base64::decode(data) {
                    // Avoid adding binary data or data that's just ASCII numbers
                    let is_binary = decoded.iter().any(|&b| b < 9 || (b > 13 && b < 32));
                    let is_just_numbers = decoded.iter().all(|&b| (b >= b'0' && b <= b'9') || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r');
                    
                    if !is_binary && !is_just_numbers {
                        results.push(("Base64".to_string(), decoded));
                    }
                }
            }
        }
        
        // Try to detect Hex
        if data.len() % 2 == 0 && data.iter().all(|&b| 
            (b >= b'0' && b <= b'9') || 
            (b >= b'A' && b <= b'F') || 
            (b >= b'a' && b <= b'f') || 
            b == b' ' || b == b'\t' || b == b'\n' || b == b'\r') {
            
            // Remove whitespace
            let hex_str = data.iter()
                .filter(|&&b| b != b' ' && b != b'\t' && b != b'\n' && b != b'\r')
                .map(|&b| b as char)
                .collect::<String>();
            
            if !hex_str.is_empty() && hex_str.len() % 2 == 0 {
                if let Ok(decoded) = hex::decode(hex_str) {
                    // Avoid adding binary data
                    let is_binary = decoded.iter().any(|&b| b < 9 || (b > 13 && b < 32));
                    
                    if !is_binary {
                        results.push(("Hex".to_string(), decoded));
                    }
                }
            }
        }
        
        // Try to detect URL encoding
        if input_string.contains('%') {
            let has_percent_encoding = Regex::new(r"%[0-9A-Fa-f]{2}").unwrap().is_match(&input_string);
            
            if has_percent_encoding {
                let decoded = url::form_urlencoded::parse(data)
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<String>>()
                    .join("&")
                    .into_bytes();
                
                results.push(("URL-encoded".to_string(), decoded));
            }
        }
        
        // Try to detect JSON
        if input_string.trim_start().starts_with('{') && input_string.trim_end().ends_with('}') {
            // Attempt to pretty-print JSON
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&input_string) {
                if let Ok(pretty) = serde_json::to_string_pretty(&parsed) {
                    results.push(("JSON".to_string(), pretty.into_bytes()));
                }
            }
        }
        
        // Try to detect XML-like content and indent it
        if input_string.trim_start().starts_with('<') && input_string.contains("</") {
            // This is a very simplistic approach to formatting XML
            // A real implementation would use a proper XML parser and formatter
            let mut indented = String::new();
            let mut indent_level = 0;
            let mut in_tag = false;
            let mut in_processing_instruction = false;
            
            for c in input_string.chars() {
                match c {
                    '<' => {
                        if !in_tag {
                            indented.push('\n');
                            indented.push_str(&"  ".repeat(indent_level));
                            in_tag = true;
                            if input_string.chars().skip(indented.len()).take(1).collect::<String>() == "/" {
                                indent_level = indent_level.saturating_sub(1);
                            }
                        }
                        indented.push(c);
                        in_processing_instruction = input_string.chars().skip(indented.len()).take(1).collect::<String>() == "?";
                    },
                    '>' => {
                        indented.push(c);
                        in_tag = false;
                        let is_self_closing = indented.ends_with("/>") || indented.ends_with("?>");
                        if !is_self_closing && !in_processing_instruction && !indented.contains("</") {
                            indent_level += 1;
                        }
                    },
                    _ => indented.push(c),
                }
            }
            
            results.push(("XML/HTML".to_string(), indented.into_bytes()));
        }
        
        results
    }
}

impl Operation for Magic {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "magic".to_string(),
            description: "Automatically detects encodings and attempts to decode them".to_string(),
            category: "Analysis".to_string(),
            args: vec![
                OperationArg {
                    name: "depth".to_string(),
                    description: "Maximum recursion depth for nested encodings".to_string(),
                    default_value: Some("3".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "show_all".to_string(),
                    description: "Show all possible decodings, not just the most likely".to_string(),
                    default_value: Some("false".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let max_depth: usize = self.args.get("depth")
            .unwrap_or(&"3".to_string())
            .parse()
            .unwrap_or(3);
        
        let show_all = self.args.get("show_all").unwrap_or(&"false".to_string()) == "true";
        
        let mut result = String::new();
        result.push_str("Magic detection results:\n\n");
        
        // Detect file type
        result.push_str("File type detection:\n");
        let file_types = FileType::detect_file_type(&input);
        for file_type in file_types {
            result.push_str(&format!("- {}\n", file_type));
        }
        result.push('\n');
        
        // Try to decode the data
        result.push_str("Detected encodings:\n");
        
        let mut to_process = vec![(input.clone(), String::new(), 0)];
        let mut processed = HashSet::new();
        
        while let Some((data, path, depth)) = to_process.pop() {
            // Avoid processing the same data multiple times
            if processed.contains(&data) || depth > max_depth {
                continue;
            }
            
            processed.insert(data.clone());
            
            // Try to detect encodings
            let detected = Self::detect_encoding(&data);
            
            for (encoding, decoded) in detected {
                let new_path = if path.is_empty() {
                    encoding.clone()
                } else {
                    format!("{} -> {}", path, encoding)
                };
                
                // Determine whether to show this result
                let should_show = show_all || depth < 1;
                
                if should_show {
                    result.push_str(&format!("Encoding chain: {}\n", new_path));
                    
                    // Show a preview of the decoded data
                    let preview = if decoded.len() > 100 {
                        format!("{}... ({} bytes total)", String::from_utf8_lossy(&decoded[0..100]), decoded.len())
                    } else {
                        String::from_utf8_lossy(&decoded).to_string()
                    };
                    
                    result.push_str(&format!("Decoded: {}\n\n", preview));
                }
                
                // Add the decoded data to the processing queue for further analysis
                to_process.push((decoded, new_path, depth + 1));
            }
        }
        
        if result.contains("Encoding chain:") {
            result.push_str("\nNote: You can use these detected encodings to create a recipe chain for decoding.\n");
        } else {
            result.push_str("No standard encodings detected.\n");
        }
        
        Ok(result.into_bytes())
    }
}

// Hex Dump Operation
pub struct HexDump {
    args: HashMap<String, String>,
}

impl HexDump {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for HexDump {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "hex-dump".to_string(),
            description: "Creates a hex dump of the input data".to_string(),
            category: "Analysis".to_string(),
            args: vec![
                OperationArg {
                    name: "width".to_string(),
                    description: "Number of bytes per line".to_string(),
                    default_value: Some("16".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "offset".to_string(),
                    description: "Starting offset".to_string(),
                    default_value: Some("0".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "show_ascii".to_string(),
                    description: "Show ASCII representation".to_string(),
                    default_value: Some("true".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let width: usize = self.args.get("width")
            .unwrap_or(&"16".to_string())
            .parse()
            .unwrap_or(16);
        
        let offset: usize = self.args.get("offset")
            .unwrap_or(&"0".to_string())
            .parse()
            .unwrap_or(0);
        
        let show_ascii = self.args.get("show_ascii").unwrap_or(&"true".to_string()) == "true";
        
        let mut result = String::new();
        
        for (i, chunk) in input.chunks(width).enumerate() {
            // Print offset
            result.push_str(&format!("{:08x}  ", offset + i * width));
            
            // Print hex values
            for (j, &byte) in chunk.iter().enumerate() {
                result.push_str(&format!("{:02x} ", byte));
                
                // Add extra space in the middle
                if j == width / 2 - 1 {
                    result.push(' ');
                }
            }
            
            // Pad for missing bytes in the last line
            if chunk.len() < width {
                let pad_count = width - chunk.len();
                result.push_str(&" ".repeat(pad_count * 3));
                
                // Adjust for the missing middle space if needed
                if chunk.len() <= width / 2 {
                    result.push(' ');
                }
            }
            
            // Print ASCII representation
            if show_ascii {
                result.push_str(" |");
                for &byte in chunk {
                    if byte >= 32 && byte <= 126 {
                        result.push(byte as char);
                    } else {
                        result.push('.');
                    }
                }
                result.push('|');
            }
            
            result.push('\n');
        }
        
        Ok(result.into_bytes())
    }
}

// Statistics Operation
pub struct Statistics {
    args: HashMap<String, String>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Statistics {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "statistics".to_string(),
            description: "Calculates statistics about the input data".to_string(),
            category: "Analysis".to_string(),
            args: vec![
                OperationArg {
                    name: "frequency".to_string(),
                    description: "Show byte frequency table".to_string(),
                    default_value: Some("true".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "top_n".to_string(),
                    description: "Show only the top N most frequent bytes".to_string(),
                    default_value: Some("10".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let show_frequency = self.args.get("frequency").unwrap_or(&"true".to_string()) == "true";
        let top_n: usize = self.args.get("top_n")
            .unwrap_or(&"10".to_string())
            .parse()
            .unwrap_or(10);
        
        let mut result = String::new();
        
        // Basic statistics
        result.push_str(&format!("File size: {} bytes\n", input.len()));
        
        // Count unique bytes
        let mut byte_counts = [0; 256];
        for &byte in &input {
            byte_counts[byte as usize] += 1;
        }
        
        let unique_bytes = byte_counts.iter().filter(|&&count| count > 0).count();
        result.push_str(&format!("Unique bytes: {}/256\n", unique_bytes));
        
        // Calculate entropy
        let entropy = Entropy::calculate_entropy(&input);
        result.push_str(&format!("Entropy: {:.6}\n", entropy));
        
        // Count ASCII, printable, and control characters
        let ascii_count = input.iter().filter(|&&b| b <= 127).count();
        let printable_count = input.iter().filter(|&&b| b >= 32 && b <= 126).count();
        let control_count = input.iter().filter(|&&b| b < 32 || b == 127).count();
        
        result.push_str(&format!("ASCII characters: {} ({:.2}%)\n", 
                              ascii_count, 
                              100.0 * ascii_count as f64 / input.len() as f64));
        
        result.push_str(&format!("Printable characters: {} ({:.2}%)\n", 
                              printable_count, 
                              100.0 * printable_count as f64 / input.len() as f64));
        
        result.push_str(&format!("Control characters: {} ({:.2}%)\n", 
                              control_count, 
                              100.0 * control_count as f64 / input.len() as f64));
        
        // Show byte frequency table
        if show_frequency && !input.is_empty() {
            result.push_str("\nByte frequency:\n");
            
            // Collect all non-zero byte counts
            let mut counts: Vec<(u8, usize)> = byte_counts.iter()
                .enumerate()
                .filter(|&(_, &count)| count > 0)
                .map(|(byte, &count)| (byte as u8, count))
                .collect();
            
            // Sort by frequency (descending)
            counts.sort_by(|a, b| b.1.cmp(&a.1));
            
            // Take the top N
            for (byte, count) in counts.iter().take(top_n) {
                let percentage = 100.0 * *count as f64 / input.len() as f64;
                
                // Format the byte as hex, decimal, and ASCII if printable
                let byte_format = if *byte >= 32 && *byte <= 126 {
                    format!("0x{:02x} / {} / '{}'", byte, byte, *byte as char)
                } else {
                    format!("0x{:02x} / {}", byte, byte)
                };
                
                result.push_str(&format!("{}: {} ({:.2}%)\n", 
                                      byte_format, count, percentage));
            }
            
            // Show if there are more not displayed
            if counts.len() > top_n {
                result.push_str(&format!("... and {} more\n", counts.len() - top_n));
            }
        }
        
        Ok(result.into_bytes())
    }
}
