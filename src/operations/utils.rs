use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use log::{info, warn, error, debug};
use regex::Regex;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use std::time::{SystemTime, UNIX_EPOCH};
use std::iter;

// Secure temporary file handling
pub struct SecureTempFile {
    path: PathBuf,
    file: Option<File>,
}

impl SecureTempFile {
    pub fn new(prefix: &str) -> Result<Self> {
        // Generate a random filename with timestamp
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .context("Failed to get system time")?
            .as_secs();
        
        let rand_suffix: String = iter::repeat(())
            .map(|()| thread_rng().sample(Alphanumeric))
            .take(16)
            .map(char::from)
            .collect();
        
        let filename = format!("{}_{:x}_{}", prefix, timestamp, rand_suffix);
        
        // Create temp directory if it doesn't exist
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(filename);
        
        // Create and open the file with secure permissions
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            // Mode 0600 (only owner can read/write) on Unix systems
            // On Windows, this is handled differently by the OS
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("Failed to create temp file: {:?}", path))?;
        
        Ok(Self {
            path,
            file: Some(file),
        })
    }
    
    pub fn path(&self) -> &Path {
        &self.path
    }
    
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if let Some(file) = &mut self.file {
            file.write_all(data).context("Failed to write to temp file")?;
            file.flush().context("Failed to flush temp file")?;
        } else {
            return Err(anyhow!("Temp file is already closed"));
        }
        
        Ok(())
    }
    
    pub fn read(&mut self) -> Result<Vec<u8>> {
        if let Some(file) = &mut self.file {
            file.seek(io::SeekFrom::Start(0)).context("Failed to seek to start of temp file")?;
            
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).context("Failed to read from temp file")?;
            
            Ok(buffer)
        } else {
            Err(anyhow!("Temp file is already closed"))
        }
    }
    
    // Securely wipe and delete the file
    pub fn secure_delete(mut self) -> Result<()> {
        // Close the file if it's open
        if let Some(mut file) = self.file.take() {
            // Get file size
            let file_size = file.metadata()
                .context("Failed to get file metadata")?
                .len() as usize;
            
            // Overwrite with random data
            let mut buffer = vec![0u8; 8192.min(file_size)];
            let mut remaining = file_size;
            
            while remaining > 0 {
                let write_size = buffer.len().min(remaining);
                thread_rng().fill(&mut buffer[..write_size]);
                
                file.seek(io::SeekFrom::Start((file_size - remaining) as u64))
                    .context("Failed to seek in file for secure wiping")?;
                
                file.write_all(&buffer[..write_size])
                    .context("Failed to overwrite file for secure wiping")?;
                
                remaining = remaining.saturating_sub(write_size);
            }
            
            // Flush changes
            file.flush().context("Failed to flush file changes")?;
            
            // Close the file
            drop(file);
        }
        
        // Delete the file
        if self.path.exists() {
            fs::remove_file(&self.path)
                .with_context(|| format!("Failed to delete temp file: {:?}", self.path))?;
        }
        
        Ok(())
    }
}

// Implement Drop to ensure the file is deleted even if secure_delete isn't called
impl Drop for SecureTempFile {
    fn drop(&mut self) {
        // Close the file if it's open
        self.file.take();
        
        // Try to delete the file
        if self.path.exists() {
            if let Err(err) = fs::remove_file(&self.path) {
                error!("Failed to delete temp file {:?}: {}", self.path, err);
            }
        }
    }
}

// Secure string handling (for sensitive data like passwords)
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }
    
    pub fn from_string(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }
    
    pub fn append(&mut self, s: &str) {
        self.data.extend_from_slice(s.as_bytes());
    }
    
    pub fn clear(&mut self) {
        // Overwrite with zeros before clearing
        for byte in &mut self.data {
            *byte = 0;
        }
        self.data.clear();
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    // Use this method carefully, as it converts to a String which may be copied by Rust
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.data).context("SecureString contains invalid UTF-8")
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.clear();
    }
}

// Constant-time comparison to prevent timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

// Safe path handling to prevent directory traversal attacks
pub fn sanitize_path(base_dir: &Path, user_path: &str) -> Result<PathBuf> {
    // Convert to absolute path
    let base_dir = fs::canonicalize(base_dir)
        .with_context(|| format!("Failed to canonicalize base directory: {:?}", base_dir))?;
    
    // Remove potentially dangerous characters
    let sanitized = user_path.replace("..", "_").replace('/', "_").replace('\\', "_");
    
    // Combine base directory with sanitized path
    let full_path = base_dir.join(sanitized);
    
    // Verify the resulting path is within the base directory
    let canonicalized = fs::canonicalize(&full_path)
        .unwrap_or_else(|_| full_path.clone());
    
    if !canonicalized.starts_with(&base_dir) {
        return Err(anyhow!("Path traversal detected"));
    }
    
    Ok(full_path)
}

// Input validation utilities
pub struct Validator;

impl Validator {
    // Validate alphanumeric string with limited punctuation
    pub fn is_safe_string(input: &str) -> bool {
        let safe_regex = Regex::new(r"^[a-zA-Z0-9_\-.\s]+$").unwrap();
        safe_regex.is_match(input)
    }
    
    // Validate hex string
    pub fn is_hex_string(input: &str) -> bool {
        let hex_regex = Regex::new(r"^[0-9a-fA-F]+$").unwrap();
        hex_regex.is_match(input)
    }
    
    // Validate base64 string
    pub fn is_base64_string(input: &str) -> bool {
        let base64_regex = Regex::new(r"^[A-Za-z0-9+/]*={0,2}$").unwrap();
        base64_regex.is_match(input) && input.len() % 4 == 0
    }
    
    // Validate integer within range
    pub fn is_int_in_range(input: &str, min: i64, max: i64) -> bool {
        if let Ok(value) = input.parse::<i64>() {
            value >= min && value <= max
        } else {
            false
        }
    }
}

// Secure random number generation
pub struct SecureRandom;

impl SecureRandom {
    // Generate random bytes
    pub fn bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        thread_rng().fill(&mut bytes[..]);
        bytes
    }
    
    // Generate random hex string
    pub fn hex_string(len: usize) -> String {
        let bytes = Self::bytes((len + 1) / 2);
        hex::encode(&bytes)[..len].to_string()
    }
    
    // Generate random alphanumeric string
    pub fn alphanumeric(len: usize) -> String {
        iter::repeat(())
            .map(|()| thread_rng().sample(Alphanumeric))
            .take(len)
            .map(char::from)
            .collect()
    }
    
    // Generate random number in range
    pub fn number_in_range(min: u64, max: u64) -> u64 {
        thread_rng().gen_range(min..=max)
    }
}

// Limit data processing to prevent resource exhaustion
pub struct ResourceLimiter {
    max_input_size: usize,
    max_memory_usage: usize,
    current_memory_usage: usize,
}

impl ResourceLimiter {
    pub fn new(max_input_size: usize, max_memory_usage: usize) -> Self {
        Self {
            max_input_size,
            max_memory_usage,
            current_memory_usage: 0,
        }
    }
    
    pub fn check_input_size(&self, size: usize) -> Result<()> {
        if size > self.max_input_size {
            return Err(anyhow!("Input size exceeds maximum allowed ({} > {})", 
                             size, self.max_input_size));
        }
        
        Ok(())
    }
    
    pub fn allocate_memory(&mut self, size: usize) -> Result<()> {
        let new_usage = self.current_memory_usage + size;
        
        if new_usage > self.max_memory_usage {
            return Err(anyhow!("Memory allocation would exceed maximum allowed ({} > {})",
                             new_usage, self.max_memory_usage));
        }
        
        self.current_memory_usage = new_usage;
        Ok(())
    }
    
    pub fn free_memory(&mut self, size: usize) {
        self.current_memory_usage = self.current_memory_usage.saturating_sub(size);
    }
}

// Secure file operations
pub fn read_file_safely(path: &Path, max_size: usize) -> Result<Vec<u8>> {
    // Check if file exists
    if !path.exists() {
        return Err(anyhow!("File not found: {:?}", path));
    }
    
    // Check file size
    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for file: {:?}", path))?;
    
    let file_size = metadata.len() as usize;
    if file_size > max_size {
        return Err(anyhow!("File size exceeds maximum allowed ({} > {})", 
                         file_size, max_size));
    }
    
    // Read file
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open file: {:?}", path))?;
    
    let mut buffer = Vec::with_capacity(file_size);
    file.read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read file: {:?}", path))?;
    
    Ok(buffer)
}

pub fn write_file_safely(path: &Path, data: &[u8], max_size: usize) -> Result<()> {
    // Check data size
    if data.len() > max_size {
        return Err(anyhow!("Data size exceeds maximum allowed ({} > {})",
                         data.len(), max_size));
    }
    
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directories: {:?}", parent))?;
        }
    }
    
    // Write to a temporary file first
    let temp_file_name = format!(".{}.tmp", SecureRandom::hex_string(8));
    let temp_path = path.with_file_name(temp_file_name);
    
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600) // Secure permissions
        .open(&temp_path)
        .with_context(|| format!("Failed to create temporary file: {:?}", temp_path))?;
    
    file.write_all(data)
        .with_context(|| format!("Failed to write to temporary file: {:?}", temp_path))?;
    
    file.flush()
        .with_context(|| format!("Failed to flush temporary file: {:?}", temp_path))?;
    
    // Close the file
    drop(file);
    
    // Rename temporary file to target file (atomic operation)
    fs::rename(&temp_path, path)
        .with_context(|| format!("Failed to rename temporary file to target: {:?} -> {:?}", 
                               temp_path, path))?;
    
    Ok(())
}

// Hash Map wrapper with case-insensitive keys
pub struct CaseInsensitiveMap<V> {
    inner: HashMap<String, V>,
}

impl<V> CaseInsensitiveMap<V> {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
    
    pub fn insert(&mut self, key: String, value: V) -> Option<V> {
        self.inner.insert(key.to_lowercase(), value)
    }
    
    pub fn get(&self, key: &str) -> Option<&V> {
        self.inner.get(&key.to_lowercase())
    }
    
    pub fn contains_key(&self, key: &str) -> bool {
        self.inner.contains_key(&key.to_lowercase())
    }
    
    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.inner.remove(&key.to_lowercase())
    }
    
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.inner.iter()
    }
}

impl<V> Default for CaseInsensitiveMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

// Logging utilities
pub fn setup_logging(level: &str) -> Result<()> {
    let level = match level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => return Err(anyhow!("Invalid log level: {}", level)),
    };
    
    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .init();
    
    Ok(())
}
