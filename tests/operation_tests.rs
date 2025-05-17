use cyberchef_cli::operations::{
    encoding::{Base64Encode, Base64Decode, HexEncode, HexDecode},
    encryption::{AesEncrypt, AesDecrypt},
    compression::{GzipCompress, GzipDecompress},
    hashing::{Sha256Hash, Sha512Hash},
    analysis::{EntropyAnalysis, FrequencyAnalysis, PatternAnalysis},
    OperationTrait,
};

#[test]
fn test_base64_operations() {
    let input = b"Hello, World!";
    let encoder = Base64Encode;
    let decoder = Base64Decode;
    
    let encoded = encoder.execute(input).unwrap();
    let decoded = decoder.execute(&encoded).unwrap();
    
    assert_eq!(input, decoded.as_slice());
}

#[test]
fn test_hex_operations() {
    let input = b"Hello, World!";
    let encoder = HexEncode;
    let decoder = HexDecode;
    
    let encoded = encoder.execute(input).unwrap();
    let decoded = decoder.execute(&encoded).unwrap();
    
    assert_eq!(input, decoded.as_slice());
}

#[test]
fn test_gzip_operations() {
    let input = b"Hello, World! This is a test string that should be compressed and then decompressed back to its original form.";
    let compressor = GzipCompress;
    let decompressor = GzipDecompress;
    
    let compressed = compressor.execute(input).unwrap();
    let decompressed = decompressor.execute(&compressed).unwrap();
    
    assert_eq!(input, decompressed.as_slice());
}

#[test]
fn test_hash_operations() {
    let input = b"Hello, World!";
    let sha256 = Sha256Hash;
    let sha512 = Sha512Hash;
    
    let hash256 = sha256.execute(input).unwrap();
    let hash512 = sha512.execute(input).unwrap();
    
    assert_eq!(hash256.len(), 32); // SHA-256 produces 32 bytes
    assert_eq!(hash512.len(), 64); // SHA-512 produces 64 bytes
}

#[test]
fn test_analysis_operations() {
    let input = b"Hello, World! This is a test string with some repeated patterns like 'test' and 'pattern'.";
    
    let entropy = EntropyAnalysis;
    let frequency = FrequencyAnalysis;
    let pattern = PatternAnalysis;
    
    let entropy_result = entropy.execute(input).unwrap();
    let frequency_result = frequency.execute(input).unwrap();
    let pattern_result = pattern.execute(input).unwrap();
    
    // Verify that we got some output
    assert!(!entropy_result.is_empty());
    assert!(!frequency_result.is_empty());
    assert!(!pattern_result.is_empty());
    
    // Verify that entropy result contains a number
    let entropy_str = std::str::from_utf8(&entropy_result).unwrap();
    assert!(entropy_str.contains("bits/byte"));
    
    // Verify that frequency analysis contains percentages
    let frequency_str = std::str::from_utf8(&frequency_result).unwrap();
    assert!(frequency_str.contains("%"));
    
    // Verify that pattern analysis found some patterns
    let pattern_str = std::str::from_utf8(&pattern_result).unwrap();
    assert!(pattern_str.contains("Pattern"));
} 