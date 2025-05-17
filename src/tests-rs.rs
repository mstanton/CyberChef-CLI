#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use anyhow::Result;
    use crate::operations::{Operation, get_operation};
    use crate::recipe::Recipe;

    fn create_test_file(content: &[u8]) -> Result<PathBuf> {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("cyberchef_test_{}.tmp", rand::random::<u64>()));
        fs::write(&file_path, content)?;
        Ok(file_path)
    }

    fn clean_test_file(path: &PathBuf) -> Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    #[test]
    fn test_base64_operations() -> Result<()> {
        // Test Base64 encode
        let input = b"Hello, world!";
        let base64_encode_op = get_operation("base64-encode", &[])?;
        let encoded = base64_encode_op.run(input.to_vec())?;
        
        // Expected result: "SGVsbG8sIHdvcmxkIQ=="
        let expected = b"SGVsbG8sIHdvcmxkIQ==";
        assert_eq!(encoded, expected);
        
        // Test Base64 decode
        let base64_decode_op = get_operation("base64-decode", &[])?;
        let decoded = base64_decode_op.run(encoded)?;
        
        assert_eq!(decoded, input);
        
        Ok(())
    }

    #[test]
    fn test_hex_operations() -> Result<()> {
        // Test Hex encode
        let input = b"Hello, world!";
        let hex_encode_op = get_operation("hex-encode", &[])?;
        let encoded = hex_encode_op.run(input.to_vec())?;
        
        // Expected result: "48656c6c6f2c20776f726c6421"
        let expected = b"48656c6c6f2c20776f726c6421";
        assert_eq!(encoded, expected);
        
        // Test Hex decode
        let hex_decode_op = get_operation("hex-decode", &[])?;
        let decoded = hex_decode_op.run(encoded)?;
        
        assert_eq!(decoded, input);
        
        Ok(())
    }

    #[test]
    fn test_recipe_chaining() -> Result<()> {
        // Create a recipe: base64-encode | hex-encode
        let recipe_str = "base64-encode | hex-encode";
        let recipe = Recipe::parse(recipe_str)?;
        
        let input = b"Hello, world!";
        let output = recipe.run(input.to_vec())?;
        
        // Expected: hex(base64("Hello, world!"))
        // base64("Hello, world!") = "SGVsbG8sIHdvcmxkIQ=="
        // hex("SGVsbG8sIHdvcmxkIQ==") = "5347567362473873494864766347786B49513d3d"
        let expected = b"5347567362473873494864766347786B49513d3d";
        assert_eq!(output, expected);
        
        Ok(())
    }

    #[test]
    fn test_recipe_validation() -> Result<()> {
        // Valid recipe
        let valid_recipe = Recipe::parse("base64-encode | hex-encode")?;
        assert!(valid_recipe.validate().is_ok());
        
        // Invalid operation
        let invalid_op_recipe = Recipe::parse("base64-encode | non-existent-op")?;
        assert!(invalid_op_recipe.validate().is_err());
        
        // Invalid argument
        let invalid_arg_recipe = Recipe::parse("base64-encode --invalid=value | hex-encode")?;
        assert!(invalid_arg_recipe.validate().is_err());
        
        Ok(())
    }

    #[test]
    fn test_file_operations() -> Result<()> {
        let input = b"Hello, world!";
        let input_file = create_test_file(input)?;
        
        // Read from file
        let data = fs::read(&input_file)?;
        assert_eq!(data, input);
        
        // Process with base64-encode
        let base64_encode_op = get_operation("base64-encode", &[])?;
        let encoded = base64_encode_op.run(data)?;
        
        // Write to output file
        let output_file = input_file.with_file_name("cyberchef_test_output.tmp");
        fs::write(&output_file, &encoded)?;
        
        // Read back and verify
        let encoded_from_file = fs::read(&output_file)?;
        assert_eq!(encoded_from_file, encoded);
        
        // Clean up
        clean_test_file(&input_file)?;
        clean_test_file(&output_file)?;
        
        Ok(())
    }

    #[test]
    fn test_entropy_calculation() -> Result<()> {
        // Test low entropy data
        let low_entropy = vec![0; 100]; // All zeros
        let entropy_op = get_operation("entropy", &[])?;
        let result = entropy_op.run(low_entropy)?;
        let result_str = String::from_utf8_lossy(&result);
        
        assert!(result_str.contains("Entropy (base 2): 0.000000"));
        
        // Test high entropy data
        let mut high_entropy = vec![0u8; 100];
        for i in 0..100 {
            high_entropy[i] = i as u8;
        }
        
        let result = entropy_op.run(high_entropy)?;
        let result_str = String::from_utf8_lossy(&result);
        
        // Should be close to maximum entropy for this data
        assert!(result_str.contains("Entropy (base 2):"));
        assert!(result_str.parse_float_greater_than(6.0));
        
        Ok(())
    }
}

trait ParseFloatFromString {
    fn parse_float_greater_than(&self, threshold: f64) -> bool;
}

impl ParseFloatFromString for str {
    fn parse_float_greater_than(&self, threshold: f64) -> bool {
        let re = regex::Regex::new(r"Entropy \(base 2\): (\d+\.\d+)").unwrap();
        
        if let Some(caps) = re.captures(self) {
            if let Ok(value) = caps[1].parse::<f64>() {
                return value > threshold;
            }
        }
        
        false
    }
}
