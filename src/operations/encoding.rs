use crate::operations::{Operation, OperationInfo, OperationArg};
use anyhow::{Result, anyhow, Context};
use std::collections::HashMap;

// Base64 Encode Operation
pub struct Base64Encode {
    args: HashMap<String, String>,
}

impl Base64Encode {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Base64Encode {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "base64-encode".to_string(),
            description: "Encodes data as Base64".to_string(),
            category: "Encoding".to_string(),
            args: vec![
                OperationArg {
                    name: "alphabet".to_string(),
                    description: "The alphabet to use for encoding".to_string(),
                    default_value: Some("standard".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let alphabet = self.args.get("alphabet").unwrap_or(&"standard".to_string());
        
        let encoded = match alphabet.as_str() {
            "standard" => base64::encode(&input),
            "url_safe" => base64::encode_config(&input, base64::URL_SAFE),
            _ => return Err(anyhow!("Unsupported Base64 alphabet: {}", alphabet)),
        };
        
        Ok(encoded.into_bytes())
    }
}

// Base64 Decode Operation
pub struct Base64Decode {
    args: HashMap<String, String>,
}

impl Base64Decode {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for Base64Decode {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "base64-decode".to_string(),
            description: "Decodes Base64 data".to_string(),
            category: "Encoding".to_string(),
            args: vec![
                OperationArg {
                    name: "alphabet".to_string(),
                    description: "The alphabet used for encoding".to_string(),
                    default_value: Some("standard".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "ignore_errors".to_string(),
                    description: "Ignore non-alphabet characters".to_string(),
                    default_value: Some("false".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let input_str = String::from_utf8_lossy(&input).to_string();
        let alphabet = self.args.get("alphabet").unwrap_or(&"standard".to_string());
        let ignore_errors = self.args.get("ignore_errors").unwrap_or(&"false".to_string()) == "true";
        
        let decoded = match alphabet.as_str() {
            "standard" => {
                if ignore_errors {
                    base64::decode_config(
                        &input_str.chars().filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=').collect::<String>(),
                        base64::STANDARD,
                    )
                } else {
                    base64::decode(&input_str)
                }
            },
            "url_safe" => {
                if ignore_errors {
                    base64::decode_config(
                        &input_str.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '=').collect::<String>(),
                        base64::URL_SAFE,
                    )
                } else {
                    base64::decode_config(&input_str, base64::URL_SAFE)
                }
            },
            _ => return Err(anyhow!("Unsupported Base64 alphabet: {}", alphabet)),
        }.context("Failed to decode Base64 data")?;
        
        Ok(decoded)
    }
}

// Hex Encode Operation
pub struct HexEncode {
    args: HashMap<String, String>,
}

impl HexEncode {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for HexEncode {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "hex-encode".to_string(),
            description: "Encodes data as hexadecimal".to_string(),
            category: "Encoding".to_string(),
            args: vec![
                OperationArg {
                    name: "delimiter".to_string(),
                    description: "Character(s) to insert between bytes".to_string(),
                    default_value: Some("".to_string()),
                    required: false,
                },
                OperationArg {
                    name: "uppercase".to_string(),
                    description: "Use uppercase letters (A-F instead of a-f)".to_string(),
                    default_value: Some("false".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let delimiter = self.args.get("delimiter").unwrap_or(&"".to_string());
        let uppercase = self.args.get("uppercase").unwrap_or(&"false".to_string()) == "true";
        
        let encoded = if delimiter.is_empty() {
            if uppercase {
                hex::encode_upper(&input)
            } else {
                hex::encode(&input)
            }
        } else {
            let hex_chars: Vec<String> = input.iter()
                .map(|b| {
                    if uppercase {
                        format!("{:02X}", b)
                    } else {
                        format!("{:02x}", b)
                    }
                })
                .collect();
            hex_chars.join(delimiter)
        };
        
        Ok(encoded.into_bytes())
    }
}

// Hex Decode Operation
pub struct HexDecode {
    args: HashMap<String, String>,
}

impl HexDecode {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for HexDecode {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "hex-decode".to_string(),
            description: "Decodes hexadecimal data".to_string(),
            category: "Encoding".to_string(),
            args: vec![
                OperationArg {
                    name: "ignore_errors".to_string(),
                    description: "Ignore non-hex characters".to_string(),
                    default_value: Some("false".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let input_str = String::from_utf8_lossy(&input).to_string();
        let ignore_errors = self.args.get("ignore_errors").unwrap_or(&"false".to_string()) == "true";
        
        let cleaned_input = if ignore_errors {
            input_str.chars()
                .filter(|c| c.is_digit(16))
                .collect::<String>()
        } else {
            input_str.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        };
        
        hex::decode(&cleaned_input).context("Failed to decode hex data")
    }
}

// URL Encode Operation
pub struct UrlEncode {
    args: HashMap<String, String>,
}

impl UrlEncode {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for UrlEncode {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "url-encode".to_string(),
            description: "Encodes data as URL-encoded text".to_string(),
            category: "Encoding".to_string(),
            args: vec![
                OperationArg {
                    name: "component".to_string(),
                    description: "Encode entire URL or just components".to_string(),
                    default_value: Some("component".to_string()),
                    required: false,
                },
            ],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let input_str = String::from_utf8_lossy(&input).to_string();
        let component = self.args.get("component").unwrap_or(&"component".to_string()) == "component";
        
        let encoded = if component {
            url::form_urlencoded::byte_serialize(&input).collect::<String>()
        } else {
            // Simple URL encoding (not a full URL parser)
            input_str.chars().map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                    c.to_string()
                } else {
                    format!("%{:02X}", c as u8)
                }
            }).collect::<String>()
        };
        
        Ok(encoded.into_bytes())
    }
}

// URL Decode Operation
pub struct UrlDecode {
    args: HashMap<String, String>,
}

impl UrlDecode {
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }
}

impl Operation for UrlDecode {
    fn info(&self) -> OperationInfo {
        OperationInfo {
            name: "url-decode".to_string(),
            description: "Decodes URL-encoded text".to_string(),
            category: "Encoding".to_string(),
            args: vec![],
        }
    }

    fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let input_str = String::from_utf8_lossy(&input).to_string();
        
        let decoded = url::form_urlencoded::parse(input_str.as_bytes())
            .map(|(key, val)| format!("{}={}", key, val))
            .collect::<Vec<String>>()
            .join("&");
        
        Ok(decoded.into_bytes())
    }
}
