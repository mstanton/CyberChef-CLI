use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::operations::{Operation, OperationRegistry};

/// Represents a complete CyberChef recipe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub operations: Vec<Operation>,
}

impl Recipe {
    /// Create a new empty recipe
    pub fn new() -> Self {
        Recipe {
            operations: Vec::new(),
        }
    }

    /// Parse a recipe from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let recipe: Recipe = serde_json::from_str(json)?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Convert recipe to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Validate the recipe
    pub fn validate(&self) -> Result<()> {
        let registry = OperationRegistry::new();
        
        for op in &self.operations {
            if let Some(operation) = registry.get_operation(&op.name) {
                operation.validate_args(&op.args)?;
            } else {
                anyhow::bail!("Unknown operation: {}", op.name);
            }
        }
        
        Ok(())
    }

    /// Execute the recipe on input data
    pub fn execute(&self, input: &[u8]) -> Result<Vec<u8>> {
        let registry = OperationRegistry::new();
        let mut data = input.to_vec();
        
        for op in &self.operations {
            if let Some(operation) = registry.get_operation(&op.name) {
                data = operation.execute(&data)?;
            } else {
                anyhow::bail!("Unknown operation: {}", op.name);
            }
        }
        
        Ok(data)
    }
} 