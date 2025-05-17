use crate::operations;
use anyhow::{Result, anyhow, Context};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeStep {
    pub operation: String,
    pub args: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub steps: Vec<RecipeStep>,
    #[serde(skip)]
    pub description: Option<String>,
    #[serde(skip)]
    pub version: String,
}

impl Recipe {
    /// Parse a recipe string in the format:
    /// "op1 --arg1=val1 | op2 --arg2=val2 | op3"
    pub fn parse(recipe_str: &str) -> Result<Self> {
        let steps = recipe_str
            .split('|')
            .map(|step_str| Self::parse_step(step_str.trim()))
            .collect::<Result<Vec<_>>>()?;

        if steps.is_empty() {
            return Err(anyhow!("Recipe contains no operations"));
        }

        Ok(Recipe { 
            steps, 
            description: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    /// Parse a single recipe step
    fn parse_step(step_str: &str) -> Result<RecipeStep> {
        let parts: Vec<&str> = step_str.split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow!("Empty operation step"));
        }

        let operation = parts[0].to_string();
        let mut args = HashMap::new();

        // Parse arguments
        let arg_regex = Regex::new(r"--([a-zA-Z0-9_-]+)(?:=(.*))?").unwrap();
        for part in &parts[1..] {
            if let Some(captures) = arg_regex.captures(part) {
                let key = captures.get(1).unwrap().as_str().to_string();
                let value = captures.get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| "true".to_string());
                
                args.insert(key, value);
            } else {
                return Err(anyhow!("Invalid argument format: {}", part));
            }
        }

        Ok(RecipeStep { operation, args })
    }

    /// Run the recipe on input data
    pub fn run(&self, input: Vec<u8>) -> Result<Vec<u8>> {
        let mut data = input;
        
        for (i, step) in self.steps.iter().enumerate() {
            let op = operations::get_operation(&step.operation, &Self::args_to_vec(&step.args))
                .with_context(|| format!("Failed to get operation: {}", step.operation))?;
            
            data = op.run(data)
                .with_context(|| format!("Failed to run step {}: {}", i + 1, step.operation))?;
        }
        
        Ok(data)
    }

    /// Convert args HashMap to a vector of strings in "key=value" format
    fn args_to_vec(args: &HashMap<String, String>) -> Vec<String> {
        args.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect()
    }

    /// Convert recipe to JSON for saving
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("Failed to serialize recipe to JSON")
    }

    /// Load recipe from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        let mut recipe: Recipe = serde_json::from_str(json)
            .context("Failed to deserialize recipe from JSON")?;
        
        recipe.version = env!("CARGO_PKG_VERSION").to_string();
        
        Ok(recipe)
    }

    /// Validate the recipe to ensure all operations exist and arguments are valid
    pub fn validate(&self) -> Result<()> {
        for (i, step) in self.steps.iter().enumerate() {
            // Check if operation exists
            let op = operations::get_operation(&step.operation, &Self::args_to_vec(&step.args))
                .with_context(|| format!("Step {}: Invalid operation '{}'", i + 1, step.operation))?;
            
            // Check if arguments are valid
            let info = op.info();
            let valid_args: Vec<String> = info.args.iter().map(|arg| arg.name.clone()).collect();
            
            for arg_name in step.args.keys() {
                if !valid_args.contains(arg_name) {
                    return Err(anyhow!("Step {}: Invalid argument '{}' for operation '{}'", 
                                      i + 1, arg_name, step.operation));
                }
            }
            
            // Check required arguments
            for arg in info.args.iter().filter(|arg| arg.required) {
                if !step.args.contains_key(&arg.name) {
                    return Err(anyhow!("Step {}: Missing required argument '{}' for operation '{}'", 
                                      i + 1, arg.name, step.operation));
                }
            }
        }
        
        Ok(())
    }
}
