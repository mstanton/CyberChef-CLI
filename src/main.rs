use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::io::{self, Read};
use std::fs;
use anyhow::{Result, Context};

mod operations;
mod recipe;
mod utils;

use operations::Operation;
use recipe::Recipe;

/// CyberChef CLI - A command-line implementation of CyberChef for data manipulation
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a single operation
    Op {
        /// Operation to execute
        #[arg(required = true)]
        operation: String,

        /// Operation arguments as key=value pairs
        #[arg(short, long)]
        args: Vec<String>,

        /// Input data as string
        #[arg(required_unless_present = "input_file")]
        input: Option<String>,

        /// Input from file
        #[arg(short, long)]
        input_file: Option<PathBuf>,

        /// Output to file
        #[arg(short, long)]
        output_file: Option<PathBuf>,
    },

    /// Run a chain of operations (recipe)
    Recipe {
        /// Recipe as operations separated by pipes: "op1 | op2 --arg=val | op3"
        #[arg(required_unless_present = "recipe_file")]
        recipe: Option<String>,

        /// Load recipe from file
        #[arg(short, long)]
        recipe_file: Option<PathBuf>,

        /// Save recipe to file
        #[arg(short, long)]
        save_recipe: Option<PathBuf>,

        /// Input data as string
        #[arg(required_unless_present = "input_file")]
        input: Option<String>,

        /// Input from file
        #[arg(short, long)]
        input_file: Option<PathBuf>,

        /// Output to file
        #[arg(short, long)]
        output_file: Option<PathBuf>,
    },

    /// List available operations
    List {
        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Op { operation, args, input, input_file, output_file } => {
            let input_data = get_input_data(input, input_file)?;
            let op = operations::get_operation(&operation, &args)?;
            let result = op.run(input_data)?;
            output_data(&result, output_file)?;
        },
        Commands::Recipe { recipe, recipe_file, save_recipe, input, input_file, output_file } => {
            let recipe_str = match (recipe, recipe_file) {
                (Some(r), _) => r,
                (_, Some(path)) => fs::read_to_string(path)
                    .with_context(|| format!("Failed to read recipe file: {:?}", path))?,
                _ => return Err(anyhow::anyhow!("Either recipe or recipe_file must be provided")),
            };

            let recipe = Recipe::parse(&recipe_str)?;
            
            if let Some(path) = save_recipe {
                let json = recipe.to_json()?;
                fs::write(path, json)
                    .with_context(|| format!("Failed to write recipe to file: {:?}", path))?;
            }

            let input_data = get_input_data(input, input_file)?;
            let result = recipe.run(input_data)?;
            output_data(&result, output_file)?;
        },
        Commands::List { category } => {
            operations::list_operations(category.as_deref())?;
        }
    }

    Ok(())
}

fn get_input_data(input: Option<String>, input_file: Option<PathBuf>) -> Result<Vec<u8>> {
    match (input, input_file) {
        (Some(text), _) => Ok(text.into_bytes()),
        (_, Some(path)) => fs::read(&path)
            .with_context(|| format!("Failed to read input file: {:?}", path)),
        (_, _) => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)
                .context("Failed to read from stdin")?;
            Ok(buffer)
        }
    }
}

fn output_data(data: &[u8], output_file: Option<PathBuf>) -> Result<()> {
    match output_file {
        Some(path) => fs::write(&path, data)
            .with_context(|| format!("Failed to write to output file: {:?}", path)),
        None => {
            // If data is valid UTF-8, print as string, otherwise print as hex
            match std::str::from_utf8(data) {
                Ok(text) => println!("{}", text),
                Err(_) => println!("{}", hex::encode(data)),
            }
            Ok(())
        }
    }
}
