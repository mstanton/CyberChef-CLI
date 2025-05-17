use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Recipe to execute (JSON format)
    #[arg(short, long)]
    pub recipe: Option<String>,

    /// Input file (defaults to stdin)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// List available operations
    #[arg(short, long)]
    pub list_operations: bool,

    /// Show help for a specific operation
    #[arg(short, long)]
    pub operation_help: Option<String>,
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }

    pub fn read_input(&self) -> Result<Vec<u8>> {
        use std::io::Read;
        
        let mut data = Vec::new();
        
        if let Some(input_path) = &self.input {
            let mut file = std::fs::File::open(input_path)?;
            file.read_to_end(&mut data)?;
        } else {
            std::io::stdin().read_to_end(&mut data)?;
        }
        
        Ok(data)
    }

    pub fn write_output(&self, data: &[u8]) -> Result<()> {
        use std::io::Write;
        
        if let Some(output_path) = &self.output {
            let mut file = std::fs::File::create(output_path)?;
            file.write_all(data)?;
        } else {
            std::io::stdout().write_all(data)?;
        }
        
        Ok(())
    }
} 