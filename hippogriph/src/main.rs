// use aes::demo_aes;
use clap::Parser;
use clear_aes::demo_clear_aes;
use encrypted_aes::demo_encrypted_aes;

// mod aes;
mod clear_aes;
mod encrypted_aes;



#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    number_of_outputs: usize,

    #[clap(long)]
    iv: String,

    #[clap(long)]
    key: String,
}


fn main() {
    let args = Cli::parse();

    // Print the parsed arguments (for demonstration)
    println!("Number of Outputs: {}", args.number_of_outputs);
    println!("IV: {}", args.iv);
    println!("Key:{}", args.key);

    let ciphertexts_conventional = demo_clear_aes(args.number_of_outputs, &args.iv, &args.key);

    demo_encrypted_aes(args.number_of_outputs, &args.iv, &args.key, ciphertexts_conventional);
}
