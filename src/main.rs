mod parser;
mod stats;

use parser::{FailedLogin, ParseOutcome, parse_line};
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo run -- <log_file> [--top N]");
        process::exit(1);
    }

    let file_path = &args[1];

    let mut top_n: Option<usize> = None;
    if args.len() >= 4 && args[2] == "--top" {
        match args[3].parse::<usize>() {
            Ok(value) if value > 0 => {
                top_n = Some(value);
            }
            _ => {
                eprintln!("Invalid value for --top. Use a positive integer.");
                process::exit(1);
            }
        }
    }

    let content = match fs::read_to_string(file_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", file_path, err);
            process::exit(1);
        }
    };

    let mut failed_events: Vec<FailedLogin> = Vec::new();
    let mut malformed_or_ignored: usize = 0;
    let mut total_lines: usize = 0;

    for line in content.lines() {
        total_lines += 1;
        match parse_line(line) {
            ParseOutcome::Failed(event) => {
                failed_events.push(event);
            }
            ParseOutcome::Ignored | ParseOutcome::Malformed => {
                malformed_or_ignored += 1;
            }
        }
    }

    let ip_stats = stats::count_by_ip(&failed_events);
    let user_stats = stats::count_by_user(&failed_events);

    println!("TP1 Secure Log Analyzer");
    println!("Input file: {}", file_path);
    if let Some(n) = top_n {
        println!("Displaying top {} results", n);
    }

    println!("\nSummary:");
    println!("  - Total lines read:           {}", total_lines);
    println!("  - Failed login events:        {}", failed_events.len());
    println!("  - Ignored or malformed lines: {}", malformed_or_ignored);

    println!("\nTop source IPs:");
    let ip_limit = top_n.unwrap_or(ip_stats.len());
    for (i, (ip, count)) in ip_stats.iter().take(ip_limit).enumerate() {
        let word = if *count == 1 { "attempt" } else { "attempts" };
        println!("  {}. {} -> {} failed {}", i + 1, ip, count, word);
    }

    println!("\nTop targeted users:");
    let user_limit = top_n.unwrap_or(user_stats.len());
    for (i, (user, count)) in user_stats.iter().take(user_limit).enumerate() {
        let word = if *count == 1 { "attempt" } else { "attempts" };
        println!("  {}. {} -> {} failed {}", i + 1, user, count, word);
    }
}
