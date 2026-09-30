//! Settlement alert notifier.
//!
//! Reads notifier.toml, drains the alert queue and prints a coloured summary
//! for the on-call operator tailing the logs.

use ansi_term::Colour::{Green, Red, Yellow};

#[derive(Debug)]
enum Severity {
    Ok,
    Warning,
    Critical,
}

fn render(severity: &Severity, message: &str) -> String {
    match severity {
        Severity::Ok => Green.paint(message).to_string(),
        Severity::Warning => Yellow.paint(message).to_string(),
        Severity::Critical => Red.paint(message).to_string(),
    }
}

fn main() {
    println!("{}", render(&Severity::Ok, "notifier started"));
    println!("{}", render(&Severity::Warning, "settlement transfer retried"));
}
