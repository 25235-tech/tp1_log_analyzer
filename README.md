<<<<<<< HEAD
# tp1_log_analyzer
A command-line tool that reads a Linux SSH authentication log file and produces a summary of suspicious login activity. It counts failed login attempts by source IP address and by targeted username, while safely ignoring accepted logins and malformed lines.
=======
# TP1 – Secure Log Analyzer in Rust

## Objective

A command-line tool that reads a Linux SSH authentication log file and produces
a summary of suspicious login activity. It counts failed login attempts by source
IP address and by targeted username, while safely ignoring accepted logins and
malformed lines.

Log analysis is a core technique in defensive security: it allows detection of
brute-force attacks and credential-stuffing campaigns before they succeed.

## Environment requirements

- Docker and Docker Compose installed on the host
- The provided `docker-compose.yml` for the Rust labs

## Build and run inside Docker

```bash
# Start the container
mkdir -p workspace
docker compose up -d --build
docker compose exec rustlab bash

# Inside the container
cd /workspace/tp1_log_analyzer

# Build
cargo build

# Run
cargo run -- samples/auth_sample.log

# With bonus flag
cargo run -- samples/auth_sample.log --top 3
```

## Test

```bash
cargo test
```

## Lint and format

```bash
cargo clippy -- -D warnings
cargo fmt --check
```


>>>>>>> f697ecf (Initial Rust project)
