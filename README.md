# RCE Payload Tester

**RCE Payload Tester** is a robust and versatile Python tool designed for security researchers to test URLs for Remote Code Execution (RCE) vulnerabilities using `qsreplace` and `gf`. It automates payload injection into URL parameters, extracts RCE-relevant parameters with `gf rce`, and generates comprehensive reports in JSON, CSV, and HTML formats. With features like concurrent testing, resume functionality, dynamic tool detection, vulnerability scoring, and detailed error handling, it’s optimized for large-scale reconnaissance and vulnerability testing.

## Usage

### Prerequisites
- **Install Dependencies**:
  - `qsreplace`: `npm install -g qsreplace`
  - `gf`: Install and configure RCE patterns (e.g., from `gf-patterns`)
  - Python packages: `pip install tqdm validators pyyaml`
- **Prepare Input**:
  - **URLs**: Create a file with one URL per line (e.g., `~/recon/example.com/urls.txt`), use a single URL with `--single-url`, or pipe URLs via stdin (`cat urls.txt | python rce_test_script.py`).
  - **Payloads**: Create a file with one payload per line (e.g., `~/recon/example.com/payloads.txt`), use a single payload with `--single-payload`, or rely on default payloads.
  - **Optional Config**: Create `rce_config.yaml` for default settings (e.g., tool paths, timeout).

### Running the Tool
The tool supports both command-line and interactive modes, with extensive customization options for flexibility and debugging.

#### Command-Line Mode
```bash
python rce_test_script.py [options]
```

**Options**:
- `--url-file <path>`: Path to file containing target URLs (e.g., `~/recon/example.com/urls.txt`).
- `--single-url <url>`: Test a single URL (e.g., `http://example.com/page?param=value`).
- `--payload-file <path>`: Path to file containing payloads (e.g., `~/recon/example.com/payloads.txt`).
- `--single-payload <payload>`: Test a single payload (e.g., `;id;`).
- `--qsreplace-path <path>`: Custom path to `qsreplace` executable (e.g., `/usr/local/bin/qsreplace`).
- `--gf-path <path>`: Custom path to `gf` executable (e.g., `/usr/local/bin/gf`).
- `--max-workers <int>`: Maximum concurrent workers (default: CPU count).
- `--timeout <int>`: Timeout for `qsreplace` in seconds (default: 30).
- `--retries <int>`: Number of retries for `qsreplace` (default: 2).
- `--quiet`: Suppress console output except errors.
- `--verbose`: Enable detailed console output.
- `--dry-run`: Simulate execution without running `qsreplace`.
- `--resume`: Resume from previous run using state file.

**Example**:
```bash
python rce_test_script.py --url-file ~/recon/example.com/urls.txt --payload-file ~/recon/example.com/payloads.txt --qsreplace-path /usr/local/bin/qsreplace --gf-path /usr/local/bin/gf --max-workers 10 --timeout 20 --verbose --resume
```

#### Interactive Mode
```bash
python rce_test_script.py
```
- Enter the URL file path (e.g., `~/recon/example.com/urls.txt`) or press Enter for stdin or `--single-url`.
- Enter the payload file path (e.g., `~/recon/example.com/payloads.txt`) or press Enter to use `payloads.txt` or embedded default payloads.

#### Piped Input
```bash
cat ~/recon/example.com/urls.txt | python rce_test_script.py --payload-file ~/recon/example.com/payloads.txt
```

#### Dry Run
```bash
python rce_test_script.py --url-file ~/recon/example.com/urls.txt --dry-run
```

### Output
- **RCE Parameters**: Extracted by `gf rce` and appended to `rce_all_params.txt`.
- **Results**: Saved in `rce_results_<domain>` directories with timestamped filenames (e.g., `rce_results_example.com/http_example.com_id_20250707_213000.txt`).
- **Summary**:
  - JSON: `rce_summary_YYYYMMDD_HHMMSS.json`
  - CSV: `rce_summary_YYYYMMDD_HHMMSS.csv`
  - HTML: `rce_summary_YYYYMMDD_HHMMSS.html` (styled report with vulnerability scores)
- **Compressed**: Results zipped into `rce_results_YYYYMMDD_HHMMSS.zip`.
- **State**: Processed URLs tracked in `rce_state.json` for resuming.
- **Log**: Detailed execution logs in `rce_test.log`.

### Notes
- Ensure `qsreplace` and `gf` are in PATH or specify their locations with `--qsreplace-path` or `--gf-path`. Alternatively, set environment variables `QSREPLACE_PATH` or `GF_PATH`.
- Verify file paths for URLs and payloads to avoid errors.
- Adjust `--max-workers`, `--timeout`, and `--retries` based on system and network conditions.
- Test responsibly on authorized targets only, ensuring compliance with legal and ethical guidelines.
