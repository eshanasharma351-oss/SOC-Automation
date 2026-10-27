# IOC Checker

A simple Python CLI tool for offline SOC alert triage.

It detects IPv4 addresses, domains, and file hashes, compares them against a
local IOC watchlist, and exports the results to CSV.

## Objective

During alert investigation, SOC analysts often collect suspicious indicators
such as IP addresses, domains, and file hashes. This tool helps compare those
indicators with a local watchlist and produce a structured CSV result for
documentation or further investigation.

This is **Version 1**, an offline IOC checker. It does not query external
threat-intelligence APIs.

## Features

- Detects IPv4 addresses
- Detects domains
- Detects MD5, SHA-1, and SHA-256 file hashes
- Compares IOCs against a local watchlist
- Supports batch checking from a text file
- Exports results to CSV
- Handles invalid or unsupported input as `UNKNOWN`

## How it works

```text
Input IOC file
      ↓
Detect IOC type
      ↓
Normalize and validate input
      ↓
Compare with local watchlist
      ↓
Generate MATCH / NO_MATCH / UNKNOWN result
      ↓
Display results and export CSV
```

## Project structure

```text
ioc-checker/
├── ioc_checker.py
├── watchlist.csv
├── sample_iocs.txt
├── results.csv
├── README.md
├── .gitignore
└── screenshots/
    ├── 01-help-menu.png
    ├── 02-watchlist.png
    ├── 03-sample-iocs.png
    ├── 04-batch-check.png
    ├── 05-csv-output.png
```

## Requirements

- Python 3.8 or newer
- No external Python packages are required


Create and activate a virtual environment:

### Windows PowerShell

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## Usage

Create or edit `sample_iocs.txt` with one IOC per line:

```text
203.0.113.45
8.8.8.8
evil.example
example.com
44d88612fea8a8f36de82e1278abb02f
not-a-valid-ioc
```

Run the checker:

```bash
python ioc_checker.py --file sample_iocs.txt --watchlist watchlist.csv --output results.csv
```

### Command options

| Option | Description | Default |
|---|---|---|
| `--file` | Text file containing one IOC per line | Required |
| `--watchlist` | CSV file containing known IOCs | Required |
| `--output` | Output CSV file | `results.csv` |

## Watchlist format

The watchlist must be a CSV file with the following columns:

```csv
ioc,type,category,description
203.0.113.45,ipv4,malicious,Example C2 server
evil.example,domain,phishing,Example phishing domain
44d88612fea8a8f36de82e1278abb02f,md5,malicious,EICAR test hash
```

| Column | Description |
|---|---|
| `ioc` | The indicator to match |
| `type` | IOC type: `ipv4`, `domain`, `md5`, `sha1`, or `sha256` |
| `category` | Classification, such as `malicious` or `phishing` |
| `description` | Short context for the indicator |

## Example output

```text
IOC Check Results
----------------------------------------------------------------------
203.0.113.45 | ipv4 | MATCH | malicious | Example C2 server
8.8.8.8 | ipv4 | NO_MATCH |  |
evil.example | domain | MATCH | phishing | Example phishing domain
example.com | domain | NO_MATCH |  |
44d88612fea8a8f36de82e1278abb02f | md5 | MATCH | malicious | EICAR test hash
not-a-valid-ioc | unknown | UNKNOWN |  | Input is not a supported IPv4, domain, or hash IOC
----------------------------------------------------------------------
Total IOCs checked: 6
Results saved to: results.csv
```

## Result values

| Verdict | Meaning |
|---|---|
| `MATCH` | The IOC exists in the local watchlist |
| `NO_MATCH` | The IOC is valid but was not found in the watchlist |
| `UNKNOWN` | The input is not a supported IPv4, domain, or hash IOC |

## Evidence

### CLI help menu

![IOC Checker help menu](screenshots/01-help-menu.png)

### Local IOC watchlist

![Local IOC watchlist](screenshots/02-watchlist.png)

### Sample IOC input

![Sample IOC input file](screenshots/03-sample-iocs.png)

### Batch IOC check

![Batch IOC check output](screenshots/04-batch-check.png)

### CSV results

![CSV results output](screenshots/05-csv-output.png)


## Skills demonstrated

- IOC identification and classification
- SOC alert-triage workflow
- Local watchlist matching
- Python CLI development
- CSV reading and writing
- Input validation
- Basic error handling
- Git and GitHub documentation

## Limitations

- Performs exact matching only
- Does not perform external reputation checks
- Does not support VirusTotal or AbuseIPDB enrichment
- Does not automatically resolve subdomains or IP ranges
- Does not determine whether an unmatched IOC is safe
- A `NO_MATCH` result does not mean an IOC is clean

## Planned improvements

- VirusTotal enrichment for hashes, domains, URLs, and IP addresses
- AbuseIPDB enrichment for IP reputation
- `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, and `UNKNOWN` verdict logic
- JSON output for automation
- API response caching
- Rate-limit handling
- Unit tests with mocked API responses

## References

- [Python `argparse` documentation](https://docs.python.org/3/library/argparse.html) — used for command-line argument parsing.
- [Python `ipaddress` documentation](https://docs.python.org/3/library/ipaddress.html) — used for IPv4 address validation.
- [Python `csv` documentation](https://docs.python.org/3/library/csv.html) — used for reading the watchlist and writing CSV results.
- [VirusTotal API documentation](https://docs.virustotal.com/) — planned for future IOC enrichment.
- [AbuseIPDB API documentation](https://docs.abuseipdb.com/) — planned for future IP reputation enrichment.

