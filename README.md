# SOC Automation Scripts

A collection of Python scripts developed to automate basic security operations tasks, including IOC checking, file integrity monitoring, log analysis, and security alert analysis.

These scripts are built for learning and practicing SOC Analyst skills through small, practical security automation projects.

## Scripts

### 1. IOC Checker
Checks indicators of compromise (IOCs), such as IP addresses, domains, URLs, and file hashes, against a defined list of known indicators.

**Key concepts:**
- Indicators of Compromise (IOCs)
- Threat intelligence fundamentals
- Matching and identifying suspicious indicators

### 2. File Integrity Monitoring (FIM) Script
Monitors files by calculating cryptographic hashes and comparing them with previously recorded values to identify potential file modifications.

**Key concepts:**
- File integrity monitoring
- Hashing using SHA-256
- Detecting file changes

### 3. Log Parser
Processes log files to extract relevant security events and identify patterns such as failed login attempts and suspicious activity.

**Key concepts:**
- Log analysis
- Python file handling
- Filtering and extracting security events

### 4. Alert Analyzer
Analyzes security alerts using predefined rules and conditions to help categorize events and identify potentially suspicious activity.

**Key concepts:**
- Alert triage
- Basic detection logic
- False-positive analysis
- Security event prioritization

## Technologies Used

- Python
- File handling and text processing
- JSON and CSV (where applicable)
- SHA-256 hashing
- Basic detection and analysis logic

## Project Structure

```text
SOC-Automation/
└── Scripts/
    ├── IOC-Checker/
    ├── FIM-Script/
    ├── Log-Parser/
    └── Alert-Analyzer/
```

Each script has its own directory containing the source code, documentation, and sample inputs or outputs where applicable.

## Learning Objectives

- Automate repetitive SOC tasks using Python.
- Develop practical log analysis and alert triage skills.
- Understand file integrity monitoring and IOC matching.
- Build foundational security automation tools.
- Document findings and demonstrate practical cybersecurity skills.

## Disclaimer

These scripts are intended for educational purposes and authorized security testing. They use basic detection logic and should not be considered replacements for enterprise security tools or professional threat intelligence platforms.

## Status

This repository is a work in progress. Features, detection logic, and documentation will be updated as the tools develop.
## Future Additions

- **IOC Checker:** Add threat intelligence API integration and support for more IOC types.
- **FIM Script:** Generate alerts when monitored files are created, modified, or deleted.
- **Log Parser:** Support multiple log formats and detect repeated failed login attempts.
- **Alert Analyzer:** Add severity-based classification, MITRE ATT&CK mapping, and improved false-positive analysis.
- **Reporting:** Generate automated investigation reports in CSV or JSON format.
- **Testing:** Add sample logs, test cases, and documented evidence for each script.
