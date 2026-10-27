import argparse
import csv
import ipaddress
import re
import sys
from pathlib import Path


HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)"
    r"[A-Za-z0-9-]{1,63}"
    r"(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63})*"
    r"\.[A-Za-z]{2,63}$"
)


def detect_ioc_type(value: str) -> str:
    value = value.strip().lower()

    try:
        ipaddress.IPv4Address(value)
        return "ipv4"
    except ValueError:
        pass

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(value):
            return hash_type

    if DOMAIN_PATTERN.fullmatch(value):
        return "domain"

    return "unknown"


def load_watchlist(path: str) -> dict:
    watchlist = {}

    csv_path = Path(path)

    if not csv_path.exists():
        raise FileNotFoundError(f"Watchlist file not found: {path}")

    with csv_path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_columns = {"ioc", "type", "category", "description"}

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError(
                "Watchlist must contain columns: ioc, type, category, description"
            )

        for row in reader:
            ioc = row["ioc"].strip().lower()

            if ioc:
                watchlist[ioc] = {
                    "type": row["type"].strip().lower(),
                    "category": row["category"].strip(),
                    "description": row["description"].strip(),
                }

    return watchlist


def load_iocs(path: str) -> list:
    iocs = []
    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(f"IOC input file not found: {path}")

    with input_path.open(encoding="utf-8") as file:
        for line in file:
            ioc = line.strip()

            if ioc and ioc not in iocs:
                iocs.append(ioc)

    return iocs


def check_ioc(ioc: str, watchlist: dict) -> dict:
    ioc_type = detect_ioc_type(ioc)
    normalized_ioc = ioc.strip().lower()
    match = watchlist.get(normalized_ioc)

    if match:
        verdict = "MATCH"
        category = match["category"]
        description = match["description"]

    elif ioc_type == "unknown":
        verdict = "UNKNOWN"
        category = ""
        description = "Input is not a supported IPv4, domain, or hash IOC"

    else:
        verdict = "NO_MATCH"
        category = ""
        description = ""

    return {
        "ioc": ioc,
        "type": ioc_type,
        "verdict": verdict,
        "category": category,
        "description": description,
    }


def export_results(results: list, output_path: str) -> None:
    fieldnames = ["ioc", "type", "verdict", "category", "description"]

    with Path(output_path).open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_results(results: list) -> None:
    print("\nIOC Check Results")
    print("-" * 70)

    for result in results:
        print(
            f"{result['ioc']} | {result['type']} | {result['verdict']}"
            f" | {result['category']} | {result['description']}"
        )

    print("-" * 70)
    print(f"Total IOCs checked: {len(results)}")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Offline IOC checker for SOC alert triage"
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Text file containing one IOC per line",
    )

    parser.add_argument(
        "--watchlist",
        required=True,
        help="CSV file containing known IOCs",
    )

    parser.add_argument(
        "--output",
        default="results.csv",
        help="Output CSV file (default: results.csv)",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    try:
        watchlist = load_watchlist(args.watchlist)
        iocs = load_iocs(args.file)

        if not iocs:
            print("No IOCs found in the input file.")
            sys.exit(1)

        results = [check_ioc(ioc, watchlist) for ioc in iocs]

        print_results(results)
        export_results(results, args.output)

        print(f"Results saved to: {args.output}")

    except (FileNotFoundError, ValueError) as error:
        print(f"Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()