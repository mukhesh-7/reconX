import argparse
import requests
import sys
import csv
import json


def get_total_results(asset_name, api_key):
    """Fetch the total number of results for a given asset."""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': asset_name, 'resultsPerPage': 1}  # Fetch only one result to get totalResults
    headers = {'User-Agent': 'Mozilla/5.0', 'apiKey': api_key}
    response = requests.get(base_url, headers=headers, params=params)
    if response.status_code == 200:
        try:
            data = response.json()
            return data.get('totalResults', 0)
        except ValueError:
            print("Error decoding JSON from initial total results fetch.")
            return 0
    else:
        print(f"Failed to fetch total results: HTTP {response.status_code}", file=sys.stderr)
        return 0


def vector_string_human_readable(vector_string):
    # CVSS v3.x metrics mapping
    metrics_map = {
        'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
        'AC': {'L': 'Low', 'H': 'High'},
        'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
        'UI': {'N': 'None', 'R': 'Required'},
        'S': {'U': 'Unchanged', 'C': 'Changed'},
        'C': {'N': 'None', 'L': 'Low', 'H': 'High'},
        'I': {'N': 'None', 'L': 'Low', 'H': 'High'},
        'A': {'N': 'None', 'L': 'Low', 'H': 'High'},
    }
    parts = vector_string.split('/')
    readable = []
    for part in parts:
        if ':' not in part:
            continue
        key, val = part.split(':', 1)
        desc = metrics_map.get(key, {}).get(val, val)
        readable.append(f"{key}: {desc}")
    return ', '.join(readable)

def get_cvss_info(vulnerability):
    # Initialize default values for CVSS information
    base_score, cvss_version, base_severity, vector_string = 'Unknown', 'Unknown', 'Unknown', 'Unknown'

    # Try to extract CVSS information for each version
    for version_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        metric = vulnerability['cve']['metrics'].get(version_key)
        if metric:
            metric_data = metric[0]  # Assuming the first entry is the one we're interested in
            cvss_data = metric_data.get('cvssData')
            if cvss_data:
                base_score = cvss_data.get('baseScore', 'Unknown')
                vector_string = cvss_data.get('vectorString', 'Unknown')
                if vector_string.startswith("CVSS:"):
                    vector_string = vector_string.split('/', 1)[-1]  # Remove the CVSS version prefix
            base_severity = cvss_data.get('baseSeverity', 'Unknown')
            cvss_version = version_key[-3:].replace('c','').replace('31', '3.1').replace('30', '3.0').replace('2', '2.0')
            vector_string = vector_string.replace('Au', 'AU')
            break  # Exit the loop after finding the first available CVSS data
    # Convert vector string to human readable if possible
    human_vector = vector_string_human_readable(vector_string) if vector_string != 'Unknown' else 'Unknown'
    return base_score, cvss_version, base_severity, human_vector


def get_cves_for_asset(asset_name, api_key, score, results_per_asset, severity, vector):
    total_results = get_total_results(asset_name, api_key)
    if total_results == 0:
        return [], []

    # Calculate the start index for fetching the most recent CVEs
    last_page_start_index = max(0, total_results - results_per_asset)

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': asset_name, 'resultsPerPage': results_per_asset, 'startIndex': last_page_start_index}
    headers = {'User-Agent': 'Mozilla/5.0', 'apiKey': api_key}

    response = requests.get(base_url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Failed to query NVD API: HTTP {response.status_code}", file=sys.stderr)
        return [], []

    try:
        data = response.json()
    except ValueError as e:
        print(f"Error decoding JSON: {e}", file=sys.stderr)
        return [], []

    items = []
    structured_items = []  # For CSV/JSON output
    for vulnerability in data.get('vulnerabilities', []):
        cve_id = vulnerability['cve']['id']
        base_score, cvss_version, base_severity, human_vector = get_cvss_info(vulnerability)
        item_details = f"{cve_id}"
        details = []
        if score and base_score != 'Unknown':
            details.append(f"CVSS {cvss_version}: {base_score}")
        if severity and base_severity != 'Unknown':
            details.append(f"Severity: {base_severity}")
        if vector and human_vector != 'Unknown':
            # Split vector metrics into separate lines
            vector_lines = human_vector.split(', ')
            details.append("Vector:\n" + "\n".join(vector_lines))
        if details:
            item_details += "\n" + "\n".join(details)
        items.append(item_details)
        # Collect structured data for CSV/JSON
        structured_items.append({
            "asset": asset_name,
            "cve_id": cve_id,
            "cvss_version": cvss_version if score else "",
            "base_score": base_score if score else "",
            "base_severity": base_severity if severity else "",
            "vector": human_vector if vector else ""
        })
    items.sort(key=lambda item: item.split()[0], reverse=True)
    return items, structured_items

def read_assets_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Get CVEs for given assets using the NVD API.')
    parser.add_argument('-a', '--asset', help='Single asset to check for CVEs.')
    parser.add_argument('-A', '--asset_file', help='File containing a list of assets to check for CVEs.')
    parser.add_argument('-o', '--output_file',
                        help='File to write the CVEs output. If not specified, output will be printed to the console.')
    parser.add_argument('-k', '--api_key', required=True, help='NVD API key.')
    parser.add_argument('-s', '--score', action='store_true', help='Include CVSS scores in the output.')
    parser.add_argument('-rpa', '--results-per-asset', type=int, default=3, choices=range(1, 11),
                        help='Number of results per asset (default: 3, max: 10).')
    parser.add_argument('-sev', '--severity', action='store_true', help='Include CVSS base severity in the output.')
    parser.add_argument('-vec', '--vector', action='store_true',
                        help='Include CVSS vector string in the output, removing version prefix if present.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output including scores, severity, and vectors.')
    parser.add_argument('--csv_file', help='File to write the CVEs output in CSV format.')
    parser.add_argument('--json_file', help='File to write the CVEs output in JSON format.')

    args = parser.parse_args()

    if args.verbose:
        args.score = True
        args.severity = True
        args.vector = True

    assets = []
    if args.asset:
        assets.append(args.asset)
    if args.asset_file:
        assets.extend(read_assets_from_file(args.asset_file))

    output_lines = []
    all_structured_items = []
    for asset in assets:
        display_asset = asset.title()  # Capitalize each word of the asset name
        cves, structured_items = get_cves_for_asset(asset, args.api_key, args.score, args.results_per_asset, args.severity, args.vector)
        output_lines.append(f"{display_asset}:")
        # Add each CVE on a new line, with details formatted
        output_lines.extend([f"{cve}\n" for cve in cves])
        all_structured_items.extend(structured_items)

    if args.output_file:
        with open(args.output_file, 'w') as file:
            file.write("".join(output_lines))  # Already includes newlines
    else:
        for line in output_lines:
            print(line, end='')  # Avoid double newlines

    # Write CSV output if requested
    if args.csv_file:
        fieldnames = ["asset", "cve_id", "cvss_version", "base_score", "base_severity", "vector"]
        with open(args.csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in all_structured_items:
                writer.writerow(item)

    # Write JSON output if requested
    if args.json_file:
        with open(args.json_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(all_structured_items, jsonfile, indent=2)


if __name__ == "__main__":
    main()