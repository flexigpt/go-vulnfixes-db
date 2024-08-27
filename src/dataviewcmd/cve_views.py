import argparse
import json
import os
from typing import Dict, List, Tuple

import tiktoken

from ..fileutils import filehandle
from ..schemas import fixes


def get_tokens_from_string(model_name: str, input_str: str) -> int:
    tokenizer = tiktoken.encoding_for_model(model_name).encode
    return len(tokenizer(input_str))


def get_token_data(cveinfo_unified_path: str, fixes_relative_path: str) -> Tuple[Dict, Dict]:
    fixes_path = os.path.join(cveinfo_unified_path, fixes_relative_path)
    if not os.path.exists(fixes_path):
        return {}, {}

    fixes_data = filehandle.read_json_zip(fixes_path)
    fixes_object = fixes.CVEFixes.model_validate(fixes_data)

    if not fixes_object.changes:
        return {}, {}
    token_counts = {}
    for change in fixes_object.changes:
        file_token_counts = {}
        if change.diff:
            file_token_counts["diff_c100"] = get_tokens_from_string("gpt-4", change.diff)
            file_token_counts["diff_o200"] = get_tokens_from_string("gpt-4o", change.diff)
        if change.code_after:
            file_token_counts["after_c100"] = get_tokens_from_string("gpt-4", change.code_after)
            file_token_counts["after_o200"] = get_tokens_from_string("gpt-4o", change.code_after)
        if change.code_before:
            file_token_counts["before_c100"] = get_tokens_from_string("gpt-4", change.code_before)
            file_token_counts["before_o200"] = get_tokens_from_string("gpt-4o", change.code_before)
        if file_token_counts:
            token_counts[change.filename] = file_token_counts

    all_token_counts = {}
    all_token_counts["all_diff_c100_tokens"] = sum(
        file_token_counts.get("diff_c100", 0) for file_token_counts in token_counts.values())
    all_token_counts["all_diff_o200_tokens"] = sum(
        file_token_counts.get("diff_o200", 0) for file_token_counts in token_counts.values())
    all_token_counts["all_after_c100_tokens"] = sum(
        file_token_counts.get("after_c100", 0) for file_token_counts in token_counts.values())
    all_token_counts["all_after_o200_tokens"] = sum(
        file_token_counts.get("after_o200", 0) for file_token_counts in token_counts.values())
    all_token_counts["all_before_c100_tokens"] = sum(
        file_token_counts.get("before_c100", 0) for file_token_counts in token_counts.values())
    all_token_counts["all_before_o200_tokens"] = sum(
        file_token_counts.get("before_o200", 0) for file_token_counts in token_counts.values())

    return token_counts, all_token_counts


def generate_cve_structure(cve: str, cwe: str) -> Dict:
    cve_info = {}
    cve_info["cveinfo"] = f"data/go-cves/{cve}.json"
    cve_info["fixes"] = f"data/go-fixes/{cve}_fixes.json.gz"
    cve_info["cwe_id"] = cwe
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.abspath(os.path.join(script_dir, "../../"))
    token_counts, all_token_counts = get_token_data(parent_dir, cve_info["fixes"])
    if token_counts:
        cve_info["token_counts_per_file"] = token_counts
    if all_token_counts:
        cve_info["token_counts_all"] = all_token_counts
    return cve_info


def get_cve_details_struct(data: Dict[str, List]) -> Dict:
    cve_details = {}
    for cwe_id, cves in data.items():
        for cveinfo in cves:
            cve_id = cveinfo['cve_id']
            cve_details[cve_id] = generate_cve_structure(cve_id, cwe_id)

    return cve_details


# Get CVE details using CWE CVE mappings
def get_cve_details_using_cwe(file_path: str, include_noinfo_cves=False, only_one_cve=False) -> Dict:
    data = filehandle.read_json(file_path)
    if not include_noinfo_cves:
        data = {cwe: cves for cwe, cves in data.items() if cwe != "NVD-CWE-noinfo"}
    if only_one_cve:
        data = {cwe: [cves[0]] for cwe, cves in data.items()}

    return get_cve_details_struct(data)


# Function to get selected CVEs based on a list of input CWE IDs
def get_selected_cve_details_using_cweids(file_path: str, cwe_ids: List[str], only_one_cve=False) -> Dict:
    data = filehandle.read_json(file_path)
    selected_cwe_cve = {cwe: cves for cwe, cves in data.items() if cwe in cwe_ids}
    if only_one_cve:
        selected_cwe_cve = {cwe: [cves[0]] for cwe, cves in data.items() if cwe in cwe_ids}

    return get_cve_details_struct(selected_cwe_cve)


def main():
    parser = argparse.ArgumentParser(description="Process a CWE to CVE JSON file.")
    parser.add_argument('index_path', type=str, help="The path to the JSON CWE to CVE index file.")
    parser.add_argument('--output-path', type=str, help="The path to the output the view.", default="")
    parser.add_argument('--selected-cves-path',
                        type=str,
                        default="",
                        help="Path to a JSON file that provides a list of CWEs to process.")
    parser.add_argument('--per-cwe-one', action='store_true', help="If set, only one CVE per CWE will be returned.")
    parser.add_argument('--include-noinfo',
                        action='store_true',
                        help="If set, CVEs associated with 'NVD-CWE-noinfo' will also be returned.")

    args = parser.parse_args()
    expanded_index_path = os.path.abspath(os.path.expanduser(args.index_path))
    output = {}
    if args.selected_cves_path:
        expanded_selection_path = os.path.abspath(os.path.expanduser(args.selected_cves_path))
        selected_cwe_ids = filehandle.read_json(expanded_selection_path)
        output = get_selected_cve_details_using_cweids(expanded_index_path, selected_cwe_ids, args.per_cwe_one)
    else:
        output = get_cve_details_using_cwe(expanded_index_path,
                                           include_noinfo_cves=args.include_noinfo,
                                           only_one_cve=args.per_cwe_one)
    if args.output_path:
        p = os.path.abspath(os.path.expanduser(args.output_path))
        filehandle.write_json(p, output)
    else:
        print(json.dumps(output, indent=2, ensure_ascii=False))


# Main execution
if __name__ == "__main__":
    # Set up argument parsing
    # Get all CVEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --include-noinfo --output-path ./data/views/all_cwes_all_cves.json
    # Get one CVE per CWE:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --per-cwe-one --output-path ./data/views/all_cwes_one_cve.json
    # Get all CVEs for top 25 CWEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --selected-cves-path ./data/cwe-699/cwe_top25_2023.json --output-path ./data/views/top25cwe_2023_all_cves.json
    # Get one CVE for top 25 CWEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --selected-cves-path ./data/cwe-699/cwe_top25_2023.json --per-cwe-one --output-path ./data/views/top25cwe_2023_one_cve.json
    # Get all CVEs for top 10 CWEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --selected-cves-path ./data/cwe-699/cwe_top10_cisa_kev.json --output-path ./data/views/top10cwe_cisa_kev_all_cves.json
    # Get one CVE for top 10 CWEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --selected-cves-path ./data/cwe-699/cwe_top10_cisa_kev.json --per-cwe-one --output-path ./data/views/top10cwe_cisa_kev_one_cve.json
    # Get all CVEs for top 25 stubborn CWEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --selected-cves-path ./data/cwe-699/cwe_top25_2023_stubborn.json --output-path ./data/views/top25cwe_2023_stubborn_all_cves.json
    # Get one CVE for top 25 stubborn CWEs:
    #   python -m src.dataviewcmd.cve_views ./data/all_cwe_to_cveinfo_index.json --selected-cves-path ./data/cwe-699/cwe_top25_2023_stubborn.json --per-cwe-one --output-path ./data/views/top25cwe_2023_stubborn_one_cve.json

    main()
