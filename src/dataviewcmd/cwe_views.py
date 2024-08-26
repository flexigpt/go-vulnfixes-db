import argparse
import json
from typing import Dict, List

from ..fileutils import filehandle


# Function to get unique tuples of first-level and second-level keys
def get_unique_functional_category_tuples(file_path: str) -> List:
    data = get_all_cwe_details(file_path)
    unique_tuples = []

    for first_level_key, second_level_dict in data.items():
        for second_level_key in second_level_dict.keys():
            unique_tuples.append((first_level_key, second_level_key))

    return unique_tuples


def get_all_cwe_details(file_path: str) -> Dict:
    data = dict(filehandle.read_json(file_path))
    # print(data)
    return data


# Main execution
if __name__ == "__main__":
    # python -m src.dataviewcmd.cwe_views ./data/cwe-699/cwe_functional_areas.json
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Process a JSON file and extract unique tuples.")
    parser.add_argument('file_path', type=str, help="The path to the JSON file to process.")

    # Parse the arguments
    args = parser.parse_args()

    # Get and print unique tuples
    print(
        f"Unique Tuples: {json.dumps(get_unique_functional_category_tuples(args.file_path), indent=2, ensure_ascii=False)}"
    )
