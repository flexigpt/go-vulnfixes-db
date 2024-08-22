import argparse
from collections import defaultdict
import csv


# Function to process the CSV and create the desired dictionary
def create_dict_from_csv(fpath):
    # Initialize a defaultdict of lists
    functional_area_dict = defaultdict(list)

    # Open and read the CSV file
    with open(fpath, mode='r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)

        # Iterate over each row in the CSV
        for row in csv_reader:
            # Extract relevant fields
            cwe_id = row['CWE-ID']
            name = row['Name']
            functional_areas = row['Functional Areas'].split(';')  # Assuming multiple areas are separated by semicolon

            # Populate the dictionary
            for area in functional_areas:
                functional_area_dict[area.strip()].append({'CWE-ID': cwe_id, 'Name': name})

    # Convert defaultdict to a regular dict
    return dict(functional_area_dict)


# Main execution
if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(
        description="Process a CSV file and create a dictionary based on Functional Areas."
    )
    parser.add_argument('file_path', type=str, help="The path to the CSV file to process.")

    # Parse the arguments
    args = parser.parse_args()

    # Create the dictionary from the CSV
    result_dict = create_dict_from_csv(args.file_path)

    # Print the resulting dictionary
    print(f"FUNCTIONAL_AREAS = {result_dict}")
