import argparse
import csv


# Function to process the CSV and create the desired dictionary
def create_dict_from_csv(fpath):
    functional_area_dict = {}

    # Open and read the CSV file
    with open(fpath, mode='r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)

        # Iterate over each row in the CSV
        for row in csv_reader:
            # Extract relevant fields
            cwe_id = row['CWE-ID'].strip()
            name = row['Name'].strip()
            primary_functional_area = row['Primary Functional Area'].strip()
            if primary_functional_area == "Software Architecture and Design":
                continue
            secondary_functional_area = row['Secondary Functional Area'].strip()
            cwe_category = row['CWE Category'].strip()
            cwe_category_id = row['CWE Category ID'].strip()
            if primary_functional_area not in functional_area_dict:
                functional_area_dict[primary_functional_area] = {}
            if secondary_functional_area not in functional_area_dict[primary_functional_area]:
                functional_area_dict[primary_functional_area][secondary_functional_area] = []
            functional_area_dict[primary_functional_area][secondary_functional_area].append(
                {
                    'CWE-ID': cwe_id,
                    'Name': name,
                    'CWE-Category': cwe_category,
                    'CWE-Category-ID': cwe_category_id
                }
            )

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
    print(f"CWE_FUNCTIONAL_AREAS = {result_dict}")
