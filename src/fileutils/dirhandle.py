import os
from typing import List


def get_json_filenames(directory_path: str) -> List[str]:
    # List to store filenames without extension
    filenames_without_extension: List[str] = []

    # Iterate through all files in the given directory
    for filename in os.listdir(directory_path):
        # Check if the file has a .json extension
        if filename.endswith('.json'):
            # Remove the .json extension and add the filename to the list
            filenames_without_extension.append(os.path.splitext(filename)[0])

    return filenames_without_extension
