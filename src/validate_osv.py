import os
import sys

from .logging.logging import logger
from .schemautils.validate import validate_json_files_in_directory

if __name__ == "__main__":
    # Main entry point for the script. Takes a directory path as an argument, validates all JSON files
    # in the directory that start with 'CVE-', and logs any validation errors.

    # Usage:
    # python script.py <path_to_directory>

    # Exits with error code 1 if the provided path is not a directory or if the number of arguments is incorrect.
    if len(sys.argv) != 2:
        logger.error("Usage: python script.py <path_to_directory>")
        sys.exit(1)

    directory_path = sys.argv[1]

    if not os.path.isdir(directory_path):
        logger.error("The provided path %s is not a directory.", directory_path)
        sys.exit(1)

    validate_json_files_in_directory(directory_path)
