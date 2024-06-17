import json
import os
from typing import Optional

from pydantic import ValidationError

from ..fileutils import filehandle
from ..logging.logging import logger
from ..schemas.osv import OpenSourceVulnerability


def load_and_validate_json(file_path: str) -> Optional[OpenSourceVulnerability]:
    """
    Load and validate a JSON file against the Open Source Vulnerability schema.

    Parameters:
    file_path (str): The path to the JSON file to be validated.

    Returns:
    OpenSourceVulnerability: The validated Open Source Vulnerability object.

    Raises:
    json.JSONDecodeError: If there is an error decoding the JSON file.
    ValidationError: If the JSON data does not conform to the Open Source Vulnerability schema.
    """
    try:
        data = filehandle.read_json(file_path)
        vulnerability = OpenSourceVulnerability(**data)
        logger.info("Validation successful for %s", file_path)
        return vulnerability
    except json.JSONDecodeError as e:
        logger.error("Error decoding JSON in %s: %s", file_path, e)
        raise
    except ValidationError as e:
        logger.error("Validation error in %s: %s", file_path, e)
        raise


def validate_json_files_in_directory(directory: str):
    """
    Validate all JSON files in the specified directory that start with 'CVE-' and log any errors.

    Parameters:
    directory (str): The directory containing JSON files to be validated.

    Returns:
    None
    """
    error_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            try:
                if file.startswith("CVE-") and file.endswith(".json"):
                    file_path = os.path.join(root, file)
                    load_and_validate_json(file_path)
            except Exception as _:
                error_files.append(file)
    if error_files:
        logger.warning("Validation errors in files: %s", json.dumps(error_files))
