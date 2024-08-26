import json
import os
import time

from dotenv import load_dotenv
import requests

from ..extract.nvddb import v2api
from ..fileutils import filehandle
from ..logging.logging import logger

MAX_ERRORS = 10


def main(input_json_path: str, output_dir: str, apikey: str, overwrite: bool):
    """
    Processes CVE IDs from an input JSON file, retrieves their details from the NVD database using an API,
    and writes the retrieved data to JSON files in the specified output directory.

    Parameters:
    input_json_path (str): The path to the input JSON file containing CVE IDs.
    output_dir (str): The directory where the output JSON files will be saved.
    apikey (str): The API key for accessing the NVD database.
    overwrite (bool): A flag indicating whether to overwrite existing files in the output directory.

    Returns:
    None
    """
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Read the input JSON file
    cve_entries = filehandle.read_json(input_json_path)

    # Initialize the list for errored CVE IDs
    errored_cveids = []
    ses = requests.Session()

    # Iterate over each CVE ID in the JSON file
    for cve_id in cve_entries.keys():
        if len(errored_cveids) > MAX_ERRORS:
            break
        output_file_path = os.path.join(output_dir, f"{cve_id}.json")
        if not overwrite and os.path.exists(output_file_path):
            continue
        try:
            cve_info = v2api.get_cve(cve_id, apikey, ses)
            if cve_info:
                filehandle.write_pydantic_to_json(output_file_path, cve_info)
                logger.info("Successfully wrote data for %s to %s", cve_id, output_file_path)
            else:
                logger.warning("No data found for %s", cve_id)
                errored_cveids.append(cve_id)

            # Sleep for a second between each call
            time.sleep(1)
        except Exception as e:
            logger.error("Got error in processing cve: %s. Error: %s", cve_id, e)
            errored_cveids.append(cve_id)

    # Log the errored CVE IDs
    if errored_cveids:
        logger.error("The following CVE IDs could not be processed:\n %s", json.dumps(errored_cveids))


# Entry point for the script. Loads environment variables from a .env file, and runs the main function with
# the provided parameters.
if __name__ == "__main__":
    load_dotenv(dotenv_path=".env")
    main(os.path.expanduser(os.getenv("PROCESS_NVD_CVE_JSON")), os.path.expanduser(os.getenv("NVD_DB_PATH")),
         os.getenv("NVD_API_KEY"), False)
