import os
import time
import traceback
from typing import List, Optional, Set

from pydantic import ValidationError
import requests

from . import v2api
from ...fileutils import filehandle
from ...logging.logging import logger
from ...schemas import nvd


def get_cve_from_file(cve_id: str, nvddb_path: str) -> Optional[nvd.CVEItem]:
    try:
        data = filehandle.read_json(os.path.join(nvddb_path, cve_id + ".json"))
        return nvd.CVEItem.model_validate(data)
    except ValidationError as e:
        logger.error("Validation failed for json file: %s", e)

    return None


def fetch_and_save_cve_data(cve_id: str, apikey: str, session: requests.Session, outdata_path: str,
                            overwrite: bool) -> Optional[str]:
    """
    Fetch CVE data from NVD API and save to a JSON file.

    Args:
        cve_id (str): The CVE ID to fetch data for.
        apikey (str): The API key for NVD API.
        session (requests.Session): The requests session object.
        outdata_path (str): The path to the output data directory.
        overwrite (bool): Flag to overwrite existing files.

    Returns:
        Optional[str]: The CVE ID if there was an error, otherwise None.
    """
    output_file_path = os.path.join(outdata_path, f"{cve_id}.json")
    if not overwrite and os.path.exists(output_file_path):
        logger.info("Skipping CVE: %s as it already exists and overwrite is disabled", cve_id)
        return None
    # Sleep for a second before each call
    time.sleep(1)
    try:
        cve_info = v2api.get_cve(cve_id, apikey, session)
        if cve_info:
            filehandle.write_pydantic_to_json(output_file_path, cve_info)
            logger.info("Successfully wrote data for %s to %s", cve_id, output_file_path)
            return None
        else:
            logger.warning("No data found for %s", cve_id)
            return cve_id
    except Exception as e:
        logger.error("Got error in processing CVE: %s. Error: %s", cve_id, e)
        traceback.print_exc()
        return cve_id


def process_cve_ids(cve_ids: Set[str], apikey: str, outdata_path: str, overwrite: bool, ensure_nvd_data: bool,
                    max_process_items: int, max_errors: int) -> List[str]:
    """
    Process a set of CVE IDs, fetching their data from the NVD API and saving it.

    Args:
        cve_ids (Set[str]): A set of CVE IDs to process.
        apikey (str): The API key for NVD API.
        outdata_path (str): The path to the output data directory.
        overwrite (bool): Flag to overwrite existing files.
        ensure_nvd_data (bool): Flag to ensure NVD data is fetched if not present.

    Returns:
        List[str]: A list of CVE IDs that encountered errors.
    """
    if not ensure_nvd_data:
        return []

    session = requests.Session()
    os.makedirs(outdata_path, exist_ok=True)

    error_cve_ids = []
    processed = 0

    for cve_id in cve_ids:
        error_cve_id = fetch_and_save_cve_data(cve_id, apikey, session, outdata_path, overwrite)
        if error_cve_id:
            error_cve_ids.append(error_cve_id)
            if len(error_cve_ids) >= max_errors:
                break

        processed += 1
        if processed >= max_process_items:
            break

    logger.info("Processed files count: %s", processed)
    return error_cve_ids
