import argparse
import json
import os
from typing import Set

from dotenv import load_dotenv

from .extract.cvefixesdb import dblevel_query
from .extract.govulndb.govulndb import build_cve_index
from .extract.nvddb import fileparse as nvdfileparse
from .fileutils import filehandle
from .logging.logging import logger

MAX_PROCESS_ITEMS = 10000000
MAX_ERRORS = 10000


def get_cve_ids_to_process(cvefixes_db_path: str, govulndb_path: str) -> Set[str]:
    """
    Get CVE IDs to process by comparing CVE fixes database and GoVulnDB index.

    Args:
        cvefixes_db_path (str): Path to the CVE fixes database.
        govulndb_path (str): Path to the GoVulnDB.

    Returns:
        Set[str]: A set of CVE IDs that need to be processed.
    """
    govulndb_index = build_cve_index(govulndb_path)
    dblevel_query.ensure_indexes(cvefixes_db_path)

    cves_from_vulndb = {cve_id for cve_id, _ in govulndb_index.items()}
    cves_from_fixesdb, _ = dblevel_query.get_cve_ids_by_languages(cvefixes_db_path, ["go", "golang"])
    cves_from_fixesdb = set(cves_from_fixesdb)

    cve_ids = cves_from_fixesdb - cves_from_vulndb
    logger.info("Total CVE IDs found in CVE fixes are %s", len(cve_ids))
    return cve_ids


def process_all_cves(cvefixes_db_path: str, govulndb_path: str, outdata_path: str, nvddb_path: str, apikey: str,
                     overwrite: bool, ensure_nvd_data: bool) -> None:
    """
    Main function to process all CVEs.

    Args:
        cvefixes_db_path (str): Path to the CVE fixes database.
        govulndb_path (str): Path to the GoVulnDB.
        outdata_path (str): Path to the output data directory.
        nvddb_path (str): Path to the nvddb directory.
        apikey (str): The API key for NVD API.
        overwrite (bool): Flag to overwrite existing files.
        ensure_nvd_data (bool): Flag to ensure NVD data is fetched if not present.

    Returns:
        None
    """
    cve_ids = get_cve_ids_to_process(cvefixes_db_path, govulndb_path)
    # Save cveIDs
    filehandle.write_json(os.path.join(outdata_path, "cvefixes_only_index.json"), list(cve_ids))
    error_cve_ids = nvdfileparse.process_cve_ids(cve_ids, apikey, nvddb_path, overwrite, ensure_nvd_data,
                                                 MAX_PROCESS_ITEMS, MAX_ERRORS)

    if error_cve_ids:
        logger.info("Errored CVEs:\n%s", json.dumps(error_cve_ids, indent=2))


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Generate OSV data from CVE ID and database path.')
    parser.add_argument('--overwrite',
                        action='store_true',
                        default=False,
                        help='Overwrite existing files (default: False)')
    parser.add_argument('--ensurenvddata', action='store_true', default=False, help='Fetch NVD data if not present')
    return parser.parse_args()


def main() -> None:
    """
    Main function to parse command-line arguments and process CVEs.

    Returns:
        None
    """
    args = parse_arguments()
    process_all_cves(os.path.expanduser(os.getenv("CVEFIXES_DB_PATH")), os.path.expanduser(os.getenv("GOVULN_DB_PATH")),
                     os.path.expanduser(os.getenv("OUTDATA_PATH")), os.path.expanduser(os.getenv("NVD_DB_PATH")),
                     os.getenv("NVD_API_KEY"), args.overwrite, args.ensurenvddata)


if __name__ == "__main__":
    # python -m src.process_cvefixes_only --ensurenvddata > out/out.txt 2>&1
    load_dotenv(dotenv_path=".env")
    main()
