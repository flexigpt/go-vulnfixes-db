import argparse
from collections import Counter
import json
import os
import traceback
from typing import Any, Dict, List

from dotenv import load_dotenv

from ..extract.cvefixesdb import dblevel_query
from ..extract.cvefixesdb import single_cvedata_query
from ..extract.cvefixesdb import single_cvefiledata_query
from ..extract.govulndb.govulndb import build_cve_index
from ..fileutils import filehandle
from ..logging.logging import logger
from ..schemautils.osvhandler import merge_refs

MAX_PROCESS_ITEMS = 10000000
MAX_ERRORS = 10000


def add_govuln_data(cve_id: str, osv_schema: Dict[str, Any], govulndb_index: Dict[str, Dict[str, Any]]) -> None:
    """
    Adds data from the GoVulnDB to the OSV schema based on a given CVE ID.

    Parameters:
    cve_id (str): The CVE ID to look up in the GoVulndb index.
    osv_schema (dict): The OSV schema to which the GoVulnDB data will be added.
    govulndb_index (dict): The GoVulnDB index containing the mapping from CVE IDs to their data.

    Returns:
    None
    """
    if cve_id not in govulndb_index:
        # logger.info("Couldn't find %s in GoVulnDB", cve_id)
        return

    govulndb_data = govulndb_index[cve_id]
    osv_schema["aliases"] = govulndb_data.get("aliases", [])

    govulndb_id_data = filehandle.read_json(govulndb_data["id_file_path"])

    # Append summary
    osv_schema["summary"] = f"{osv_schema['summary']}. {govulndb_id_data['summary']}"
    # Append details
    osv_schema[
        "details"] = f"CVEFixes details: {osv_schema['details']}. GoVulnDB details: {govulndb_id_data['details']}"
    # Extend database specific fields
    osv_schema["database_specific"]["govulndb"] = govulndb_id_data.get("database_specific", {})
    # Extend credits
    osv_schema["credits"].extend(govulndb_id_data.get("credits", []))
    # Create a merged ref object
    osv_schema["references"] = merge_refs(osv_schema["references"], govulndb_id_data["references"])
    # Overwrite affected
    osv_schema["affected"] = govulndb_id_data["affected"]

    # Extend severity if present
    if "severity" in govulndb_id_data:
        osv_schema["affected"].extend(govulndb_id_data["severity"])


def process_cve(cve_id: str, cvefixes_db_path: str, govulndb_index: Dict[str, Dict[str, Any]], outdata_path: str,
                overwrite: bool):
    """
    Processes a CVE ID to generate an OSV schema JSON file.

    Parameters:
    cve_id (str): The CVE ID to process.
    cvefixes_db_path (str): The path to the SQLite database file containing CVE data.
    govulndb_index (str): The index for go vulndb.
    outdata_path (str): The path to the directory where the output JSON file should be saved.

    Returns:
    None
    """
    logger.info("Started processing for %s, %s, %s", cve_id, cvefixes_db_path, outdata_path)

    # Query the database for all relevant data
    data = single_cvedata_query.get_cve_data_from_db(cve_id, cvefixes_db_path)
    if not data:
        logger.info("No data found for CVE ID %s", cve_id)
        return
    # logger.info(f"Got CVE data from query: {json.dumps(data[0], indent=2)}")
    # Convert the first item in data to OSV schema
    osv_schema = single_cvedata_query.convert_to_osv(data)

    # Add GoVulnDB data to the OSV schema
    add_govuln_data(cve_id, osv_schema, govulndb_index)

    logger.info("Successfully processed and saved data for CVE ID %s", cve_id)

    fchanges_schema = single_cvefiledata_query.get_fixes_by_cve(cvefixes_db_path, cve_id)
    fchanges = fchanges_schema.model_dump(exclude_none=True)
    most_common_language = "unknown"
    programming_languages = [fc["fc_programming_language"].lower() for fc in fchanges]
    # Count the occurrences of each programming language
    language_counter = Counter(programming_languages)
    most_common = language_counter.most_common(1)
    if most_common:
        # Find the programming language with the maximum count
        most_common_language = language_counter.most_common(1)[0][0]

    language_dir = os.path.join(outdata_path, most_common_language)
    # Create the directory if it doesn't exist
    os.makedirs(language_dir, exist_ok=True)

    # Paths for the output files
    out_cveosv_path = os.path.join(language_dir, f"{cve_id}.json")
    out_cveosv_path = filehandle.get_unique_filepath(out_cveosv_path, overwrite)
    filehandle.write_json(out_cveosv_path, osv_schema)

    out_cve_file_change_path = os.path.join(language_dir, f"{cve_id}_filechanges.json")
    out_cve_file_change_path = filehandle.get_unique_filepath(out_cve_file_change_path, overwrite)
    filehandle.write_json(out_cve_file_change_path, fchanges)


def process_all_cves(cvefixes_db_path: str,
                     govulndb: str,
                     outdata_path: str,
                     overwrite: bool,
                     cve_list: List[int] = None):
    # Build the CVE index from the GoVulnDB
    govulndb_index = build_cve_index(govulndb)
    dblevel_query.ensure_indexes(cvefixes_db_path)
    cve_ids = []
    error_cve_ids = []
    if cve_list:
        cve_ids = cve_list
    else:
        cve_ids = dblevel_query.get_all_cve_ids(cvefixes_db_path)

    logger.info("Total cve ids found are %s", len(cve_ids))

    processed = 0
    for cve_id in cve_ids:
        try:
            process_cve(cve_id, cvefixes_db_path, govulndb_index, outdata_path, overwrite)
        except Exception as e:
            logger.error("An exception occured: %s", e)
            traceback.print_exc()
            error_cve_ids.append(cve_id)
            if len(error_cve_ids) >= MAX_ERRORS:
                break

        processed += 1
        if processed >= MAX_PROCESS_ITEMS:
            break

    logger.info("Processed files count: %s", processed)
    logger.info("Errored cves:\n%s", json.dumps(error_cve_ids, indent=2))


def main() -> None:
    """
    Main function to parse command-line arguments and process CVEs.

    Returns:
    None
    """
    parser = argparse.ArgumentParser(description='Generate OSV data from CVE ID and database path.')

    parser.add_argument('--cve_id', type=str, help='The CVE ID to query (if provided, only this CVE will be processed)')
    parser.add_argument('--processall', action='store_true', help='Process all CVEs (if provided, --cve_id is ignored)')
    parser.add_argument('--overwrite',
                        action='store_true',
                        default=False,
                        help='Overwrite existing files (default: False)')

    args = parser.parse_args()
    cve_list = []
    if args.cve_id:
        cve_list.append(args.cve_id)
    if args.processall or args.cve_id:
        process_all_cves(os.path.expanduser(os.getenv("CVEFIXES_DB_PATH")),
                         os.path.expanduser(os.getenv("GOVULN_DB_PATH")), os.path.expanduser(os.getenv("OUTDATA_PATH")),
                         args.overwrite, cve_list)
    else:
        parser.error('Either --cve_id or --processall must be provided.')


if __name__ == "__main__":
    # This file processors the cve fixes db and extracts relevent data out.
    # the cve metadata is enriched with govulndb data if present
    # filechanges are taken from the cvefixes db annd dumped too
    # It does this for all languages. Moving to the language specific fodler and gziping is left manually so that sizes of output are checked.
    # In some cases the sizes of file and method changes are very large. E.g: CVE-2022-2306 CVE-2020-14958 CVE-2022-24738

    # python -m src.cmd.process_cvefixes_and_govulndb --cve_id CVE-2019-10214 --overwrite
    # python -m src.cmd.process_cvefixes_and_govulndb --processall --overwrite > out/out.txt 2>&1
    load_dotenv()
    main()
