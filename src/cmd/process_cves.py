import argparse
import json
import os
import traceback
from typing import Any, Dict, List

from dotenv import load_dotenv

from ..extract.cvefixesdb import cvefixes_dict_converter
from ..extract.cvefixesdb import dblevel_query
from ..extract.gitrepo.github_cveinfo_handler import get_cveinfo_using_git_repo
from ..extract.govulndb.govulndb import build_cve_index
from ..extract.govulndb.govulndb import get_govulndb_cve_data_as_schema
from ..extract.nvddb import fileparse as nvdfileparse
from ..extract.nvddb.cveitem_converter import convert_nvd_cve_item_to_osv
from ..fileutils import filehandle
from ..logging.logging import logger
from ..schemas import osv
from ..schemautils.cvecounters import compare_cve_sets
from ..schemautils.osvhandler import merge_osv_schemas

# MAX_PROCESS_ITEMS = 1
MAX_PROCESS_ITEMS = 10000000
MAX_ERRORS = 10


def process_cve(cve_id: str, cvefixes_db_path: str, govulndb_index: Dict[str, Dict[str, Any]], nvd_db_path: str,
                outdata_path: str, apitoken: str, overwrite: bool):
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
    out_cveosv_path = os.path.join(outdata_path, f"{cve_id}.json")
    if not overwrite and os.path.exists(out_cveosv_path):
        logger.info("%s - Skipping processing as cve fixes file already exists", cve_id)
        return
    logger.info("Started processing for CVEID: %s", cve_id)
    found_in_govulndb = False
    found_in_nvddb = False
    found_in_cvefixesdb = False
    osv_schema_obj = get_govulndb_cve_data_as_schema(cve_id, govulndb_index)
    # first get go vuln db data
    if osv_schema_obj:
        found_in_govulndb = True

    try:
        # Then get nvd data. It is ok even if it is not present there
        nvd_data = nvdfileparse.get_cve_from_file(cve_id, nvd_db_path)
        if nvd_data:
            nvd_osv_schema_obj = convert_nvd_cve_item_to_osv(nvd_data)
            if osv_schema_obj:
                osv_schema_obj = merge_osv_schemas(osv_schema_obj, nvd_osv_schema_obj)
            else:
                osv_schema_obj = nvd_osv_schema_obj
            found_in_nvddb = True
    except Exception as e:
        logger.error("Error in processing NVD cve: %s, err: %s", cve_id, e)
        traceback.print_exc()

    try:
        # Then the cve fixes data. It is ok even if it is not present there
        cvefixesdb_data = cvefixes_dict_converter.get_cve_data_as_schema(cve_id, cvefixes_db_path)
        if cvefixesdb_data:
            if osv_schema_obj:
                # If present merge these, assuming cve fixes is a cleaned data
                osv_schema_obj = merge_osv_schemas(osv_schema_obj, cvefixesdb_data)
            else:
                osv_schema_obj = cvefixesdb_data
            found_in_cvefixesdb = True
    except Exception as e:
        logger.error("Error in processing CVEFixes cve: %s, err: %s", cve_id, e)

    if not osv_schema_obj:
        logger.warning("No data found for %s in any DB sources", cve_id)
        return

    if not found_in_cvefixesdb:
        logger.info("%s - No data in cveinfo. process metadata using github", cve_id)
        osv_schema_obj = get_cveinfo_using_git_repo(cve_id, apitoken, osv_schema_obj)

    osv_schema_obj.database_specific.datasources = osv.SourceInfoModel(govuln=found_in_govulndb,
                                                                       nvd=found_in_nvddb,
                                                                       cvefixes=found_in_cvefixesdb)
    logger.info("Data sources for CVE: %s. GoVulnDB: %s, NVDDB: %s, CVEFixesDB: %s", cve_id, found_in_govulndb,
                found_in_nvddb, found_in_cvefixesdb)
    # logger.info(osv_schema_obj.model_dump_json(exclude_none=True, indent=2))

    filehandle.write_pydantic_to_json(out_cveosv_path, osv_schema_obj)
    logger.info("Successfully processed and saved data for CVE ID %s", cve_id)


def process_all_cves(cvefixes_db_path: str,
                     govuln_db_path: str,
                     nvd_db_path: str,
                     outdata_path: str,
                     apitoken: str,
                     overwrite: bool,
                     cve_list: List[int] = None):

    logger.info("CVEFIXES DB: %s, GoVULNDB: %s, NVDDB: %s, OutputPath:%s, Overwrite existing file:%s", cvefixes_db_path,
                govuln_db_path, nvd_db_path, outdata_path, overwrite)

    # Build the CVE index from the GoVulnDB
    govulndb_index = build_cve_index(govuln_db_path)
    dblevel_query.ensure_indexes(cvefixes_db_path)
    cve_ids = []
    error_cve_ids = []
    if cve_list:
        cve_ids = cve_list
    else:
        cves_from_vulndb = {cve_id for cve_id, _ in govulndb_index.items()}
        cves_from_fixesdb, _ = dblevel_query.get_cve_ids_by_languages(cvefixes_db_path, ["go", "golang"])
        cves_from_fixesdb = set(cves_from_fixesdb)
        cve_ids = cves_from_vulndb.union(cves_from_fixesdb)
        compare_cve_sets(cves_from_vulndb, cves_from_fixesdb)

    processed = 0
    for cve_id in cve_ids:
        try:
            process_cve(cve_id, cvefixes_db_path, govulndb_index, nvd_db_path, outdata_path, apitoken, overwrite)
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
                         os.path.expanduser(os.getenv("GOVULN_DB_PATH")), os.path.expanduser(os.getenv("NVD_DB_PATH")),
                         os.path.expanduser(os.getenv("OUTDATA_PATH")), os.path.expanduser(os.getenv("GITHUB_TOKEN")),
                         args.overwrite, cve_list)
    else:
        parser.error('Either --cve_id or --processall must be provided.')


if __name__ == "__main__":

    # python -m src.cmd.process_cves --cve_id CVE-2019-10214 --overwrite
    # python -m src.cmd.process_cves --processall --overwrite > out/out.txt 2>&1
    load_dotenv()
    main()
