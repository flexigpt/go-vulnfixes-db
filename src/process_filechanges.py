import argparse
import json
import os
import traceback
from typing import List

from dotenv import load_dotenv

from .extract.cvefixesdb import dblevel_query
from .extract.cvefixesdb import single_cvefiledata_query
from .extract.gitrepo import github_fixes_handler
from .fileutils import dirhandle
from .logging.logging import logger
# from .schemas import osv
from .schemautils.validate import load_and_validate_json

MAX_PROCESS_ITEMS = 10000000
MAX_ERRORS = 10000


def process_all_cves(cvefixes_db_path: str,
                     cveinfo_unified_path: str,
                     outdata_path: str,
                     apitoken: str,
                     overwrite: bool,
                     cve_list: List[int] = None):

    dblevel_query.ensure_indexes(cvefixes_db_path)
    cve_ids = []
    error_cve_ids = []
    if cve_list:
        cve_ids = cve_list
    else:
        cve_ids = dirhandle.get_json_filenames(cveinfo_unified_path)

    logger.info("Total cve ids found are %s", len(cve_ids))

    processed = 0
    for cve_id in cve_ids:
        try:
            osv_schema_obj = load_and_validate_json(os.path.join(cveinfo_unified_path, cve_id + ".json"))
            if not osv_schema_obj:
                raise ValueError(f"{cve_id} No OSV schema found")
            outdata_file_path = os.path.join(outdata_path, f"{cve_id}_fixes.json.gz")
            if not overwrite and os.path.exists(outdata_file_path):
                logger.info("%s - Skipping processing as cve fixes file already exists", cve_id)
                return
            if osv_schema_obj.database_specific.datasources and osv_schema_obj.database_specific.datasources.cvefixes:
                single_cvefiledata_query.write_fixes_using_cvefixes_db(cve_id, cvefixes_db_path, outdata_file_path,
                                                                       osv_schema_obj)
            else:
                # logger.info("%s - Skipping file as not present in cvefixes db", cve_id)
                github_fixes_handler.write_fixes_using_git_repo(cve_id, outdata_file_path, apitoken, osv_schema_obj)
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
    parser = argparse.ArgumentParser(description='Generate File data from CVE ID and database path.')

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
                         os.path.expanduser(os.getenv("CVE_INFO_UNIFIED_PATH")),
                         os.path.expanduser(os.getenv("OUTFIXES_DATA_PATH")),
                         os.path.expanduser(os.getenv("GITHUB_TOKEN")), args.overwrite, cve_list)
    else:
        parser.error('Either --cve_id or --processall must be provided.')


if __name__ == "__main__":

    # python -m src.process_filechanges --cve_id CVE-2016-3697 --overwrite
    # gunzip -c ./data/go-fixes/CVE-2016-3697_fixes.json.gz | jq .
    # python -m src.process_filechanges --processall --overwrite > out/out.txt 2>&1
    load_dotenv()
    main()
