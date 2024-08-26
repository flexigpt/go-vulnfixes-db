import argparse
import os
from typing import Dict, List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel
from pydantic import Field

from ..fileutils import filehandle
from ..logging.logging import logger
from ..schemautils import validate

MAX_PROCESS_ITEMS = 10000000
MAX_ERRORS = 10000


class CVEIndexInfo(BaseModel):
    cve_id: str


class CWEIndex(BaseModel):
    items: Dict[str, List[CVEIndexInfo]] = Field(default_factory=dict)


def build_cwe_based_index(all_cveinfo_dir_path: str) -> Optional[CWEIndex]:
    osv_schemas = validate.load_json_files_in_directory(all_cveinfo_dir_path)
    if not osv_schemas:
        logger.warning("No files found in directory: %s", all_cveinfo_dir_path)
        return None  # Add this return to avoid further processing

    cwe_index = {"NVD-CWE-noinfo": []}
    for osv_schema in osv_schemas:
        if not osv_schema.database_specific or not osv_schema.database_specific.cwe_details:
            cwe_index["NVD-CWE-noinfo"].append(CVEIndexInfo(cve_id=osv_schema.id))
            continue
        for cwe_detail in osv_schema.database_specific.cwe_details:
            cwe_ids = cwe_detail.cwe_id.split(" ")
            for cwe_id in cwe_ids:
                if not cwe_id:
                    continue
                if cwe_id not in cwe_index:
                    cwe_index[cwe_id] = []
                cwe_index[cwe_id].append(CVEIndexInfo(cve_id=osv_schema.id))

    if not cwe_index:
        return None
    return CWEIndex(items=cwe_index)


def process_all_cves(all_cveinfo_dir_path: str, outdata_path: str) -> None:
    """
    Main function to process all CVEs.

    Args:
        all_cveinfo_dir_path (str): Path to the populated CVE info jsons.
        outdata_path (str): Path to the output data directory.
        overwrite (bool): Flag to overwrite existing files.

    Returns:
        None
    """
    vulndb_index = build_cwe_based_index(all_cveinfo_dir_path)
    if not vulndb_index:
        logger.warning("No index built")
    # Save index
    index_dict = vulndb_index.model_dump(exclude_none=True)
    filehandle.write_json(os.path.join(outdata_path, "all_cwe_to_cveinfo_index.json"), index_dict["items"])
    return vulndb_index


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Generate CWE to CVE mapping.')
    parser.add_argument('--overwrite',
                        action='store_true',
                        default=False,
                        help='Overwrite existing files (default: False)')
    return parser.parse_args()


def main() -> None:
    """
    Main function to parse command-line arguments and process CVEs.

    Returns:
        None
    """
    parse_arguments()
    process_all_cves(os.path.expanduser(os.getenv("ALL_CVE_INFO_DIR_PATH")),
                     os.path.expanduser(os.getenv("OUTDATA_PATH")))


if __name__ == "__main__":
    # python -m src.cmd.build_cwe_to_cve_index > out/out.txt 2>&1
    load_dotenv(dotenv_path=".env")
    main()
