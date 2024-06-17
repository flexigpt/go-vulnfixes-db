import os
from typing import Any, Dict, Optional

from ...fileutils import filehandle
from ...logging.logging import logger
from ...schemas import osv


def build_cve_index(govulndb: str) -> Dict[str, Dict[str, Any]]:
    """
    Builds an index of CVE IDs and their associated aliases from the GoVulnDB.

    Parameters:
    govulndb (str): The path to the directory of the GoVulnDB zip extract.

    Returns:
    dict: A dictionary where keys are CVE IDs and values are dictionaries containing aliases and file paths.
    """
    file_path = os.path.join(govulndb, "index/vulns.json")
    id_dir_path = os.path.join(govulndb, "ID")

    data = filehandle.read_json(file_path)

    cve_index = {}

    for entry in data:
        if 'id' in entry and 'aliases' in entry:
            main_id = entry['id']
            aliases = entry['aliases']
            for alias in aliases:
                if alias.startswith('CVE'):
                    # Initialize the CVE index entry for the alias
                    cve_index[alias] = {}
                    # Create a list of aliases without the CVE ID
                    other_aliases = [main_id] + [a for a in aliases if a != alias]
                    cve_index[alias]["aliases"] = other_aliases
                    cve_index[alias]["id_file_path"] = os.path.join(id_dir_path, entry["id"] + ".json")
                    break
    return cve_index


def get_govuln_cve_data(cve_id: str, govulndb_index: Dict[str, Dict[str, Any]]) -> Any:
    # first get go vuln db data
    if cve_id not in govulndb_index:
        logger.warning("Couldn't find %s in GoVulnDB", cve_id)
        return {}

    govulndb_index_data = govulndb_index[cve_id]
    return filehandle.read_json(govulndb_index_data["id_file_path"])


def get_govulndb_cve_data_as_schema(cve_id: str,
                                    govulndb_index: Dict[str, Dict[str, Any]]) -> Optional[osv.OpenSourceVulnerability]:
    data = get_govuln_cve_data(cve_id, govulndb_index)
    if not data:
        return None

    osvschema = osv.OpenSourceVulnerability.model_validate(data)
    govulndbid = osvschema.id
    osvschema.id = cve_id
    osvschema.aliases.append(govulndbid)
    dbspecific_dict = osvschema.database_specific.model_dump(exclude_none=True)
    osvschema.database_specific = None
    osvschema.database_specific = osv.TopDatabaseSpecificModel(vulndb_data=dbspecific_dict)
    return osvschema
