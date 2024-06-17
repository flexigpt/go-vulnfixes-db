import sqlite3
from typing import Any, Dict, List

# from ...logging.logging import logger
from .pandas_utils import convert_pandas_str_to_json

query = '''
SELECT 
    cve.*,
    fixes.hash AS fixes_hash,
    fixes.repo_url AS fixes_repo_url,
    repository.repo_name AS repository_repo_name,
    repository.description AS repository_description,
    repository.date_created AS repository_date_created,
    repository.date_last_push AS repository_date_last_push,
    repository.homepage AS repository_homepage,
    repository.repo_language AS repository_repo_language,
    repository.owner AS repository_owner,
    repository.forks_count AS repository_forks_count,
    repository.stars_count AS repository_stars_count,
    commits.author AS commits_author,
    cwe_classification.cwe_id AS cwe_classification_cwe_id,
    cwe.cwe_name AS cwe_cwe_name,
    cwe.description AS cwe_description,
    cwe.extended_description AS cwe_extended_description,
    cwe.url AS cwe_url,
    cwe.is_category AS cwe_is_category
FROM 
    cve
LEFT JOIN 
    fixes ON cve.cve_id = fixes.cve_id
LEFT JOIN 
    repository ON fixes.repo_url = repository.repo_url
LEFT JOIN 
    commits ON fixes.hash = commits.hash
LEFT JOIN 
    cwe_classification ON cve.cve_id = cwe_classification.cve_id
LEFT JOIN 
    cwe ON cwe_classification.cwe_id = cwe.cwe_id
WHERE 
    cve.cve_id = ?
'''


def get_cve_data_from_db(cve_id: str, db_path: str) -> List[Dict[str, Any]]:
    """
    Queries the database to get all relevant data for a given CVE ID.

    Parameters:
    dbfile (str): The path to the SQLite database file.
    cve_id (str): The CVE ID to query.

    Returns:
    List[Dict[str, Any]]: A list of dictionaries containing the CVE data.
    """
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (cve_id, ))
        data = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        results = [dict(zip(columns, row)) for row in data]
        return results


def extract_cve_level_details(data: Dict[str, Any]) -> Dict[str, Any]:
    problemtype = convert_pandas_str_to_json(data["problemtype_json"])
    description = convert_pandas_str_to_json(data["description"])
    nodes = convert_pandas_str_to_json(data["nodes"])
    reference = convert_pandas_str_to_json(data["reference_json"])

    osv_data = {}
    osv_data["schema_version"] = "1.6.3"

    if problemtype and problemtype[0]['description']:
        if isinstance(problemtype[0]['description'], str):
            osv_data["summary"] = problemtype[0]['description']
        elif isinstance(problemtype[0]['description'], list) and "value" in problemtype[0]['description'][0]:
            osv_data["summary"] = problemtype[0]['description'][0]['value']

    if description:
        if isinstance(description, str):
            osv_data["details"] = description
        elif isinstance(description, list) and "value" in description[0]:
            osv_data["details"] = description[0]['value']

    # Add keys to osv_data based on conditions
    if data.get("cve_id"):
        osv_data["id"] = data.get("cve_id")
    if data.get("last_modified_date"):
        osv_data["modified"] = data.get("last_modified_date")
    if data.get("published_date"):
        osv_data["published"] = data.get("published_date")
    if problemtype and problemtype[0]['description']:
        if isinstance(problemtype[0]['description'], str):
            osv_data["summary"] = problemtype[0]['description']
        elif isinstance(problemtype[0]['description'], list) and "value" in problemtype[0]['description'][0]:
            osv_data["summary"] = problemtype[0]['description'][0]['value']

    if description:
        if isinstance(description, str):
            osv_data["details"] = description
        elif isinstance(description, list) and "value" in description[0]:
            osv_data["details"] = description[0]['value']

    severity = []
    if data.get('cvss2_vector_string'):
        severity.append({"type": "CVSS_V2", "score": f"{data.get('cvss2_vector_string')}"})
    if data.get('cvss3_vector_string'):
        severity.append({"type": "CVSS_V3", "score": f"{data.get('cvss3_vector_string')}"})
    if severity:
        osv_data["severity"] = severity

    credits_in = {}
    if data.get("commits_author"):
        credits_in["name"] = data.get("commits_author")
        credits_in["type"] = "REMEDIATION_DEVELOPER"
    if credits_in:
        osv_data["credits"] = [credits_in]

    references = [{"type": "WEB", "url": ref['url']} for ref in reference if 'url' in ref]
    if references:
        osv_data["references"] = references

    database_specific = {}

    cvss2 = {}
    if data.get("cvss2_vector_string"):
        cvss2["vector_string"] = data.get("cvss2_vector_string")
    if data.get("cvss2_access_vector"):
        cvss2["access_vector"] = data.get("cvss2_access_vector")
    if data.get("cvss2_access_complexity"):
        cvss2["access_complexity"] = data.get("cvss2_access_complexity")
    if data.get("cvss2_authentication"):
        cvss2["authentication"] = data.get("cvss2_authentication")
    if data.get("cvss2_confidentiality_impact"):
        cvss2["confidentiality_impact"] = data.get("cvss2_confidentiality_impact")
    if data.get("cvss2_integrity_impact"):
        cvss2["integrity_impact"] = data.get("cvss2_integrity_impact")
    if data.get("cvss2_availability_impact"):
        cvss2["availability_impact"] = data.get("cvss2_availability_impact")
    if data.get('cvss2_base_score'):
        cvss2["base_score"] = data.get('cvss2_base_score')
    if cvss2:
        database_specific["cvss2"] = cvss2

    cvss3 = {}
    if data.get("cvss3_vector_string"):
        cvss3["vector_string"] = data.get("cvss3_vector_string")
    if data.get("cvss3_attack_vector"):
        cvss3["attack_vector"] = data.get("cvss3_attack_vector")
    if data.get("cvss3_attack_complexity"):
        cvss3["attack_complexity"] = data.get("cvss3_attack_complexity")
    if data.get("cvss3_privileges_required"):
        cvss3["privileges_required"] = data.get("cvss3_privileges_required")
    if data.get("cvss3_user_interaction"):
        cvss3["user_interaction"] = data.get("cvss3_user_interaction")
    if data.get("cvss3_scope"):
        cvss3["scope"] = data.get("cvss3_scope")
    if data.get("cvss3_confidentiality_impact"):
        cvss3["confidentiality_impact"] = data.get("cvss3_confidentiality_impact")
    if data.get("cvss3_integrity_impact"):
        cvss3["integrity_impact"] = data.get("cvss3_integrity_impact")
    if data.get("cvss3_availability_impact"):
        cvss3["availability_impact"] = data.get("cvss3_availability_impact")
    if data.get("cvss3_base_severity"):
        cvss3["base_severity"] = data.get("cvss3_base_severity")
    if data.get('cvss3_base_score'):
        cvss3["base_score"] = data.get('cvss3_base_score')
    if cvss3:
        database_specific["cvss3"] = cvss3

    impact = {}
    if data.get("severity"):
        impact["severity"] = data.get("severity")
    if data.get("obtain_all_privilege"):
        impact["obtain_all_privilege"] = data.get("obtain_all_privilege")
    if data.get("obtain_user_privilege"):
        impact["obtain_user_privilege"] = data.get("obtain_user_privilege")
    if data.get("obtain_other_privilege"):
        impact["obtain_other_privilege"] = data.get("obtain_other_privilege")
    if data.get("user_interaction_required"):
        impact["user_interaction_required"] = data.get("user_interaction_required")
    if data.get("exploitability_score"):
        impact["exploitability_score"] = data.get("exploitability_score")
    if data.get("impact_score"):
        impact["impact_score"] = data.get("impact_score")
    if impact:
        database_specific["impact"] = impact

    if nodes:
        database_specific["nodes"] = nodes

    if database_specific:
        osv_data["database_specific"] = database_specific

    return osv_data


def extract_unique_repository(rows):
    repo_dict = {}

    for data in rows:
        if (not data.get('fixes_repo_url')) or data['fixes_repo_url'] in repo_dict:
            continue

        repository = {}
        if data.get("fixes_repo_url"):
            repository["url"] = data.get("fixes_repo_url")
        if data.get("repository_repo_name"):
            repository["name"] = data.get("repository_repo_name")
        if data.get("repository_description"):
            repository["description"] = data.get("repository_description")
        if data.get("repository_date_created"):
            repository["date_created"] = data.get("repository_date_created")
        if data.get("repository_date_last_push"):
            repository["date_last_push"] = data.get("repository_date_last_push")
        if data.get("repository_owner"):
            repository["owner"] = data.get("repository_owner")
        if data.get("repository_forks_count"):
            repository["forks_count"] = data.get("repository_forks_count")
        if data.get("repository_stars_count"):
            repository["stars_count"] = data.get("repository_stars_count")
        if data.get("repository_homepage"):
            repository["homepage"] = data.get("repository_homepage")
        if data.get("repository_repo_language"):
            repository["repo_language"] = data.get("repository_repo_language")
        repo_dict[data['fixes_repo_url']] = repository

    return repo_dict


def extract_unique_cwe(rows):
    cwe_dict = {}
    for data in rows:
        if (not data.get('cwe_classification_cwe_id')) or data['cwe_classification_cwe_id'] in cwe_dict:
            continue

        cwe_details = {}
        if data.get("cwe_classification_cwe_id"):
            cwe_details["cwe_id"] = data.get("cwe_classification_cwe_id")
        if data.get("cwe_cwe_name"):
            cwe_details["name"] = data.get("cwe_cwe_name")
        if data.get("cwe_description"):
            cwe_details["description"] = data.get("cwe_description")
        if data.get("cwe_url"):
            cwe_details["url"] = data.get("cwe_url")
        if data.get("cwe_is_category"):
            cwe_details["is_category"] = data.get("cwe_is_category")
        if data.get("cwe_extended_description"):
            cwe_details["extended_description"] = data.get("cwe_extended_description")
        cwe_dict[data['cwe_classification_cwe_id']] = cwe_details

    return cwe_dict


def convert_to_osv(allrows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Converts the CVE data into the OSV schema format.

    Parameters:
    data (Dict[str, Any]): The dictionary containing the CVE data.

    Returns:
    Dict[str, Any]: A dictionary in the OSV schema format.
    """
    if not allrows:
        return {}
    first_row = allrows[0]
    osv_data = extract_cve_level_details(first_row)

    cwe_details = extract_unique_cwe(allrows)
    if cwe_details:
        osv_data["database_specific"]["cwe_details"] = list(cwe_details.values())

    repositories = extract_unique_repository(allrows)
    if repositories:
        osv_data["database_specific"]["repositories"] = list(repositories.values())

    nodes = osv_data["database_specific"]["nodes"]
    versionEndIncluding = ""
    versionEndExcluding = ""
    versionStartIncluding = ""
    if nodes and "cpe_match" in nodes[0] and nodes[0]['cpe_match'] and "versionEndIncluding" in nodes[0]['cpe_match'][0]:
        versionEndIncluding = nodes[0]['cpe_match'][0]['versionEndIncluding']
    if nodes and "cpe_match" in nodes[0] and nodes[0]['cpe_match'] and "versionEndExcluding" in nodes[0]['cpe_match'][0]:
        versionEndExcluding = nodes[0]['cpe_match'][0]['versionEndExcluding']
    if nodes and "cpe_match" in nodes[0] and nodes[0]['cpe_match'] and "versionStartIncluding" in nodes[0]['cpe_match'][
            0]:
        versionStartIncluding = nodes[0]['cpe_match'][0]['versionStartIncluding']

    affected = {"package": {}, "ranges": [{"type": "SEMVER", "events": []}]}
    if first_row.get('repository_repo_name'):
        affected["package"]["name"] = first_row.get('repository_repo_name')
    if first_row.get('fixes_repo_url'):
        affected["package"]["purl"] = first_row.get('fixes_repo_url')

    events = {}
    if versionStartIncluding:
        events["introduced"] = versionStartIncluding
    if versionEndIncluding:
        events["last_affected"] = versionEndIncluding
    if versionEndExcluding:
        events["fixed"] = versionEndExcluding

    if events:
        affected["ranges"][0]["events"].append(events)

    if affected["package"] or affected["ranges"][0]["events"]:
        osv_data["affected"] = [affected]

    return osv_data
