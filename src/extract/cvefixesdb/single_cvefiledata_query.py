import ast
import json
import sqlite3
from typing import Any, Dict, List, Tuple

from ...fileutils import filehandle
from ...logging.logging import logger
from ...schemas import fixes as fixesschema
from ...schemas import osv
from .pandas_utils import convert_pandas_str_to_json

MAX_SIZE = 4 * 1024 * 1024


def get_all_data_by_cve_id(cve_id: str, db_path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Fetch CVE details
        cursor.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id, ))
        cve_details = cursor.fetchone()
        if cve_details:
            result['cve'] = cve_details

        # Fetch fixes details
        cursor.execute("SELECT * FROM fixes WHERE cve_id = ?", (cve_id, ))
        fixes_details = cursor.fetchall()
        if fixes_details:
            result['fixes'] = fixes_details

        # Fetch associated repositories
        repo_urls = {fix[2] for fix in fixes_details}

        repos_details = []
        for repo_url in repo_urls:
            cursor.execute("SELECT * FROM repository WHERE repo_url = ?", (repo_url, ))
            repo_detail = cursor.fetchone()
            if repo_detail:
                repos_details.append(repo_detail)
        if repos_details:
            result['repositories'] = repos_details

        # Fetch commits details
        commits_details = []
        for fix in fixes_details:
            fix_hash = fix[1]
            cursor.execute("SELECT * FROM commits WHERE hash = ?", (fix_hash, ))
            commit_detail = cursor.fetchone()
            if commit_detail:
                commits_details.append(commit_detail)
        if commits_details:
            result['commits'] = commits_details

        # Fetch file changes and their corresponding method changes
        file_changes_details = []
        for commit in commits_details:
            commit_hash = commit[0]
            cursor.execute("SELECT * FROM file_change WHERE hash = ?", (commit_hash, ))
            file_changes = cursor.fetchall()
            for file_change in file_changes:
                file_change_id = file_change[0]
                cursor.execute("SELECT * FROM method_change WHERE file_change_id = ?", (file_change_id, ))
                method_changes = cursor.fetchall()
                file_changes_details.append({"file_change": file_change, "method_changes": method_changes})
        if file_changes_details:
            result['file_changes'] = file_changes_details

        # Fetch associated CWEs
        cursor.execute("SELECT * FROM cwe_classification WHERE cve_id = ?", (cve_id, ))
        cwe_classifications = cursor.fetchall()
        cwe_details = []
        for cwe_class in cwe_classifications:
            cwe_id = cwe_class[1]
            cursor.execute("SELECT * FROM cwe WHERE cwe_id = ?", (cwe_id, ))
            cwe_detail = cursor.fetchone()
            if cwe_detail:
                cwe_details.append(cwe_detail)
        if cwe_details:
            result['cwes'] = cwe_details

    return result


def get_file_change_counts_by_cve(db_path: str) -> Dict[str, int]:
    cve_file_change_counts: Dict[str, int] = {}

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Query to count file changes for each CVE
        cursor.execute("""
            SELECT cve.cve_id, COUNT(file_change.file_change_id) AS file_change_count
            FROM cve
            JOIN fixes ON cve.cve_id = fixes.cve_id
            JOIN file_change ON fixes.hash = file_change.hash
            GROUP BY cve.cve_id
        """)

        rows = cursor.fetchall()

        # Convert query result to dictionary
        cve_file_change_counts = {row[0]: row[1] for row in rows}

    return cve_file_change_counts


def is_data_size_within_threshold(db_path: str, cve_id: str, threshold_bytes: int = MAX_SIZE) -> Tuple[bool, int | Any]:
    size_query = """
    SELECT SUM(LENGTH(filename) + LENGTH(old_path) + LENGTH(new_path) + LENGTH(diff) + 
               LENGTH(diff_parsed) + LENGTH(code_after) + LENGTH(code_before) + 
               LENGTH(programming_language)) AS total_text_size,
           SUM(nloc + complexity + token_count + num_lines_added + num_lines_deleted) * 4 AS total_int_size
    FROM file_change
    JOIN fixes ON file_change.hash = fixes.hash
    WHERE fixes.cve_id = ?
    """

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(size_query, (cve_id, ))
        result = cursor.fetchone()
        total_text_size, total_int_size = result

        # Handle cases where either size might be None
        total_text_size = total_text_size if total_text_size else 0
        total_int_size = total_int_size if total_int_size else 0

        total_size = total_text_size + total_int_size
        return (total_size <= threshold_bytes, total_size)


file_change_query = """
SELECT file_change.file_change_id AS file_change_id,
       file_change.hash AS hash,
       file_change.filename AS filename,
       file_change.old_path AS old_path,
       file_change.new_path AS new_path,
       file_change.change_type AS change_type,
       file_change.diff AS diff,
       file_change.diff_parsed AS diff_parsed,
       file_change.code_after AS code_after,
       file_change.code_before AS code_before,
       file_change.nloc AS nloc,
       file_change.complexity AS complexity,
       file_change.token_count AS token_count,
       file_change.programming_language AS programming_language,
       file_change.num_lines_added AS num_lines_added,
       file_change.num_lines_deleted AS num_lines_deleted
FROM file_change
JOIN fixes ON file_change.hash = fixes.hash
WHERE fixes.cve_id = ?
"""

method_change_query_template = """
SELECT method_change.file_change_id AS file_change_id,
       method_change.method_change_id AS method_change_id,
       method_change.name AS name,
       method_change.signature AS signature,
       method_change.parameters AS parameters,
       method_change.start_line AS start_line,
       method_change.end_line AS end_line,
       method_change.code AS code,
       method_change.nloc AS nloc,
       method_change.complexity AS complexity,
       method_change.token_count AS token_count,
       method_change.top_nesting_level AS top_nesting_level,
       method_change.before_change AS before_change
FROM method_change
WHERE method_change.file_change_id IN ({placeholders})
"""


def convert_to_pydantic_schema(cve_id: str, data: List[Dict[str, Any]], commits: Dict[str,
                                                                                      Any]) -> fixesschema.CVEFixes:
    change_dict = {"cve_id": cve_id, "changes": data, "commits": list(commits.values())}
    cvefixes_obj = fixesschema.CVEFixes(**change_dict)
    return cvefixes_obj


def convert_string_to_list(string_list: str) -> List[str]:
    if not string_list:
        return []
    # Remove any leading/trailing whitespace
    string_list = string_list.strip()

    # Handle empty list case
    if string_list == "[]":
        return []

    # Use ast.literal_eval to safely evaluate the string as a Python literal
    result = ast.literal_eval(string_list)
    if isinstance(result, list) and all(isinstance(item, str) for item in result):
        return result
    else:
        raise ValueError("The input string does not represent a list of strings.")


def extract_unique_commits(rows):
    commits_dict = {}
    for data in rows:
        if (not data.get('hash')) or data['hash'] in commits_dict:
            continue
        commits = {}
        commits["author"] = data.get("author")
        commits["committer_date"] = data.get("committer_date")
        commits["message"] = data.get("msg")
        commits["merge"] = data.get("merge")
        commits["author_date"] = data.get("author_date")
        commits["author_timezone"] = data.get("author_timezone")
        commits["committer"] = data.get("committer")
        commits["committer_timezone"] = data.get("committer_timezone")
        commits["parents"] = convert_string_to_list(data.get("parents"))
        commits["num_lines_added"] = data.get("num_lines_added")
        commits["num_lines_deleted"] = data.get("num_lines_deleted")
        commits["dmm_unit_complexity"] = data.get("dmm_unit_complexity")
        commits["dmm_unit_interfacing"] = data.get("dmm_unit_interfacing")
        commits["dmm_unit_size"] = data.get("dmm_unit_size")
        commits["hash"] = data['hash']
        commits["repo_url"] = data["repo_url"]
        commits_dict[data['hash']] = commits
    return commits_dict


# commits = extract_unique_commits(allrows)
#     if commits:
#         osv_data["database_specific"]["commits"] = list(commits.values())

commits_query = '''
SELECT 
    commits.*
FROM commits
JOIN fixes ON commits.hash = fixes.hash
WHERE fixes.cve_id = ?
'''


def get_commits_data_from_db(cve_id: str, db_path: str) -> List[Dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(commits_query, (cve_id, ))
        data = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        results = [dict(zip(columns, row)) for row in data]
        return results


def get_fixes_by_cve(db_path: str, cve_id: str) -> fixesschema.CVEFixes:
    issmall, size = is_data_size_within_threshold(db_path, cve_id)
    if not issmall:
        debugstr = f"{cve_id} Data size exceeds threshold. Size: {size} Aborting query."
        raise ValueError(debugstr)

    commits_db = get_commits_data_from_db(cve_id, db_path)
    commits_dict = extract_unique_commits(commits_db)
    # logger.info(json.dumps(commits_dict, indent=2))

    changes: List[Dict[str, Any]] = []
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()

        # Execute the query to get all file changes for the given CVE ID
        cursor.execute(file_change_query, (cve_id, ))
        file_changes = cursor.fetchall()
        file_change_columns = [desc[0] for desc in cursor.description]

        # Organize file changes into the list
        for row in file_changes:
            file_change_data = dict(zip(file_change_columns, row))
            if "diff_parsed" in file_change_data:
                diff_parsed = convert_pandas_str_to_json(file_change_data["diff_parsed"])
                file_change_data["diff_parsed"] = json.dumps(diff_parsed)
            changes.append(file_change_data)

        # Get all file_change_ids for method changes query
        file_change_ids = [fc['file_change_id'] for fc in changes]
        if file_change_ids:
            placeholders = ','.join(['?'] * len(file_change_ids))
            method_change_query = method_change_query_template.format(placeholders=placeholders)

            # Execute the query to get method changes for the retrieved file_change_ids
            cursor.execute(method_change_query, file_change_ids)
            method_changes = cursor.fetchall()
            method_change_columns = [desc[0] for desc in cursor.description]

            # Organize method changes into the corresponding file changes
            for row in method_changes:
                method_change_data = dict(zip(method_change_columns, row))
                for file_change in changes:
                    if file_change['file_change_id'] == method_change_data['file_change_id']:
                        if 'method_changes' not in file_change:
                            file_change['method_changes'] = []
                        file_change['method_changes'].append(method_change_data)

    # Convert to Pydantic schema
    cve_changes = convert_to_pydantic_schema(cve_id, changes, commits_dict)
    return cve_changes


def write_fixes_using_cvefixes_db(cve_id: str, cvefixes_db_path: str, outdata_file_path: str,
                                  osv_schema_obj: osv.OpenSourceVulnerability):
    logger.info("Started processing for %s, %s, %s", cve_id, cvefixes_db_path, outdata_file_path)
    if osv_schema_obj.database_specific.datasources and not osv_schema_obj.database_specific.datasources.cvefixes:
        logger.info("%s: No cve fixes data for this cve", cve_id)
        return

    fchanges_schema = get_fixes_by_cve(cvefixes_db_path, cve_id)
    fchanges = fchanges_schema.model_dump(exclude_none=True)

    filehandle.write_json_zip(outdata_file_path, fchanges)
    logger.info("%s - Successfully processed and saved data", cve_id)
