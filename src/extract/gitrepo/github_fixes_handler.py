import json
from typing import Any, Dict, List, Optional, Tuple
import uuid

from pygments.lexers import guess_lexer_for_filename
from pygments.util import ClassNotFound
import requests
from unidiff import Hunk
from unidiff import PatchedFile
from unidiff import PatchSet

from . import gitutils
from ...fileutils import filehandle
from ...logging.logging import logger
from ...schemas import fixes
from ...schemas import osv

GET_COMMIT_URL = "https://api.github.com/repos/{owner}/{repo}/commits/{hash}"


def create_unidiff(filename: str, previous_filename: str, status: str, sha: str, patch: str) -> str:
    if not patch:
        return ""
    header = f"diff --git a/{previous_filename or filename} b/{filename}\n"
    if status == "added":
        header += "new file mode 100644\n"
    elif status == "removed":
        header += "deleted file mode 100644\n"
    header += f"index {sha[:7]}..{sha[:7]} 100644\n"
    header += f"--- a/{previous_filename or filename}\n"
    header += f"+++ b/{filename}\n"

    unidiff_string = header + patch + "\n\n"

    return unidiff_string


def parse_patch(patch: str) -> Optional[PatchSet]:
    if not patch:
        return None
    try:
        return PatchSet(patch)
    except Exception as e:
        logger.error("Failed to parse patch: %s", e)
        return None


def get_code_before_after(patched_file: PatchedFile) -> Tuple[str, str, Dict[str, List[Tuple[int, str]]]]:
    if not isinstance(patched_file, PatchedFile):
        raise TypeError("patched_file must be an instance of PatchedFile")

    before_lines: List[str] = []
    after_lines: List[str] = []
    diff_parsed: Dict[str, List[Tuple[int, str]]] = {"added": [], "deleted": []}

    for hunk in patched_file:
        if not isinstance(hunk, Hunk):
            continue

        for line in hunk:
            if line.is_context or line.is_removed:
                before_lines.append(line.value)
            if line.is_context or line.is_added:
                after_lines.append(line.value)

            if line.is_added:
                diff_parsed["added"].append((line.target_line_no, line.value))
            elif line.is_removed:
                diff_parsed["deleted"].append((line.source_line_no, line.value))

    return ''.join(before_lines), ''.join(after_lines), diff_parsed


def detect_language(filename: str, patched_file: Optional[PatchedFile]) -> str:
    if not patched_file:
        return "unknown"

    all_code = []

    for hunk in patched_file:
        for line in hunk:
            all_code.append(line.value)

    code_combined = '\n'.join(all_code)

    try:
        lexer = guess_lexer_for_filename(filename, code_combined)
        return lexer.name
    except ClassNotFound:
        return "unknown"
    except Exception as e:
        logger.error("Error detecting language: %s", e)
        return "unknown"


def get_files_model(url_info: Dict[str, Any], commit_all_data: Dict[str, Any]) -> List[fixes.FileChange]:
    file_changes = []
    for file_entry in commit_all_data.get("files", []):
        file_change_id = str(uuid.uuid4().fields[-1])
        filename = file_entry["filename"]
        previous_filename = file_entry.get("previous_filename", "")
        status = file_entry["status"]
        shaval = file_entry["sha"]
        patch = file_entry.get("patch", "")
        # logger.debug("patch:\n%s", patch)

        unidiff_patch = create_unidiff(filename, previous_filename, status, shaval, patch)

        # logger.debug("unipatch:\n%s", unidiff_patch)
        parsed_patch = parse_patch(unidiff_patch)
        code_before, code_after, diff_parsed = "", "", {}
        patched_file = None
        if parsed_patch:
            patched_file = parsed_patch[0]
            code_before, code_after, diff_parsed = get_code_before_after(patched_file)
        # logger.debug(json.dumps(parsed_patch, indent=2))
        file_change = fixes.FileChange(
            file_change_id=file_change_id,
            hash=url_info["hash"],
            filename=filename,
            old_path=None,
            new_path=None,
            change_type=status,
            diff=unidiff_patch,
            diff_parsed=json.dumps(diff_parsed),
            code_after=code_after,
            code_before=code_before,
            programming_language=detect_language(filename, patched_file),
            num_lines_added=file_entry.get("additions"),
            num_lines_deleted=file_entry.get("deletions"),
        )
        file_changes.append(file_change)

    return file_changes


def get_commits_model(url_info: Dict[str, Any], commit_all_data: Dict[str, Any]) -> fixes.Commit:
    added = None
    deleted = None
    if "stats" in commit_all_data and "additions" in commit_all_data["stats"]:
        added = str(commit_all_data["stats"].get("additions"))
    if "stats" in commit_all_data and "deletions" in commit_all_data["stats"]:
        deleted = str(commit_all_data["stats"].get("deletions"))
    commit_info = {
        'hash': url_info["hash"],
        'repo_url': url_info["repo"],
        'author': commit_all_data["commit"]["author"]["name"],
        'author_date': commit_all_data["commit"]["author"].get("date"),
        'committer': commit_all_data["commit"]["committer"]["name"],
        'committer_date': commit_all_data["commit"]["committer"].get("date"),
        'message': commit_all_data["commit"]["message"],
        'num_lines_added': added,
        'num_lines_deleted': deleted,
        'parents': [item["sha"] for item in commit_all_data["parents"]],
    }

    return fixes.Commit.model_validate(commit_info)


def get_commit_data(apitoken: str, ses: requests.Session,
                    url_info: List[Dict[str, Any]]) -> Tuple[List[fixes.FileChange], fixes.Commit]:
    headers = {'Authorization': f'Bearer {apitoken}', "X-GitHub-Api-Version": "2022-11-28"}
    url = GET_COMMIT_URL.format(owner=url_info["owner"], repo=url_info["project"], hash=url_info["hash"])

    try:
        response = gitutils.get_request_result(ses, gitutils.REQUEST_GET, url, headers)

        # logger.info(to_curl(response.request))
        response.raise_for_status()
    except requests.RequestException as e:
        # Log the exception or handle it as needed
        logger.error("Repo get request failed:%s", e)
        raise

    commit_all_data = response.json()
    commit_model = get_commits_model(url_info, commit_all_data)
    file_changes = get_files_model(url_info, commit_all_data)
    return (file_changes, commit_model)


def get_fixesinfo_using_git_repo(cve_id: str, apitoken: str,
                                 osv_schema_obj: osv.OpenSourceVulnerability) -> fixes.CVEFixes:
    urls_info = gitutils.extract_github_commit_urls(osv_schema_obj)
    if not urls_info:
        logger.info("%s - No commit urls found. skipping github fixes processing", cve_id)

    ses = requests.Session()

    fixes_objs = []
    for url_info in urls_info:
        fixes_info_obj = get_commit_data(apitoken, ses, url_info)
        fixes_objs.append(fixes_info_obj)
        # logger.info("URL info: %s. \n Commit info: %s", json.dumps(url_info, indent=2),
        # fixes_info_obj[1].model_dump_json(indent=2, exclude_none=True))

    commits = [item[1] for item in fixes_objs]
    filechanges = []
    for item in fixes_objs:
        filechanges.extend(item[0])
    return fixes.CVEFixes(cve_id=cve_id, commits=commits, changes=filechanges)


def write_fixes_using_git_repo(cve_id: str, outdata_file_path: str, apitoken: str,
                               osv_schema_obj: osv.OpenSourceVulnerability):
    logger.info("Started processing for %s, %s", cve_id, outdata_file_path)

    fchanges_schema = get_fixesinfo_using_git_repo(cve_id, apitoken, osv_schema_obj)
    fchanges = fchanges_schema.model_dump(exclude_none=True)

    filehandle.write_json_zip(outdata_file_path, fchanges)
    logger.info("%s - Successfully processed and saved data", cve_id)
