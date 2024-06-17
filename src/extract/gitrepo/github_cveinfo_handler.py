from typing import Any, Dict, List, Set

import requests

from . import gitutils
from ...logging.logging import logger
from ...schemas import osv

GET_REPO_URL = "https://api.github.com/repos/{owner}/{repo}"


def find_unavailable_urls(urls: Set[str], apitoken: str, ses: requests.Session) -> List[str]:
    """
    Returns the unavailable URLs (repositories that are removed or made private).

    Args:
        urls (List[str]): A list of URLs to check for availability.

    Returns:
        List[str]: A list of unavailable URLs.
    """

    unavailable_urls: List[str] = []
    headers = {'Authorization': f'Bearer {apitoken}', "X-GitHub-Api-Version": "2022-11-28"}

    for url in urls:
        response = gitutils.get_request_result(ses, gitutils.REQUEST_HEAD, url, headers)

        # Check for unavailable repositories by response status code or redirection
        if (response.status_code >= 400) or \
           (response.is_redirect and response.headers.get('location') == 'https://gitlab.com/users/sign_in'):
            logger.warning("Reference %s is not available with code: %s", url, response.status_code)
            unavailable_urls.append(url)
        else:
            logger.info("Reference %s is available with code: %s", url, response.status_code)

    return unavailable_urls


def get_repository_info(apitoken: str, ses: requests.Session, url_info: List[Dict[str, Any]]) -> osv.RepositoryModel:
    headers = {'Authorization': f'Bearer {apitoken}', "X-GitHub-Api-Version": "2022-11-28"}
    url = GET_REPO_URL.format(owner=url_info["owner"], repo=url_info["project"])

    try:
        response = gitutils.get_request_result(ses, gitutils.REQUEST_GET, url, headers)
        # logger.info(to_curl(response.request))
        response.raise_for_status()
    except requests.RequestException as e:
        # Log the exception or handle it as needed
        logger.error("Repo get request failed:%s", e)
        raise

    project_meta = response.json()
    repo_info = {
        "url": url_info["repo"],
        "name": project_meta.get("full_name"),
        "description": project_meta.get("description"),
        "date_created": project_meta.get("created_at"),
        "date_last_push": project_meta.get("pushed_at"),
        "owner": url_info["owner"],
        "forks_count": str(project_meta.get("forks_count")),
        "stars_count": str(project_meta.get("stargazers_count")),
        "repo_language": project_meta.get("language"),
    }
    repo_info_obj = osv.RepositoryModel.model_validate(repo_info)
    return repo_info_obj


def get_cveinfo_using_git_repo(cve_id: str, apitoken: str,
                               osv_schema_obj: osv.OpenSourceVulnerability) -> osv.OpenSourceVulnerability:
    urls_info = gitutils.extract_github_commit_urls(osv_schema_obj)
    if not urls_info:
        logger.info("%s - No commit urls found. skipping github processing", cve_id)
    ref_urls = {item["ref_url"] for item in urls_info}

    ses = requests.Session()
    unavailable_urls = find_unavailable_urls(ref_urls, apitoken, ses)
    available_urls_info = [item for item in urls_info if item["ref_url"] not in unavailable_urls]

    ref_objs = []
    for url_info in available_urls_info:
        repo_info_obj = get_repository_info(apitoken, ses, url_info)
        ref_objs.append(repo_info_obj)
        # logger.info("Repo info: %s", repo_info_obj.model_dump_json(indent=2, exclude_none=True))

    osv_schema_obj.database_specific.repositories = ref_objs
    return osv_schema_obj
