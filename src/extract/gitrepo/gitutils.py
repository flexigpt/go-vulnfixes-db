import re
import time
from typing import Any, Dict, List

import requests

from ...schemas import osv

MAX_SLEEP = 300
REQUEST_HEAD = "head"
REQUEST_GET = "get"


def get_request_result(ses: requests.Session,
                       req_type: str,
                       url: str,
                       headers: Any,
                       timeout: int = 120) -> requests.Response:

    def get_resp(ses: requests.Session, req_type: str, url: str, headers: Any, timeout: int = 120):
        if req_type == REQUEST_HEAD:
            return ses.head(url, headers=headers, timeout=timeout)
        if req_type == REQUEST_GET:
            return ses.get(url, headers=headers, timeout=timeout)

    sleeptime = 0
    response = get_resp(ses, req_type, url, headers, timeout)
    # Wait while sending too many requests (increasing timeout on every iteration)
    while response.status_code == 429:
        sleeptime += 10
        if sleeptime > MAX_SLEEP:
            raise ValueError("Too many requests")
        time.sleep(sleeptime)
        response = get_resp(ses, req_type, url, headers, timeout)

    return response


def extract_github_commit_urls(vulnerability: osv.OpenSourceVulnerability) -> List[Dict[str, str]]:
    github_commit_regex = (r'((?P<repo>(https|http):\/\/github\.com\/(?P<owner>[^\/]+)\/(?P<project>[^\/]+))'
                           r'\/(commit|commits)\/(?P<hash>\w+)#?)')
    commit_urls = []

    if vulnerability.references:
        for reference in vulnerability.references:
            match = re.match(github_commit_regex, reference.url)
            if match:
                commit_data = {
                    "ref_url": reference.url,
                    "repo": match.group("repo"),
                    "owner": match.group("owner"),
                    "project": match.group("project"),
                    "hash": match.group("hash"),
                }
                commit_urls.append(commit_data)

    return commit_urls
