# from .curlify import to_curl
from typing import Optional

from pydantic import ValidationError
import requests

from ...logging.logging import logger
from ...schemas import nvd

NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_cve_from_nvd(cve_id: str, apikey: str, session: requests.Session) -> Optional[nvd.CVEItem]:
    url_tail = f"?cveId={cve_id}"
    headers = {'apiKey': apikey}
    try:
        response = session.get(NVDURL + url_tail, headers=headers, timeout=120)
        # logger.info(to_curl(response.request))
        response.raise_for_status()
    except requests.RequestException as e:
        # Log the exception or handle it as needed
        logger.error("Request failed:%s", e)
        raise

    try:
        nvd_response = nvd.NVDResponse.model_validate_json(response.text)
    except ValidationError as e:
        logger.error("Validation failed: %s", e)
        return None

    if nvd_response.vulnerabilities:
        return nvd_response.vulnerabilities[0].cve

    return None


def get_cve(cve_id: str, apikey: str, session: requests.Session) -> Optional[nvd.CVEItem]:
    cve_info = get_cve_from_nvd(cve_id, apikey, session)
    if not cve_info:
        logger.info("Got empty info for: %s", cve_id)
        return None
    # logger.info(json.dumps(cve_info, indent=2))
    return cve_info
