import hashlib
# import json
from typing import Any, Dict, List, Optional

from ...logging.logging import logger
from ...schemas import nvd
from ...schemas import osv
from .single_cvedata_query import convert_to_osv
from .single_cvedata_query import get_cve_data_from_db


def create_cvss_v2(data: Dict[str, Any], impact: Dict[str, Any]) -> Optional[nvd.CvssV2]:
    cvss2 = {}
    if data.get("cvss2_vector_string"):
        cvss2["vectorString"] = data.get("cvss2_vector_string")
    if data.get("cvss2_access_vector"):
        cvss2["accessVector"] = data.get("cvss2_access_vector")
    if data.get("cvss2_access_complexity"):
        cvss2["accessComplexity"] = data.get("cvss2_access_complexity")
    if data.get("cvss2_authentication"):
        cvss2["authentication"] = data.get("cvss2_authentication")
    if data.get("cvss2_confidentiality_impact"):
        cvss2["confidentialityImpact"] = data.get("cvss2_confidentiality_impact")
    if data.get("cvss2_integrity_impact"):
        cvss2["integrityImpact"] = data.get("cvss2_integrity_impact")
    if data.get("cvss2_availability_impact"):
        cvss2["availabilityImpact"] = data.get("cvss2_availability_impact")
    if data.get('cvss2_base_score'):
        cvss2["baseScore"] = data.get('cvss2_base_score')

    if cvss2:
        return nvd.CvssV2(source="NVD",
                          type="Primary",
                          cvssData=nvd.CVSSv20Data(version="2.0", **cvss2),
                          baseSeverity=impact.get("severity"),
                          obtainAllPrivilege=impact.get("obtain_all_privilege"),
                          obtainUserPrivilege=impact.get("obtain_user_privilege"),
                          obtainOtherPrivilege=impact.get("obtain_other_privilege"),
                          userInteractionRequired=impact.get("user_interaction_required"))
    return None


def create_cvss_v3(data: Dict[str, Any], impact: Dict[str, Any]) -> Optional[nvd.CvssV30]:
    cvss3 = {}
    if data.get("cvss3_vector_string"):
        cvss3["vectorString"] = data.get("cvss3_vector_string")
    if data.get("cvss3_attack_vector"):
        cvss3["attackVector"] = data.get("cvss3_attack_vector")
    if data.get("cvss3_attack_complexity"):
        cvss3["attackComplexity"] = data.get("cvss3_attack_complexity")
    if data.get("cvss3_privileges_required"):
        cvss3["privilegesRequired"] = data.get("cvss3_privileges_required")
    if data.get("cvss3_user_interaction"):
        cvss3["userInteraction"] = data.get("cvss3_user_interaction")
    if data.get("cvss3_scope"):
        cvss3["scope"] = data.get("cvss3_scope")
    if data.get("cvss3_confidentiality_impact"):
        cvss3["confidentialityImpact"] = data.get("cvss3_confidentiality_impact")
    if data.get("cvss3_integrity_impact"):
        cvss3["integrityImpact"] = data.get("cvss3_integrity_impact")
    if data.get("cvss3_availability_impact"):
        cvss3["availabilityImpact"] = data.get("cvss3_availability_impact")
    if data.get("cvss3_base_severity"):
        cvss3["baseSeverity"] = data.get("cvss3_base_severity")
    if data.get('cvss3_base_score'):
        cvss3["baseScore"] = data.get('cvss3_base_score')

    if cvss3:
        return nvd.CvssV30(source="NVD",
                           type="Primary",
                           cvssData=nvd.CVSSv30Data(version="3.0", **cvss3),
                           impactScore=impact.get("impact_score"),
                           exploitabilityScore=impact.get("exploitability_score"))
    return None


def convert_to_metrics(data: Dict[str, Any]) -> nvd.Metrics:
    cvss_v2 = None
    cvss_v3 = None
    if "cvss2" in data:
        cvss_v2 = create_cvss_v2(data["cvss2"], data.get("impact"))
    if "cvss3" in data:
        cvss_v3 = create_cvss_v3(data["cvss3"], data.get("impact"))

    metrics = nvd.Metrics(cvssMetricV2=[cvss_v2] if cvss_v2 else None,
                          cvssMetricV30=[cvss_v3] if cvss_v3 else None,
                          cvssMetricV31=None)
    return metrics


def generate_matchCriteriaId(criteria: str) -> str:
    # Use SHA-256 hash of the criteria to generate a UUID-like string
    hash_obj = hashlib.sha256(criteria.encode())
    hash_hex = hash_obj.hexdigest()
    # Format the first 32 characters of the hash as a UUID
    return f"{hash_hex[:8]}-{hash_hex[8:12]}-{hash_hex[12:16]}-{hash_hex[16:20]}-{hash_hex[20:32]}"


def transform_cpe_match(cpe_match: dict) -> nvd.CpeMatch:
    criteria = cpe_match['cpe23Uri'] if cpe_match.get('cpe23Uri') else cpe_match.get("cpe23Uri")
    return nvd.CpeMatch(vulnerable=cpe_match['vulnerable'],
                        criteria=criteria,
                        matchCriteriaId=generate_matchCriteriaId(criteria),
                        versionStartExcluding=cpe_match.get('versionStartExcluding'),
                        versionStartIncluding=cpe_match.get('versionStartIncluding'),
                        versionEndExcluding=cpe_match.get('versionEndExcluding'),
                        versionEndIncluding=cpe_match.get('versionEndIncluding'))


def convert_to_nodes(data: List[dict]) -> List[nvd.Node]:
    nodes = []
    for n in data:
        cpe_matches = [transform_cpe_match(cpe_match) for cpe_match in n.get('cpe_match', [])]
        nodeitem = nvd.Node(operator=n.get('operator'), negate=n.get('negate'), cpeMatch=cpe_matches)
        nodes.append(nodeitem)
    return nodes


def get_cve_data_as_schema(cve_id: str, cvefixes_db_path: str) -> Optional[osv.OpenSourceVulnerability]:
    """
    get the cve data from db and convert into the Pydantic OpenSourceVulnerability model.

    Returns:
    osv.OpenSourceVulnerability: A Pydantic model in the OSV schema format.
    """
    # Query the database for all relevant data
    cvefixesdb_data = get_cve_data_from_db(cve_id, cvefixes_db_path)
    if not cvefixesdb_data:
        logger.warning("No data found for CVE ID %s in cvefixes db", cve_id)
        return {}
    # logger.info(f"Got CVE data from query: {json.dumps(data[0], indent=2)}")
    # Convert the first item in data to OSV schema

    # Convert to intermediate OSV dictionary format
    osv_data = convert_to_osv(cvefixesdb_data)
    # Process severity items
    severity = [osv.SeverityItem(type=item["type"], score=item["score"]) for item in osv_data.get("severity", [])]

    database_specific_dict = {}
    if "database_specific" in osv_data:
        if "repositories" in osv_data["database_specific"]:
            database_specific_dict["repositories"] = osv_data["database_specific"]["repositories"]
        if "cwe_details" in osv_data["database_specific"]:
            database_specific_dict["cwe_details"] = osv_data["database_specific"]["cwe_details"]
        if "nodes" in osv_data["database_specific"]:
            database_specific_dict["nodes"] = convert_to_nodes(osv_data["database_specific"]["nodes"])

        metrics = convert_to_metrics(database_specific_dict).model_dump()
        if "cvss2" in database_specific_dict:
            database_specific_dict.pop("cvss2")
        if "cvss3" in database_specific_dict:
            database_specific_dict.pop("cvss3")
        if "impact" in database_specific_dict:
            database_specific_dict.pop("impact")
        database_specific_dict["metrics"] = metrics
    # Process affected items
    affected = [
        osv.AffectedItem(
            package=osv.Package(ecosystem=item["package"].get("ecosystem"),
                                name=item["package"]["name"],
                                purl=item["package"].get("purl")),
            severity=[osv.SeverityItem(type=sev["type"], score=sev["score"]) for sev in item.get("severity", [])],
            ranges=[
                osv.RangeItem(
                    type=range_item["type"],
                    repo=range_item.get("repo"),
                    events=[
                        osv.EventIntroduced(introduced=event["introduced"]) if "introduced" in event else
                        osv.EventFixed(fixed=event["fixed"]) if "fixed" in event else osv.EventLastAffected(
                            last_affected=event["last_affected"]) if "last_affected" in event else osv.EventLimit(
                                limit=event["limit"]) if "limit" in event else None for event in range_item["events"]
                    ],
                    database_specific=range_item.get("database_specific")) for range_item in item.get("ranges", [])
            ],
            versions=item.get("versions"),
            ecosystem_specific=item.get("ecosystem_specific"),
            database_specific=item.get("database_specific")) for item in osv_data.get("affected", [])
    ]

    # Process reference items
    references = [osv.ReferenceItem(type=item["type"], url=item["url"]) for item in osv_data.get("references", [])]

    # Process credit items
    credits_data = [
        osv.CreditItem(name=item["name"], contact=item.get("contact"), type=item.get("type"))
        for item in osv_data.get("credits", [])
    ]

    # Create the OpenSourceVulnerability model instance
    return osv.OpenSourceVulnerability(schema_version=osv_data.get("schema_version"),
                                       id=osv_data["id"],
                                       modified=osv_data.get("modified"),
                                       published=osv_data.get("published"),
                                       withdrawn=osv_data.get("withdrawn"),
                                       aliases=osv_data.get("aliases"),
                                       related=osv_data.get("related"),
                                       summary=osv_data.get("summary"),
                                       details=osv_data.get("details"),
                                       severity=severity,
                                       affected=affected,
                                       references=references,
                                       credits=credits_data,
                                       database_specific=osv.TopDatabaseSpecificModel(**database_specific_dict))
