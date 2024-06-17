from typing import List, Optional

# from ...logging.logging import logger
from ...schemas import nvd
from ...schemas import osv


# Convert LangString to string
def convert_lang_string(lang_strings: List[nvd.LangString]) -> str:
    return " ".join([ls.value for ls in lang_strings])


# Function to map NVD tags to OSV tags
def map_tag(tags: Optional[List[str]], osv_tags: List[str]) -> str:
    if tags:
        for tag in tags:
            if tag in osv_tags:
                return tag
    return "WEB"


# Convert Reference to ReferenceItem
def convert_references(references: List[nvd.Reference]) -> List[osv.ReferenceItem]:
    osv_tags = [
        "ADVISORY", "ARTICLE", "DETECTION", "DISCUSSION", "REPORT", "FIX", "INTRODUCED", "GIT", "PACKAGE", "EVIDENCE",
        "WEB"
    ]
    return [osv.ReferenceItem(type=map_tag(ref.tags, osv_tags), url=str(ref.url)) for ref in references]


# Convert CvssV2, CvssV30, and CvssV31 to SeverityItem
def convert_cvss_metrics(metrics: nvd.Metrics) -> List[osv.SeverityItem]:
    severity_items = []
    if metrics.cvssMetricV2:
        for cvss in metrics.cvssMetricV2:
            severity_items.append(osv.SeverityItem(type="CVSS_V2", score=str(cvss.cvssData.baseScore)))
    if metrics.cvssMetricV30:
        for cvss in metrics.cvssMetricV30:
            severity_items.append(osv.SeverityItem(type="CVSS_V3", score=str(cvss.cvssData.baseScore)))
    if metrics.cvssMetricV31:
        for cvss in metrics.cvssMetricV31:
            severity_items.append(osv.SeverityItem(type="CVSS_V3", score=str(cvss.cvssData.baseScore)))
    return severity_items


# Convert Weakness to CweDetailsModel
def convert_weaknesses(weaknesses: List[nvd.Weakness]) -> List[osv.CweDetailsModel]:
    if not weaknesses:
        return []
    return [
        osv.CweDetailsModel(
            cwe_id=weak.source,
            name=weak.type,
            description=convert_lang_string(weak.description),
        ) for weak in weaknesses
    ]


# Populate the TopDatabaseSpecificModel
def convert_database_specific(metrics: nvd.Metrics, weaknesses: List[nvd.Weakness],
                              configs: List[nvd.Config]) -> osv.TopDatabaseSpecificModel:
    nodes = []
    if configs:
        for c in configs:
            nodes.extend(c.nodes)

    return osv.TopDatabaseSpecificModel(metrics=metrics, cwe_details=convert_weaknesses(weaknesses), nodes=nodes)


def convert_nvd_cve_item_to_osv(cve_item: nvd.CVEItem) -> osv.OpenSourceVulnerability:

    # Create the OpenSourceVulnerability instance
    osvitem = osv.OpenSourceVulnerability(schema_version="1.6.3",
                                          id=cve_item.id,
                                          modified=cve_item.lastModified.isoformat() + "Z",
                                          published=cve_item.published.isoformat() + "Z",
                                          aliases=[],
                                          related=[],
                                          summary=convert_lang_string(cve_item.descriptions),
                                          details=cve_item.evaluatorComment,
                                          severity=convert_cvss_metrics(cve_item.metrics) if cve_item.metrics else [],
                                          affected=[],
                                          references=convert_references(cve_item.references),
                                          credits=[],
                                          database_specific=convert_database_specific(
                                              cve_item.metrics, cve_item.weaknesses, cve_item.configurations))

    # logger.info(osvitem.model_dump_json(indent=2, exclude_none=True))
    return osvitem
