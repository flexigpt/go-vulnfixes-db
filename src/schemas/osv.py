from typing import Annotated, List, Literal, Optional, Union

from pydantic import AnyUrl
from pydantic import BaseModel
from pydantic import Field
from pydantic import StringConstraints

from .nvd import Metrics
from .nvd import Node

type TimeStamp = Annotated[str, StringConstraints(pattern=r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?(\.[0-9]+)?Z")]


class SeverityItem(BaseModel):
    type: Literal["CVSS_V2", "CVSS_V3", "CVSS_V4"]
    score: str


class Package(BaseModel):
    ecosystem: Optional[str] = None
    name: str
    purl: Optional[str] = None


class EventIntroduced(BaseModel):
    introduced: str


class EventFixed(BaseModel):
    fixed: str


class EventLastAffected(BaseModel):
    last_affected: str


class EventLimit(BaseModel):
    limit: str


class RangeItem(BaseModel):
    type: Literal["GIT", "SEMVER", "ECOSYSTEM"]
    repo: Optional[str] = None
    events: Annotated[List[Union[EventIntroduced, EventFixed, EventLastAffected, EventLimit]], Field(min_items=0)]
    database_specific: Optional[dict] = None


class AffectedItem(BaseModel):
    package: Package
    severity: Optional[List[SeverityItem]] = None
    ranges: Optional[List[RangeItem]] = None
    versions: Optional[List[str]] = None
    ecosystem_specific: Optional[dict] = None
    database_specific: Optional[dict] = None


class ReferenceItem(BaseModel):
    type: Literal["ADVISORY", "ARTICLE", "DETECTION", "DISCUSSION", "REPORT", "FIX", "INTRODUCED", "GIT", "PACKAGE",
                  "EVIDENCE", "WEB"]
    url: Annotated[str, AnyUrl]


class CreditItem(BaseModel):
    name: str
    contact: Optional[List[str]] = None
    type: Optional[Literal["FINDER", "REPORTER", "ANALYST", "COORDINATOR", "REMEDIATION_DEVELOPER",
                           "REMEDIATION_REVIEWER", "REMEDIATION_VERIFIER", "TOOL", "SPONSOR", "OTHER"]] = None


class CweDetailsModel(BaseModel):
    cwe_id: str
    name: str
    description: Optional[str] = ""
    source: Optional[str] = ""
    url: Optional[str] = ""
    is_category: Optional[bool] = None
    extended_description: Optional[str] = None

class RepositoryModel(BaseModel):
    url: str
    name: str
    description: Optional[str] = None
    date_created: str
    date_last_push: str
    owner: str
    forks_count: str
    stars_count: str
    repo_language: Optional[str] = None


class SourceInfoModel(BaseModel):
    govuln: bool
    nvd: bool
    cvefixes: bool
class TopDatabaseSpecificModel(BaseModel):
    metrics:  Optional[Metrics] = None
    cwe_details: Optional[List[CweDetailsModel]] = None
    repositories: Optional[List[RepositoryModel]] = None
    nodes:  Optional[List[Node]] = None
    vulndb_data: Optional[dict] = None
    datasources: Optional[SourceInfoModel] = None

    class Config:
        extra = "allow"

class OpenSourceVulnerability(BaseModel):
    schema_version: Optional[str] = None
    id: str
    modified: Optional[TimeStamp] = None
    published: Optional[TimeStamp] = None
    withdrawn: Optional[TimeStamp] = None
    aliases: Optional[List[str]] = None
    related: Optional[List[str]] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: Optional[List[SeverityItem]] = None
    affected: Optional[List[AffectedItem]] = None
    references: Optional[List[ReferenceItem]] = None
    credits: Optional[List[CreditItem]] = None
    database_specific: Optional[TopDatabaseSpecificModel] = None
