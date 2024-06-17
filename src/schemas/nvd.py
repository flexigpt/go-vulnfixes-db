from datetime import datetime
from typing import Annotated, List, Optional

from pydantic import BaseModel
from pydantic import Field
from pydantic import HttpUrl
from pydantic import StringConstraints


class CVSSv20Data(BaseModel):
    version: Annotated[str, Field(description="CVSS Version", enum=["2.0"])]
    vectorString: Annotated[
        str,
        Field(
            pattern=
            r"^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))$"
        )]
    accessVector: Annotated[str, Field(enum=["NETWORK", "ADJACENT_NETWORK", "LOCAL"])]
    accessComplexity: Annotated[str, Field(enum=["HIGH", "MEDIUM", "LOW"])]
    authentication: Annotated[str, Field(enum=["MULTIPLE", "SINGLE", "NONE"])]
    confidentialityImpact: Annotated[str, Field(enum=["NONE", "PARTIAL", "COMPLETE"])]
    integrityImpact: Annotated[str, Field(enum=["NONE", "PARTIAL", "COMPLETE"])]
    availabilityImpact: Annotated[str, Field(enum=["NONE", "PARTIAL", "COMPLETE"])]
    baseScore: Annotated[float, Field(ge=0, le=10)]
    exploitability: Optional[Annotated[
        str, Field(enum=["UNPROVEN", "PROOF_OF_CONCEPT", "FUNCTIONAL", "HIGH", "NOT_DEFINED"])]] = None
    remediationLevel: Optional[Annotated[
        str, Field(enum=["OFFICIAL_FIX", "TEMPORARY_FIX", "WORKAROUND", "UNAVAILABLE", "NOT_DEFINED"])]] = None
    reportConfidence: Optional[Annotated[
        str, Field(enum=["UNCONFIRMED", "UNCORROBORATED", "CONFIRMED", "NOT_DEFINED"])]] = None
    temporalScore: Optional[Annotated[float, Field(ge=0, le=10)]] = None
    collateralDamagePotential: Optional[Annotated[
        str, Field(enum=["NONE", "LOW", "LOW_MEDIUM", "MEDIUM_HIGH", "HIGH", "NOT_DEFINED"])]] = None
    targetDistribution: Optional[Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    confidentialityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    integrityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    availabilityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    environmentalScore: Optional[Annotated[float, Field(ge=0, le=10)]] = None


class CvssV2(BaseModel):
    source: str
    type: Annotated[str, StringConstraints(pattern=r'Primary|Secondary')]
    cvssData: CVSSv20Data
    baseSeverity: Optional[str] = None
    exploitabilityScore: Optional[Annotated[float, Field(ge=0, le=10, description="CVSS subscore value.")]] = None
    impactScore: Optional[Annotated[float, Field(ge=0, le=10, description="CVSS subscore value.")]] = None
    acInsufInfo: Optional[bool] = None
    obtainAllPrivilege: Optional[bool] = None
    obtainUserPrivilege: Optional[bool] = None
    obtainOtherPrivilege: Optional[bool] = None
    userInteractionRequired: Optional[bool] = None


class CVSSv30Data(BaseModel):
    version: Annotated[str, Field(description="CVSS Version", enum=["3.0"])]
    vectorString: Annotated[
        str,
        Field(
            pattern=
            r"^CVSS:3[.]0/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$"
        )]
    attackVector: Annotated[str, Field(enum=["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"])]
    attackComplexity: Annotated[str, Field(enum=["HIGH", "LOW"])]
    privilegesRequired: Annotated[str, Field(enum=["HIGH", "LOW", "NONE"])]
    userInteraction: Annotated[str, Field(enum=["NONE", "REQUIRED"])]
    scope: Annotated[str, Field(enum=["UNCHANGED", "CHANGED"])]
    confidentialityImpact: Annotated[str, Field(enum=["NONE", "LOW", "HIGH"])]
    integrityImpact: Annotated[str, Field(enum=["NONE", "LOW", "HIGH"])]
    availabilityImpact: Annotated[str, Field(enum=["NONE", "LOW", "HIGH"])]
    baseScore: Annotated[float, Field(ge=0, le=10)]
    baseSeverity: Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])]
    exploitCodeMaturity: Optional[Annotated[
        str, Field(enum=["UNPROVEN", "PROOF_OF_CONCEPT", "FUNCTIONAL", "HIGH", "NOT_DEFINED"])]] = None
    remediationLevel: Optional[Annotated[
        str, Field(enum=["OFFICIAL_FIX", "TEMPORARY_FIX", "WORKAROUND", "UNAVAILABLE", "NOT_DEFINED"])]] = None
    reportConfidence: Optional[Annotated[str, Field(enum=["UNKNOWN", "REASONABLE", "CONFIRMED", "NOT_DEFINED"])]] = None
    temporalScore: Optional[Annotated[float, Field(ge=0, le=10)]] = None
    temporalSeverity: Optional[Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])]] = None
    confidentialityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    integrityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    availabilityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    modifiedAttackVector: Optional[Annotated[
        str, Field(enum=["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL", "NOT_DEFINED"])]] = None
    modifiedAttackComplexity: Optional[Annotated[str, Field(enum=["HIGH", "LOW", "NOT_DEFINED"])]] = None
    modifiedPrivilegesRequired: Optional[Annotated[str, Field(enum=["HIGH", "LOW", "NONE", "NOT_DEFINED"])]] = None
    modifiedUserInteraction: Optional[Annotated[str, Field(enum=["NONE", "REQUIRED", "NOT_DEFINED"])]] = None
    modifiedScope: Optional[Annotated[str, Field(enum=["UNCHANGED", "CHANGED", "NOT_DEFINED"])]] = None
    modifiedConfidentialityImpact: Optional[Annotated[str, Field(enum=["NONE", "LOW", "HIGH", "NOT_DEFINED"])]] = None
    modifiedIntegrityImpact: Optional[Annotated[str, Field(enum=["NONE", "LOW", "HIGH", "NOT_DEFINED"])]] = None
    modifiedAvailabilityImpact: Optional[Annotated[str, Field(enum=["NONE", "LOW", "HIGH", "NOT_DEFINED"])]] = None
    environmentalScore: Optional[Annotated[float, Field(ge=0, le=10)]] = None
    environmentalSeverity: Optional[Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])]] = None


class CvssV30(CvssV2):
    cvssData: CVSSv30Data


class CVSSv31Data(BaseModel):
    version: Annotated[str, Field(description="CVSS Version", enum=["3.1"])]
    vectorString: Annotated[
        str,
        Field(
            pattern=
            r"^CVSS:3[.]1/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$"
        )]
    attackVector: Annotated[str, Field(enum=["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"])]
    attackComplexity: Annotated[str, Field(enum=["HIGH", "LOW"])]
    privilegesRequired: Annotated[str, Field(enum=["HIGH", "LOW", "NONE"])]
    userInteraction: Annotated[str, Field(enum=["NONE", "REQUIRED"])]
    scope: Annotated[str, Field(enum=["UNCHANGED", "CHANGED"])]
    confidentialityImpact: Annotated[str, Field(enum=["NONE", "LOW", "HIGH"])]
    integrityImpact: Annotated[str, Field(enum=["NONE", "LOW", "HIGH"])]
    availabilityImpact: Annotated[str, Field(enum=["NONE", "LOW", "HIGH"])]
    baseScore: Annotated[float, Field(ge=0, le=10)]
    baseSeverity: Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])]
    exploitCodeMaturity: Optional[Annotated[
        str, Field(enum=["UNPROVEN", "PROOF_OF_CONCEPT", "FUNCTIONAL", "HIGH", "NOT_DEFINED"])]] = None
    remediationLevel: Optional[Annotated[
        str, Field(enum=["OFFICIAL_FIX", "TEMPORARY_FIX", "WORKAROUND", "UNAVAILABLE", "NOT_DEFINED"])]] = None
    reportConfidence: Optional[Annotated[str, Field(enum=["UNKNOWN", "REASONABLE", "CONFIRMED", "NOT_DEFINED"])]] = None
    temporalScore: Optional[Annotated[float, Field(ge=0, le=10)]] = None
    temporalSeverity: Optional[Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])]] = None
    confidentialityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    integrityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    availabilityRequirement: Optional[Annotated[str, Field(enum=["LOW", "MEDIUM", "HIGH", "NOT_DEFINED"])]] = None
    modifiedAttackVector: Optional[Annotated[
        str, Field(enum=["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL", "NOT_DEFINED"])]] = None
    modifiedAttackComplexity: Optional[Annotated[str, Field(enum=["HIGH", "LOW", "NOT_DEFINED"])]] = None
    modifiedPrivilegesRequired: Optional[Annotated[str, Field(enum=["HIGH", "LOW", "NONE", "NOT_DEFINED"])]] = None
    modifiedUserInteraction: Optional[Annotated[str, Field(enum=["NONE", "REQUIRED", "NOT_DEFINED"])]] = None
    modifiedScope: Optional[Annotated[str, Field(enum=["UNCHANGED", "CHANGED", "NOT_DEFINED"])]] = None
    modifiedConfidentialityImpact: Optional[Annotated[str, Field(enum=["NONE", "LOW", "HIGH", "NOT_DEFINED"])]] = None
    modifiedIntegrityImpact: Optional[Annotated[str, Field(enum=["NONE", "LOW", "HIGH", "NOT_DEFINED"])]] = None
    modifiedAvailabilityImpact: Optional[Annotated[str, Field(enum=["NONE", "LOW", "HIGH", "NOT_DEFINED"])]] = None
    environmentalScore: Optional[Annotated[float, Field(ge=0, le=10)]] = None
    environmentalSeverity: Optional[Annotated[str, Field(enum=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])]] = None


class CvssV31(CvssV2):
    cvssData: CVSSv31Data


class Metrics(BaseModel):
    cvssMetricV31: Optional[List[CvssV31]] = None
    cvssMetricV30: Optional[List[CvssV30]] = None
    cvssMetricV2: Optional[List[CvssV2]] = None


class LangString(BaseModel):
    lang: str
    value: str


class Reference(BaseModel):
    url: HttpUrl
    source: Optional[str] = None
    tags: Optional[List[str]] = None


class VendorComment(BaseModel):
    organization: str
    comment: str
    lastModified: datetime


class Weakness(BaseModel):
    source: str
    type: str
    description: List[LangString]


class CpeMatch(BaseModel):
    vulnerable: bool
    criteria: str
    matchCriteriaId: Annotated[str, StringConstraints(pattern=r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
    versionStartExcluding: Optional[str] = None
    versionStartIncluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None


class Node(BaseModel):
    operator: Optional[Annotated[str, StringConstraints(pattern=r'AND|OR')]] = None
    negate: Optional[bool] = None
    cpeMatch: List[CpeMatch]


class Config(BaseModel):
    operator: Optional[Annotated[str, StringConstraints(pattern=r'AND|OR')]] = None
    negate: Optional[bool] = None
    nodes: List[Node]


class CVEItem(BaseModel):
    id: Annotated[str, StringConstraints(pattern=r'^CVE-[0-9]{4}-[0-9]{4,}$')]
    sourceIdentifier: Optional[str] = None
    vulnStatus: Optional[str] = None
    published: datetime
    lastModified: datetime
    evaluatorComment: Optional[str] = None
    evaluatorSolution: Optional[str] = None
    evaluatorImpact: Optional[str] = None
    cisaExploitAdd: Optional[datetime] = None
    cisaActionDue: Optional[datetime] = None
    cisaRequiredAction: Optional[str] = None
    cisaVulnerabilityName: Optional[str] = None
    descriptions: List[LangString]
    references: List[Reference]
    metrics: Optional[Metrics] = None
    weaknesses: Optional[List[Weakness]] = None
    configurations: Optional[List[Config]] = None
    vendorComments: Optional[List[VendorComment]] = None


class DefCVEItem(BaseModel):
    cve: CVEItem


class NVDResponse(BaseModel):
    resultsPerPage: int
    startIndex: int
    totalResults: int
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: List[DefCVEItem]
