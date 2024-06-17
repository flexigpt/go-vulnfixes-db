import math
from typing import List, Optional

from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator


class MethodChange(BaseModel):
    file_change_id: str = Field(..., min_length=1)
    method_change_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    signature: Optional[str] = Field(None, min_length=1)
    parameters: Optional[str] = Field(None, min_length=1)
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = None
    nloc: Optional[int] = None
    complexity: Optional[int] = None
    token_count: Optional[int] = None
    top_nesting_level: Optional[int] = None
    before_change: Optional[str] = None

    @field_validator('nloc', 'complexity', 'token_count', 'start_line', 'end_line', 'top_nesting_level', mode='before')
    @classmethod
    def convert_nan_to_none(cls, v):
        if isinstance(v, float) or isinstance(v, int):
            if math.isnan(v):
                return None
        if isinstance(v, str):
            if v.lower() == "nan" or v.lower() == "none":
                return None
        return v


class FileChange(BaseModel):
    file_change_id: str = Field(..., min_length=1)
    hash: str = Field(..., min_length=1)
    filename: str = Field(..., min_length=1)
    old_path: Optional[str] = Field(None, min_length=1)
    new_path: Optional[str] = Field(None, min_length=1)
    change_type: Optional[str] = Field(None, min_length=1)
    diff: Optional[str] = None
    # diff parsed in a dictionary containing the added and deleted lines.
    # The dictionary has 2 keys: “added” and “deleted”, each containing a list of Tuple (int, str)
    # corresponding to (number of line in the file, actual line).
    diff_parsed: Optional[str] = None
    code_after: Optional[str] = None
    code_before: Optional[str] = None
    nloc: Optional[int] = None
    complexity: Optional[int] = None
    token_count: Optional[int] = None
    programming_language: Optional[str] = Field(None, min_length=1)
    num_lines_added: Optional[int] = None
    num_lines_deleted: Optional[int] = None
    method_changes: Optional[List[MethodChange]] = []

    @field_validator('nloc', 'complexity', 'token_count', 'num_lines_added', 'num_lines_deleted', mode='before')
    @classmethod
    def convert_nan_to_none(cls, v):
        if isinstance(v, float) or isinstance(v, int):
            if math.isnan(v):
                return None
        if isinstance(v, str):
            if v.lower() == "nan" or v.lower() == "none":
                return None
        return v


class Commit(BaseModel):
    hash: str
    message: str
    repo_url: str
    author: str
    author_date: str
    author_timezone: Optional[str] = None
    committer: str
    committer_date: str
    committer_timezone: Optional[str] = None
    merge: Optional[str] = None
    parents: List[str]
    num_lines_added: str
    num_lines_deleted: str
    dmm_unit_complexity: Optional[str] = None
    dmm_unit_interfacing: Optional[str] = None
    dmm_unit_size: Optional[str] = None


class CVEFixes(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=100)
    commits: Optional[List[Commit]] = None
    changes: List[FileChange]
