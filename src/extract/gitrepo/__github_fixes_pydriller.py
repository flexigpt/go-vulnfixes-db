from typing import List, Optional, Tuple
import uuid

# from guesslang import Guess
# from pydriller import Repository

from ...logging.logging import logger
# Import your schema models
from ...schemas.fixes import Commit
from ...schemas.fixes import CVEFixes
from ...schemas.fixes import FileChange
from ...schemas.fixes import MethodChange

NUM_WORKERS = 4


def guess_pl(code: str) -> str:
    """
    :returns guessed programming language of the code
    """
    # if code:
    #     return Guess().language_name(code.strip())
    return 'unknown'


def clean_string(signature: str) -> str:
    return signature.strip().replace(' ', '')


def get_method_code(source_code: Optional[str], start_line: int, end_line: int) -> Optional[str]:
    try:
        if source_code is not None:
            code = '\n'.join(source_code.split('\n')[int(start_line) - 1:int(end_line)])
            return code
    except Exception as e:
        logger.warning('Problem while extracting method code from the changed file contents: %s', e)
    return None


def changed_methods_both(file) -> Tuple[set, set]:
    """
    Return the set of methods that were changed.
    :return: sets of changed methods (new and old)
    """
    new_methods = file.methods
    old_methods = file.methods_before
    added = file.diff_parsed["added"]
    deleted = file.diff_parsed["deleted"]

    methods_changed_new = {y for x in added for y in new_methods if y.start_line <= x[0] <= y.end_line}
    methods_changed_old = {y for x in deleted for y in old_methods if y.start_line <= x[0] <= y.end_line}
    return methods_changed_new, methods_changed_old


def get_methods(file, file_change_id: str) -> Optional[List[MethodChange]]:
    """
    Returns the list of methods in the file.
    """
    file_methods = []
    try:
        if file.changed_methods:
            methods_after, methods_before = changed_methods_both(file)
            if methods_before:
                for mb in methods_before:
                    if file.source_code_before is not None and mb.name != '(anonymous)':
                        method_before_code = get_method_code(file.source_code_before, mb.start_line, mb.end_line)
                        method_before_row = MethodChange(method_change_id=str(uuid.uuid4().fields[-1]),
                                                         file_change_id=file_change_id,
                                                         name=mb.name,
                                                         signature=mb.long_name,
                                                         parameters=mb.parameters,
                                                         start_line=mb.start_line,
                                                         end_line=mb.end_line,
                                                         code=method_before_code,
                                                         nloc=mb.nloc,
                                                         complexity=mb.complexity,
                                                         token_count=mb.token_count,
                                                         top_nesting_level=mb.top_nesting_level,
                                                         before_change='True')
                        file_methods.append(method_before_row)

            if methods_after:
                for mc in methods_after:
                    if file.source_code is not None and mc.name != '(anonymous)':
                        changed_method_code = get_method_code(file.source_code, mc.start_line, mc.end_line)
                        changed_method_row = MethodChange(method_change_id=str(uuid.uuid4().fields[-1]),
                                                          file_change_id=file_change_id,
                                                          name=mc.name,
                                                          signature=mc.long_name,
                                                          parameters=mc.parameters,
                                                          start_line=mc.start_line,
                                                          end_line=mc.end_line,
                                                          code=changed_method_code,
                                                          nloc=mc.nloc,
                                                          complexity=mc.complexity,
                                                          token_count=mc.token_count,
                                                          top_nesting_level=mc.top_nesting_level,
                                                          before_change='False')
                        file_methods.append(changed_method_row)
        if file_methods:
            return file_methods
    except Exception as e:
        logger.warning('Problem while fetching the methods: %s', e)
    return None


def get_files(commit) -> Tuple[List[FileChange], List[MethodChange]]:
    """
    Returns the list of files of the commit.
    """
    commit_files = []
    commit_methods = []
    try:
        logger.info('Extracting files for %s', commit.hash)
        if commit.modified_files:
            for file in commit.modified_files:
                logger.debug('Processing file %s in %s', file.filename, commit.hash)
                programming_language = guess_pl(file.source_code)
                file_change_id = str(uuid.uuid4().fields[-1])

                file_row = FileChange(file_change_id=file_change_id,
                                      hash=commit.hash,
                                      filename=file.filename,
                                      old_path=file.old_path,
                                      new_path=file.new_path,
                                      change_type=file.change_type,
                                      diff=file.diff,
                                      diff_parsed=file.diff_parsed,
                                      num_lines_added=file.added_lines,
                                      num_lines_deleted=file.deleted_lines,
                                      code_after=file.source_code,
                                      code_before=file.source_code_before,
                                      nloc=file.nloc,
                                      complexity=file.complexity,
                                      token_count=file.token_count,
                                      programming_language=programming_language)
                commit_files.append(file_row)
                file_methods = get_methods(file, file_change_id)

                if file_methods is not None:
                    commit_methods.extend(file_methods)
        else:
            logger.info('The list of modified_files is empty')

        return commit_files, commit_methods

    except Exception as e:
        logger.warning('Problem while fetching the files: %s', e)
    return [], []


def extract_commits(repo_url: str, hashes: List[str]) -> CVEFixes:
    """
    This function extracts git commit information for the specified list of hashes.
    :param repo_url: URL of the repository
    :param hashes: list of hashes of the commits to collect
    :return: CVEFixes object containing commit and file change data
    """
    repo_commits = []
    repo_files = []
    repo_methods = []

    if 'github' in repo_url:
        repo_url += '.git'

    logger.debug('Extracting commits for %s with %s worker(s) looking for the following hashes:', repo_url, NUM_WORKERS)

    single_hash = None
    if len(hashes) == 1:
        single_hash = hashes[0]
        hashes = None

    for commit in Repository(path_to_repo=repo_url, only_commits=hashes, single=single_hash,
                             num_workers=NUM_WORKERS).traverse_commits():
        logger.debug('Processing %s', commit.hash)
        try:
            commit_row = Commit(
                hash=commit.hash,
                repo_url=repo_url,
                author=commit.author.name,
                author_date=str(commit.author_date),
                author_timezone=commit.author_timezone,
                committer=commit.committer.name,
                committer_date=str(commit.committer_date),
                committer_timezone=commit.committer_timezone,
                message=commit.msg,
                merge=commit.merge,
                parents=commit.parents,
                num_lines_added=str(commit.insertions),
                num_lines_deleted=str(commit.deletions),
                dmm_unit_complexity=commit.dmm_unit_complexity,
                dmm_unit_interfacing=commit.dmm_unit_interfacing,
                dmm_unit_size=commit.dmm_unit_size,
            )
            commit_files, commit_methods = get_files(commit)
            repo_commits.append(commit_row)
            repo_files.extend(commit_files)
            repo_methods.extend(commit_methods)
        except Exception as e:
            logger.warning('Problem while fetching the commits: %s', e)

    cve_fixes = CVEFixes(cve_id="example_cve_id", commits=repo_commits, changes=repo_files)

    return cve_fixes
