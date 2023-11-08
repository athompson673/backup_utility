#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
A single-file, stdlib-only, command line backup utility for Windows written in python.

Created on Fri Mar 11 13:20:15 2022

@author: Aaron Thompson
@license: CC BY 4.0
@license-url: https://creativecommons.org/licenses/by/4.0/
"""

# main imports
import argparse
from collections.abc import Iterable
from datetime import datetime
from inspect import cleandoc
import logging
from logging.handlers import MemoryHandler, RotatingFileHandler
import os
from os import stat_result
from pathlib import Path
import pickle
import re
import shutil
import stat
import sys
from time import perf_counter

__version__ = "2023-11-08" #TODO update version each major edit


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)
# handler for buffering logging messages before log file is defined
memory_handler = MemoryHandler(1e6)
logger.addHandler(memory_handler)

# DEFAULT OPTIONS
options_template = cleandoc(r"""
    #Backup job options
    #
    #lines starting with "#" are ignored
    #lines of the form "key = value" are added to the options dictionary


    #backup directory naming convention based on python datetime formatting
    #https://docs.python.org/3/library/datetime.html
    format = {format}

    #skip backup if no files are changed? True, False
    skip = {skip}

    #follow symbolic links?
    follow_symlinks = {follow_symlinks}

    #file operation error behavior: [Ignore, Warn, Fail]
    errors = {errors}

    #log file location (leaving this empty disables logging to file)
    logfile = {logfile}

    #log file verbosity: [DEBUG, INFO, WARNING, ERROR, CRITICAL]
    loglevel = {loglevel}
    
    #backup retention policy: [ALL, LAST_N, ] #TODO add more retention policies
    retention_policy = {retention_policy}
    
    #backup retention policy arg: number
    retention_policy_arg = {retention_policy_arg}
""")

default_options = {"format": "%Y%m%d-%H%M%S",
                   "skip": "True",
                   "follow_symlinks": "True",
                   "errors": "Warn",
                   "logfile": "",
                   "loglevel": "INFO",
                   "retention_policy": "ALL", #Default to no automatic deletion
                   "retention_policy_arg":  100} #retention ALL ignores this parameter


# DEFAULT FILTERS
filter_default = cleandoc(r"""
    #Backup file/directory configuration:
    #    blocklist file includes filters for files/directories to be skipped
    #    allowlist file includes filters for files/directories which should
    #       be included, overriding the blocklist.
    #
    #    Blank lines and lines starting with "#" are skipped
    #    One filter per line: exact file or directory matches
    #    Lines containing "^" are python style regex filters
    #
    #    Example: filter a specific file
    #        C:\Users\uname\Documents\temporary.txt
    #    Example: filter an entire directory (and sub-directories)
    #        C:\Users\uname\AppData\
    #    Example: regex filter for selecting .log files from a project directory
    #        ^C:\\Users\\uname\\project\\*\.log$
""")


# TODO test robustness
def get_config(dest: Path) -> dict[str, str]:
    """
    Get backup options from file in destination directory.
    Create default files if none exist.
    """
    op = (dest / "BackupOptions.txt")
    if op.exists() and op.is_file():
        logger.debug("reading config")
        with open(op) as f:
            options = list(f)
            options = [s.strip() for s in options]  # strip whitespace
            options = [s for s in options if s and not s.startswith("#")]  # strip empty and comments
            options = {line.split("=")[0].strip(): line.split("=")[1].strip() for line in options if '=' in line}

        for option in default_options:
            if option not in options:
                logger.warning(f"option:{option} missing from BackupOptions.txt: using default: {default_options[option]}")
                options[option] = default_options[option]

        logger.debug(f"config={options}")
        return options
    else:
        logger.info("creating default config file")
        with open(op, "w") as f:
            f.write(options_template.format(**default_options))
        return default_options


def swap_logger(options: dict[str, str]) -> None:
    """
    Swap the initial logging MemoryHandler for a RotatingFileHandler
    if configured in the backup options file
    """
    # setup logger file handler options here and append buffered logs
    if options['logfile']:
        logger.debug("setting up rotating log file handler")

        file_handler = RotatingFileHandler(options['logfile'], maxBytes=2**20, backupCount=10)
        try:
            level = {"DEBUG": logging.DEBUG,
                     "INFO": logging.INFO,
                     "WARNING": logging.WARNING,
                     "ERROR": logging.ERROR,
                     "CRITICAL": logging.CRITICAL}[options["loglevel"]]
        except KeyError:
            logger.warning(f"{options['loglevel']} is not a valid 'loglevel': defaulting to INFO")
            level = logging.INFO
        file_handler.setLevel(level)
        file_handler.addFilter(lambda record: record.levelno >= level)  # to filter prior logs coming from the buffer
        file_handler.setFormatter(formatter)

        logger.debug("swapping out memory handler for file handler")
        logger.addHandler(file_handler)
        logger.removeHandler(memory_handler)

        memory_handler.setTarget(file_handler)
        memory_handler.flush()


def get_filter_lists(dest: Path) -> tuple[list[str], list[str]]:
    """
    Get Block and Allow filters from files in destination directory
    """
    res = []
    for fn in ("AllowList.txt", "BlockList.txt"):
        fp = (dest / fn)
        if fp.exists() and fp.is_file():
            logger.debug(f"reading {fn}")
            with open(fp) as f:
                l = [s.strip() for s in list(f)]  # strip whitespace
                res.append([s for s in l if s and not s.startswith("#")])  # strip empty and comments
        else:
            logger.info("creating default allowlist file")
            with open(fp, "w") as f:
                f.write(filter_default)
            res.append([])
    return tuple(res)  # allowlist, blocklist


def match_filter(file: str, pattern: str, src: Path) -> bool:
    """
    Match single file path against single filter from filter files
    """
    if "^" in pattern:
        return bool(re.match(pattern, file))
    file = Path(file)
    pattern = Path(pattern)
    if not pattern.is_absolute():  # assume relative to src
        pattern = src / pattern
    if pattern.is_dir():
        return file.is_relative_to(pattern)
    if pattern.is_file():
        return pattern.samefile(file)
    return False


# TODO Test file filtering
def filter_files(files: dict[str, stat_result],
                 src: Path,
                 blocklist: Iterable[str],
                 allowlist: Iterable[str]) -> dict[str, stat_result]:
    """
    apply block and allow filters to the list of file paths in the
    potential new backup
    """

    names = set(files.keys())

    filtered = {}
    for file in names:
        if not any(match_filter(file, pattern, src) for pattern in blocklist):
            filtered[file] = files[file]
        else:
            logger.debug(f"blocklisted: {file}")

    for file in names:
        if any(match_filter(file, pattern, src) for pattern in allowlist):
            filtered[file] = files[file]
            logger.debug(f"allowlisted: {file}")

    return filtered
    
    
def list_prior_backups(dest: Path, format: str) -> list[Path]:
    """
    list all backups within the destination directory in reverse chronological order (newest first)
    """
    paths = []
    for path in dest.iterdir():
        # only look at directories of the correct name format
        if not path.is_dir():
            continue
        # stats file must also exist
        stats_file = (path / ("backup.p"))
        if not stats_file.is_file():
            continue
        try: #folder name must match datetime format
            datetime.strptime(path.name, format)
        except ValueError:
            continue
        paths.append(path)
    paths.sort(key=lambda path: datetime.strptime(path.name, format), reverse=True)
    return paths


def get_prior_backup(dest: Path, format: str) -> tuple[dict[str, stat_result], Path]:
    """
    find the most recent backup within the destination directory, and
    extract the file stats from the pickle file.
    """

    past_backups = list_prior_backups(dest, format)
    if past_backups:
        most_recent_stats = past_backups[0]/"backup.p"
        logger.debug(f"opening prior backup stats: {most_recent_stats}")
        with open(most_recent_stats, 'rb') as f:
            most_recent = pickle.load(f)
        if __version__ > most_recent["version"]: #TODO address future version incompatibility
            pass # no changes as of 20231108
        return most_recent["stats"], past_backups[0] / most_recent["name"]

    else:
        logger.debug(f"no prior backup to link.")
        return {}, Path()


def compare_stat_result(a: stat_result, b: stat_result) -> bool:  # ignore things like access time and metadata change time
    """
    used to determine if a file is modified
    """
    return all([
        a.st_size == b.st_size,
        a.st_ino == b.st_ino,
        a.st_dev == b.st_dev,
        a.st_mtime == b.st_mtime
    ])


# TODO testing accuracy and robustness (multiarch)
def compare_stats(new: dict[str, stat_result], old: dict[str, stat_result]) -> tuple[bool, list[str], list[str], list[str]]:
    """
    Based on comparing os.stat() of the old backup to the current target:
     - determine if any files are modified (can we skip this backup?)
     - record the directory structure
     - make a list of modified files for copying
     - make a list of unmodified files for linking
    """
    is_modified = False  # is there any change at all from the old backup
    dirs = []  #list[str] (src) create all dirs because they can't be linked so just copy all
    do_link = []  #list[tuple[str,str]] (src, dst) #for unchanged and moved files
    do_copy = []  #list[str] (src) #dst is always same as src #for new and modified files

    # reverse mapping to find renamed (moved) files
    old_names_by_ino = {}
    for k, v in old.items():
        if v.st_ino in old_names_by_ino:
            old_names_by_ino[v.st_ino].append(k)
        else:
            old_names_by_ino[v.st_ino] = [k]

    # walk the new items
    for k, v in new.items():
        if stat.S_ISDIR(v.st_mode):
            dirs.append(k)
        elif v.st_ino in old_names_by_ino:  # inode existed previously
            if compare_stat_result(old[old_names_by_ino[v.st_ino][0]], v):  # stat unchanged (unmodified)
                if k in old_names_by_ino[v.st_ino]:  # name unchanged
                    do_link.append((k, k))  # (src, dst)
                else:  # name changed (moved)
                    do_link.append((old_names_by_ino[v.st_ino][0], k))  # (src, dst)
                    is_modified = True
            else:  # file modified (stat changed)
                do_copy.append(k)
                is_modified = True
        else:  # inode did not previously exist (new file)
            do_copy.append(k)
            is_modified = True

    return (is_modified, dirs, do_link, do_copy)


def delete_backup(backup: Path, options: dict[str]) -> None:
    logger.info(f"deleting old backup: {backup}")
    if options['errors'].lower() == "ignore":
        shutil.rmtree(backup, ignore_errors=True)
    elif options['errors'].lower() == "warn":
        pass
        try:
            shutil.rmtree(backup)
        except Exception as e:
            logger.exception(e, exc_info=True)
    elif options['errors'].lower() == "fail":
        try:
            shutil.rmtree(backup)
        except Exception as e:
            logger.exception(e, exc_info=True)
            raise


def do_backup(src: Path, dest: Path) -> bool: #return was a new backup created?
    """
    Full backup procedure
    """
    logger.info("Starting backup")
    start_time = perf_counter()
    os.chdir(dest) #make relative file access easy (for log file mostly)

    #### Sanity checks
    # ensure dest exists
    logger.debug("ensuring destination path exists")
    if not dest.is_dir():
        logger.critical("destination path given is not a vaild directory")
        raise RuntimeError
    logger.debug("ensuring souce path exists")
    if not src.is_dir():
        logger.critical("souce path given is not a vaild directory")
        raise RuntimeError
    # don't try to backup recursively  # TODO test this
    logger.debug("ensuring destination is not inside source")
    if dest.is_relative_to(src):
        logger.critical("backup source directory cannot contain destination directory")
        raise RuntimeError

    #### Read data from dest
    options = get_config(dest)
    swap_logger(options)
    allowlist, blocklist = get_filter_lists(dest)
    # get old backup
    old_stats, old_backup = get_prior_backup(dest, options["format"])

    #### setup options
    follow_symlinks = options["follow_symlinks"].lower() in ("true", "yes", "y")

    def handle_error(e: Exception) -> None:
        if options['errors'].lower() == "ignore":
            pass
        elif options['errors'].lower() == "warn":
            logger.exception(e, exc_info=True)
        elif options['errors'].lower() == "fail":
            logger.exception(e, exc_info=True)
            raise

    #### read src data
    logger.debug("walking source directory")
    # get target dir stats
    target_stats = {}

    # better file stats scan than recursive glob?
    # qwery journal for file modifications?
    # options to throttle file operations to prevent system slowdown with disk usage?
    # os.walk is not faster.
    # os.scandir produces dict_result without needed stats,
    #  requiring extra stat() call anyway. Not faster.
    for i in src.rglob('*'):
        try:
            if follow_symlinks:
                target_stats[str(i)] = i.stat()  #python 3.10 and up can use follow_symlinks arg
            else:
                target_stats[str(i)] = i.lstat()
        except Exception as e:
            handle_error(e)

    #### determine files to copy / link
    logger.debug("filtering target files")
    # filter stats
    new_stats = filter_files(target_stats, src, blocklist, allowlist)

    # convert absolute to relative path for processing
    new_stats = {str(Path(k).relative_to(src)): v for k, v in new_stats.items()}

    logger.debug("comparing source directory to old backups")

    # compare old - new
    is_modified, dirs, do_link, do_copy = compare_stats(new_stats, old_stats)
    # optionally skip this backup
    if options["skip"].lower() in ("true", "yes", "y") and not is_modified:
        logger.info("Skipping backup: directory is unchanged")
        return  False

    #### create the new backup
    # new directory
    this_backup = (dest / datetime.now().strftime(options['format'])) / src.name
    this_backup.mkdir(parents=True, exist_ok=False)
    logger.info(f"Creating new backup: {this_backup}")

    logger.debug("creating dir structure")
    # build the structure
    for d in dirs:
        (this_backup / d).mkdir(parents=True, exist_ok=True)

    # copy files
    copy_size = 0
    for i in sorted(do_copy):  # sorted() makes finding a specific file in debug output easier
        logger.debug(f"copying {i}")
        try:
            shutil.copy2(src / i, this_backup / i, follow_symlinks=follow_symlinks)
            copy_size += (this_backup/i).stat(follow_symlinks=follow_symlinks).st_size
        except Exception as e:
            handle_error(e)
            del new_stats[i]  # delete from stats to indicate file is not present in this backup
    logger.info(f"copied {copy_size} bytes of new data")

    for s, d in sorted(do_link):
        logger.debug(f"linking {d}")
        try:
            os.link(old_backup / s, this_backup / d, follow_symlinks=follow_symlinks)
        except Exception as e:
            handle_error(e)
            del new_stats[d]  # delete from stats to indicate file is not present in this backup

    #### save backup metadata
    logger.debug("writing backup stats")
    with open(this_backup.parent / ("backup.p"), "wb") as f:
        pickle.dump({  #save metadata of this backup TODO determine additional useful metadata
            "stats": new_stats,
            "name": this_backup.name,
            "version": __version__,
            },f)

    #### trim old backups
    prior_backups = list_prior_backups(dest, options["format"])
    ## backup file size
    #unique_files = {}
    #for backup in prior_backups:
    #    with open(backup/"backup.p", "rb") as f:
    #        for stat_result in pickle.load(f)["stats"].values():
    #            if not stat.S_ISDIR(stat_result.st_mode):
    #                unique_files[stat_result.st_ino] = stat_result.st_size
    
    if options["retention_policy"] ==  "ALL":
        logger.debug("retention policy: ALL. no old backups will be Deleted")
        
    elif options["retention_policy"] ==  "LAST_N":
        keep_backups = int(options["retention_policy_arg"])
        
        logger.debug(f"retention policy: LAST_N. {min(len(prior_backups),keep_backups)} old backups will be kept")
        to_delete = prior_backups[keep_backups:]
        logger.info(f"retention policy: LAST_N. {len(to_delete)} old backups will be deleted") #info only when deleting backups
        for backup in to_delete:
            delete_backup(backup, options)
            
    logger.info(f"Backup complete in {perf_counter()-start_time:.1f} seconds")
    return  True


def main():
    """
    parse command line args, and call the main backup procedure.
    """
    parser = argparse.ArgumentParser(description="A single-file zero-dependency python backup utility.",
                                     epilog=f"version: {__version__}")
    parser.add_argument('Destination', type=Path, help="Destination for backup files including backup config files")
    parser.add_argument('Source', nargs="?", type=Path, help="Path to directory which will be backed up. Omit this to generate default config files in the destination directory without performing a backup.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--verbose', action="store_true", help="set console logging verbosity to DEBUG")
    group.add_argument('-q', '--quiet', action="store_true", help="set console logging verbosity to ERROR")
    args = parser.parse_args()

    if args.quiet:
        console_handler.setLevel(logging.ERROR)
    elif args.verbose:
        console_handler.setLevel(logging.DEBUG)

    logger.debug(f"backup_utility.main version {__version__}")
    logger.debug(f"got args: {args}")

    if args.Source is None:
        logger.info("no backup source given: ensuring config files exist in destination directory.")
        get_config(args.Destination)
    else:
        old_cwd = os.getcwd()
        try:
            do_backup(args.Source, args.Destination)
        finally:
            os.chdir(old_cwd)


if __name__ == "__main__":
    main()
