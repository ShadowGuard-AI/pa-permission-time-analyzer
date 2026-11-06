import argparse
import os
import stat
import time
import logging
import sys
from pathlib import Path
from typing import List, Dict, Union
import pathspec
from rich.console import Console
from rich.table import Table


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Reports files whose access and modification timestamps are older than a cutoff, based on timestamps alone. No usage data is read."
    )

    parser.add_argument(
        "path",
        type=str,
        help="The path to analyze.  Can be a file or directory."
    )

    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Number of days to consider when determining 'dormant' permissions. Default: 365."
    )

    parser.add_argument(
        "--output",
        type=str,
        default="report.txt",
        help="File to write the report to. Default: report.txt"
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        help="Path to a .gitignore-style file containing patterns to exclude from analysis."
    )
    return parser


def is_excluded(path: str, exclude_patterns: pathspec.PathSpec = None) -> bool:
    """
    Checks if a given path should be excluded based on provided patterns.

    Args:
        path (str): The path to check.
        exclude_patterns (pathspec.PathSpec, optional): A PathSpec object containing exclusion patterns. Defaults to None.

    Returns:
        bool: True if the path should be excluded, False otherwise.
    """
    if exclude_patterns is None:
        return False
    return exclude_patterns.match_file(path)

def analyze_permissions(path: str, days: int, exclude_patterns: pathspec.PathSpec = None) -> List[Dict[str, Union[str, int, bool]]]:
    """
    Analyzes the permissions of files within the given path. Directories themselves are not analyzed.

    Args:
        path (str): The path to analyze.
        days (int): The number of days to consider when determining dormant permissions.
        exclude_patterns (pathspec.PathSpec, optional): A PathSpec object containing exclusion patterns. Defaults to None.

    Returns:
        List[Dict[str, Union[str, int, bool]]]: A list of dictionaries, each representing a file or directory
                                                and its permission analysis results.
    """

    results = []
    cutoff_timestamp = time.time() - (days * 24 * 60 * 60)  # Calculate cutoff timestamp

    if os.path.isfile(path):
        # A lone file is matched against the patterns by its basename
        # only, while the directory branch below matches by path
        # relative to the root. The same exclude file therefore means
        # two different things depending on how the tool was pointed.
        if not is_excluded(os.path.basename(path), exclude_patterns):
            result = analyze_file(path, cutoff_timestamp)
            if result is not None:
                results.append(result)
        return results
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if not is_excluded(os.path.relpath(full_path, path), exclude_patterns):
                    try:
                        result = analyze_file(full_path, cutoff_timestamp)
                        if result is not None:
                            results.append(result)
                    except OSError as e:
                        logging.error(f"Error analyzing {full_path}: {e}")
    else:
        logging.error(f"Path '{path}' is not a valid file or directory.")

    return results


def analyze_file(file_path: str, cutoff_timestamp: float) -> Dict[str, Union[str, int, bool]]:
    """
    Analyzes the permissions of a single file.

    Args:
        file_path (str): The path to the file.
        cutoff_timestamp (float): The timestamp to use for determining dormant permissions.

    Returns:
        Dict[str, Union[str, int, bool]]: A dictionary containing the file's permission analysis results.
    """

    try:
        stat_info = os.stat(file_path)
        last_access_time = stat_info.st_atime
        last_modified_time = stat_info.st_mtime
        permissions = stat.filemode(stat_info.st_mode)

        # Both stamps must be old, and the access stamp is the weak
        # half of that test. On a relatime mount atime lags real reads,
        # and a backup or antivirus pass that does update it makes a
        # long untouched file look used. Dormant here means neither
        # stamp moved, which is a statement about the filesystem's
        # bookkeeping as much as about people using the file.
        is_dormant = (last_access_time < cutoff_timestamp) and (last_modified_time < cutoff_timestamp)

        return {
            "file_path": file_path,
            "permissions": permissions,
            "last_access_time": last_access_time,
            "last_modified_time": last_modified_time,
            "is_dormant": is_dormant
        }
    except OSError as e:
        logging.error(f"Error getting file stats for {file_path}: {e}")
        # Return None so the caller skips this file. The report writer
        # expects every entry to carry file_path, so returning an
        # empty dict here would raise KeyError and end the run with
        # no report at all.
        return None

def load_exclude_patterns(exclude_file: str) -> pathspec.PathSpec:
    """
    Loads exclusion patterns from a .gitignore-style file.

    Args:
        exclude_file (str): Path to the exclude file.

    Returns:
        pathspec.PathSpec: A PathSpec object containing the exclusion patterns, or None if the file cannot be loaded.
    """
    try:
        with open(exclude_file, "r") as f:
            lines = f.readlines()
            return pathspec.PathSpec.from_lines("gitwildmatch", lines)
    except FileNotFoundError:
        logging.warning(f"Exclude file not found: {exclude_file}")
        return None
    except Exception as e:
        logging.error(f"Error loading exclude file {exclude_file}: {e}")
        return None

def generate_report(results: List[Dict[str, Union[str, int, bool]]], output_file: str) -> bool:
    """
    Generates a report of the permission analysis results and writes it to a file.

    Args:
        results (List[Dict[str, Union[str, int, bool]]]): A list of dictionaries containing the analysis results.
        output_file (str): The path to the output file.
    """

    try:
        with open(output_file, "w") as f:
            f.write("Permission Analysis Report\n")
            f.write("---------------------------\n")
            for result in results:
                f.write(f"File: {result['file_path']}\n")
                f.write(f"  Permissions: {result['permissions']}\n")
                f.write(f"  Last Access Time: {time.ctime(result['last_access_time'])}\n")
                f.write(f"  Last Modified Time: {time.ctime(result['last_modified_time'])}\n")
                f.write(f"  Is Dormant: {result['is_dormant']}\n")
                f.write("\n")
        logging.info(f"Report saved to {output_file}")
        return True

    except Exception as e:
        logging.error(f"Error writing report to file: {e}")
        return False

def generate_rich_table(results: List[Dict[str, Union[str, int, bool]]]) -> Table:
    """
    Generates a Rich table for displaying the analysis results.

    Args:
        results (List[Dict[str, Union[str, int, bool]]]): A list of dictionaries containing the analysis results.

    Returns:
        Table: A Rich Table object.
    """
    table = Table(title="Permission Analysis Results")
    table.add_column("File Path", style="cyan")
    table.add_column("Permissions", style="magenta")
    table.add_column("Last Access Time", style="green")
    table.add_column("Last Modified Time", style="green")
    table.add_column("Is Dormant", style="red")

    for result in results:
        table.add_row(
            result['file_path'],
            result['permissions'],
            time.ctime(result['last_access_time']),
            time.ctime(result['last_modified_time']),
            str(result['is_dormant'])
        )
    return table


def main():
    """
    Main function to execute the permission analysis tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.exists(args.path):
        logging.error(f"Error: The specified path '{args.path}' does not exist.")
        sys.exit(1)

    if args.days <= 0:
        logging.error("Error: The number of days must be a positive integer.")
        sys.exit(1)

    input_resolved = os.path.realpath(args.path)
    output_resolved = os.path.realpath(args.output)
    if output_resolved == input_resolved or (os.path.isdir(args.path) and output_resolved.startswith(input_resolved + os.sep)):
        logging.error("Error: The report path must not be the analyzed file or a file inside the analyzed directory.")
        sys.exit(1)

    exclude_patterns = None
    if args.exclude:
        exclude_patterns = load_exclude_patterns(args.exclude)

    try:
        results = analyze_permissions(args.path, args.days, exclude_patterns)

        if not results:
            logging.error("No files analyzed: nothing was scanned, so no report was written.")
            sys.exit(1)

        if not generate_report(results, args.output):
            sys.exit(1)

        console = Console()
        table = generate_rich_table(results)
        console.print(table)


    except SystemExit:
        raise
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()