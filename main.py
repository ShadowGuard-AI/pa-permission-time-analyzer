import argparse
import os
import stat
import time
import logging
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
        description="Analyzes permission usage patterns over time to identify dormant or underutilized permissions."
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
    Analyzes the permissions of files and directories within the given path.

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
        if not is_excluded(path, exclude_patterns):
            results.append(analyze_file(path, cutoff_timestamp))
        return results
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if not is_excluded(full_path, exclude_patterns):
                    try:
                        results.append(analyze_file(full_path, cutoff_timestamp))
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
        return {}

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
            return pathspec.PathSpec(lines)
    except FileNotFoundError:
        logging.warning(f"Exclude file not found: {exclude_file}")
        return None
    except Exception as e:
        logging.error(f"Error loading exclude file {exclude_file}: {e}")
        return None

def generate_report(results: List[Dict[str, Union[str, int, bool]]], output_file: str) -> None:
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

    except Exception as e:
        logging.error(f"Error writing report to file: {e}")

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
        return

    if args.days <= 0:
        logging.error("Error: The number of days must be a positive integer.")
        return

    exclude_patterns = None
    if args.exclude:
        exclude_patterns = load_exclude_patterns(args.exclude)

    try:
        results = analyze_permissions(args.path, args.days, exclude_patterns)
        generate_report(results, args.output)

        console = Console()
        table = generate_rich_table(results)
        console.print(table)


    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()