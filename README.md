# pa-permission-time-analyzer
Reports files whose access time and modification time are both older than a cutoff, based on timestamps alone. It reads no usage data and does not judge which permissions a file needs, so a dormant result here means only that the timestamps are old. Access time is a weak signal on systems mounted with relatime, where it may not update on every read. Directories themselves are not analyzed; only files are. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-time-analyzer`

## Usage
`python3 main.py [params]`

A run over a path that does not exist, a non positive `--days` value, or an unwritable report path exits 1. An empty scan writes no report, prints a no files analyzed line, and exits 1. The report path must not be the analyzed file or a file inside the analyzed directory; such a run refuses at exit 1, so place the report outside the analyzed tree.

## Parameters
- `-h`: Show help message and exit
- `path`: The path to analyze. Can be a file or directory.
- `--days`: Number of days to consider when determining 'dormant' permissions. Default: 365.
- `--output`: File to write the report to. Default: report.txt
- `--exclude`: Path to a .gitignore-style file containing patterns to exclude from analysis. Patterns are matched against paths relative to the analyzed directory.

## License
Copyright (c) ShadowStrikeHQ
