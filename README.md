# pa-permission-time-analyzer
Analyzes permission usage patterns over time to identify dormant or underutilized permissions that can be revoked or downsized to reduce the attack surface. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-time-analyzer`

## Usage
`./pa-permission-time-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--days`: Number of days to consider when determining 
- `--output`: File to write the report to. Default: report.txt
- `--exclude`: Path to a .gitignore-style file containing patterns to exclude from analysis.

## License
Copyright (c) ShadowStrikeHQ
