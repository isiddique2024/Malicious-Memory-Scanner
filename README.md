# Malicious Memory Scanner

## Overview

Malicious Memory Scanner is a C++ application designed to query the memory of running processes for malicious implants. 
The scanner takes the Process ID of the process you want to scan as a command-line argument and performs a deep scan analysis to detect IOCs.

## Features

- **Command-Line Interface**: Simple CLI for specifying the process ID to scan.
- **Signature Scanning**: Scans RWX (Read-Write-Execute) regions for known malicious signatures.
- **Unverified Module Reporting**: Any loaded module without a valid signature will be reported.
- **Memory Dumps**: Dumps detected malicious implants into a folder called "malicious_dumps"

## Usage

    scanner.exe <PID> 

## Planned Features

- **Detailed Reporting**: Currently the reporting only returns the malicious base address and region size, soon I will expand on that to include more detailed reporting
- **Packed PE Detection**: If implants utilize packers such as VMProtect and Themida it will be included in the detailed reporting.
- **Quick Scan**: Currently the scanner iterates through all memory regions for malicious implants, this can be quite time consuming especially on larger applications. I plan to implement a quick scan option to speed up the scanning process.
