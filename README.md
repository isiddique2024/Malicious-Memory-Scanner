# Malicious Memory Scanner

## Overview

Malicious Memory Scanner is a C++ application designed to query the memory of running processes for malicious implants. 
The scanner takes the Process ID of the process you want to scan as a command-line argument and performs a deep scan analysis to detect IOCs.

## Features

- **Command-Line Interface**: Simple CLI for specifying the process ID to scan.
- **Signature Scanning**: Scans executable regions for known malicious signatures.
- **Unverified Module Reporting**: Any loaded module without a valid signature will be reported.
- **Advanced Reporting**: Advanced details such as the Allocation Base, Base Address, Region Size, Commit Size, Found Signatures, etc.
- **Memory Dumps**: Dumps detected malicious implants into a folder called "malicious_dumps"

## Usage

    scanner.exe <PID> 

## Planned Features
- **Asynchronous Multi-process Scanning**: Currently the scanner synchronously scans 1 process, soon it will be multi-process and asynchronous.
- **IAT Lookup**: If the executable region has an IAT/EAT (Import Address Table/Export Address Table) it will be present on the scan report.
- **Quick Scan**: Currently the scanner iterates through all memory regions for malicious implants, this can be quite time consuming especially on larger applications. I plan to implement a quick scan option to speed up the scanning process.

  
## License

This project is open source and available under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
