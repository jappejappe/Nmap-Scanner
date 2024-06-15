# Nmap-Scanner
This script uses Nmap to scan specified IPs and ports, parsing the output to identify open, closed, and filtered ports. It then queries the NVD for CPE and CVE information related to detected services and versions. Results, including CVE details like severity and exploitability, are printed.

Nmap and NVD Integration Script
This script integrates Nmap and NVD (National Vulnerability Database) to scan network hosts and retrieve information about potential vulnerabilities. It performs the following tasks:

- Scan Network Hosts: Uses Nmap to scan specified IP addresses and ports.
- Parse Scan Results: Processes the Nmap output to extract information about open, closed, and filtered ports.
- Query NVD: Searches the NVD for Common Platform Enumeration (CPE) and Common Vulnerabilities and Exposures (CVE) based on the services and versions identified during the Nmap scan.
- Display Results: Prints the details of the vulnerabilities found, including their severity, description, and exploitability.

Key Features
  Nmap Integration: Leverages the Nmap tool to perform network scans and gather data on open ports and running services.
  NVD Integration: Utilizes the nvdlib library to query the NVD for known vulnerabilities related to the identified services.
  Detailed Output: Provides a detailed summary of vulnerabilities, including CVE IDs, risk levels, discovery dates, descriptions, and exploitability scores.

Libraries Used
  nmap: For network scanning.
  nvdlib: For querying the NVD.
  subprocess: For executing shell commands.
  re: For regular expression operations.
  copy: For handling data structures.

Usage
  To run the script, ensure that the necessary libraries are installed and execute it in a Python environment. Follow the prompts to input the target IP address and ports for scanning.
