Terraform Security Group Rules Import and Block Generation
Author: Pedro Romão
Date Created: 19/10/2024

Overview:
This Python script automates the generation of Terraform configuration blocks and corresponding import commands for AWS security group rules. It facilitates the management of security groups by streamlining the importation of existing rules into Terraform, allowing for consistent infrastructure as code practices in AWS cloud environments.

Key Features:

Data Extraction:
The script extracts security group rules from a provided CSV file and loads existing security group rules from a JSON file. This enables the mapping of existing rules to Terraform configurations seamlessly.

Rule Matching:
It implements a matching algorithm to correlate security group rules defined in the CSV with the JSON structure. The matching process evaluates various criteria, including:

Security group IDs
Ingress and egress types
IP protocols, including special handling for 'All traffic' rules
Port ranges and address types (CIDR blocks, prefix lists, and referenced security groups)
Terraform Block Generation:
The script generates Terraform resource blocks for both ingress and egress security group rules. It formats these blocks to conform to Terraform's syntax, ensuring that protocol types such as TCP and UDP are properly enclosed in strings.

Import Command Creation:
A corresponding BAT script is generated, containing commands to import the defined security group rules into Terraform. This ensures that all existing rules can be integrated into the Terraform state without losing configurations.

Exclusion Criteria:
Users can define specific security group names to exclude from the import process, providing flexibility for customized environments.

Duplicate Rule Detection:
The script checks for duplicate security group rule IDs to prevent conflicts in the Terraform state file, ensuring a clean and manageable infrastructure.

Limitations:
This script is designed specifically for use within the AWS cloud environment. It assumes that security group rules adhere to the structure defined in the provided CSV and JSON files.

Dependencies:

Python 3.x
Pandas library for CSV handling
JSON library for reading and parsing JSON files
Usage:
To utilize this script, ensure that you have a valid CSV file containing security group rules and a JSON file with existing AWS security group rules. Specify the paths for these files, along with the desired output files for Terraform blocks and the BAT script. Execute the script to generate the necessary configurations and import commands.

