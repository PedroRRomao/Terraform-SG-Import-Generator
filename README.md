# Terraform Security Group Rules Import and Block Generation

**Author:** Pedro Romão  
**Date Created:** 19/10/2024  

## Overview
This Python script automates the generation of Terraform configuration blocks and corresponding import commands for AWS security group rules. It facilitates the management of security groups by streamlining the importation of existing rules into Terraform, allowing for consistent infrastructure as code practices in AWS cloud environments.

## Key Features

### Data Extraction
- Extracts security group rules from a provided CSV file.
- Loads existing security group rules from a JSON file, enabling seamless mapping to Terraform configurations.

### Rule Matching
- Implements a matching algorithm to correlate security group rules defined in the CSV with the JSON structure, evaluating:
  - Security group IDs
  - Ingress and egress types
  - IP protocols, including special handling for 'All traffic' rules
  - Port ranges and address types (CIDR blocks, prefix lists, and referenced security groups)

### Terraform Block Generation
- Generates Terraform resource blocks for both ingress and egress security group rules.
- Ensures proper formatting, with protocol types such as TCP and UDP enclosed in strings.

### Import Command Creation
- Creates a BAT script containing commands to import the defined security group rules into Terraform, facilitating integration into the Terraform state without losing configurations.

### Exclusion Criteria
- Allows users to define specific security group names to exclude from the import process, providing flexibility for customized environments.

### Duplicate Rule Detection
- Checks for duplicate security group rule IDs to prevent conflicts in the Terraform state file, ensuring a clean and manageable infrastructure.

## Limitations
- Designed specifically for use within the AWS cloud environment. Assumes that security group rules adhere to the structure defined in the provided CSV and JSON files.

## Dependencies
- Python 3.x
- Pandas library for CSV handling
- JSON library for reading and parsing JSON files

## Usage
To utilize this script, ensure you have a valid CSV file containing security group rules and a JSON file with existing AWS security group rules. Specify the paths for these files, along with the desired output files for Terraform blocks and the BAT script. Execute the script to generate the necessary configurations and import commands.
