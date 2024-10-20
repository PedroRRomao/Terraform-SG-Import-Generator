"""
Script Name: Terraform Security Group Generation

Author: Pedro Romão

Description:
This script generates Terraform configuration blocks for AWS security groups and their associated ingress and egress rules.
It processes CSV and JSON files to create Terraform blocks, ensuring proper structure and matching of security group rules.

Date Created: 19/10/2024
"""

import pandas as pd

# Function to convert tags from the CSV format into a dictionary
def parse_tags(tags_string):
    tags_dict = {}
    if pd.notna(tags_string):
        tags_pairs = tags_string.split(',')
        for pair in tags_pairs:
            key, value = pair.split(':', 1)  # Split only on the first colon
            tags_dict[key.strip()] = value.strip()  # Add to dictionary
    return tags_dict

# Load the CSV file
def generate_security_group_from_csv(csv_file, output_file):
    df = pd.read_csv(csv_file)

    terraform_blocks = []

    # Loop through each row in the DataFrame
    for index, row in df.iterrows():
        group_name = row['GroupName'].replace(" ", "-").lower()  # Replace spaces in group name
        vpc_id = row['VpcId']  # VPC ID
        description = row['Description']  # Description
        tags_string = row['Tags']  # Tags string

        # Use the group name directly for the resource name (without '-sg')
        resource_name = group_name

        # Parse the tags into a dictionary
        tags_dict = parse_tags(tags_string)

        # Start building the Terraform block
        terraform_txt = f"""
resource "aws_security_group" "{resource_name}" {{
  name        = "{group_name}"
  description = "{description}"
  vpc_id      = "{vpc_id}"
"""

        # Add tags block only if there are tags
        if tags_dict:
            terraform_txt += "  tags = {\n"
            for key, value in tags_dict.items():
                terraform_txt += f'    {key} = "{value}"\n'
            terraform_txt += "  }\n"

        terraform_txt += "}\n"

        terraform_blocks.append(terraform_txt)

    # Write the Terraform blocks to a text file
    with open(output_file, 'w') as file:
        file.writelines(terraform_blocks)

# Fill with your file names
csv_file = "security_groups.csv"  # Path to your CSV file
output_file = "terraform_security_groups.txt"  # Output file for Terraform blocks
generate_security_group_from_csv(csv_file, output_file)
