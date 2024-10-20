"""
Script Name: Terraform Security Group Rules Import and Block Generation

Author: Pedro Romão

Description:
This script generates Terraform configuration blocks and corresponding import commands for AWS security group rules
based on data extracted from a CSV file and a JSON file. It processes security group rules to create both ingress 
and egress rules, ensuring proper matching between the Terraform configuration and existing rules in the JSON file.

Key Features:
- Parses CSV input for security group rules.
- Loads JSON rules to find matches for import commands.
- Generates Terraform blocks for ingress and egress rules.
- Creates a BAT script for executing Terraform import commands.

Date Created: 19/10/2024
"""


import pandas as pd
import json

# Function to extract description from brackets
def extract_description(value):
    if "(" in value and ")" in value:
        return value[value.find("(") + 1:value.find(")")]
    return ""

# Function to clean the value and remove any parentheses content
def clean_value(value):
    if "(" in value and ")" in value:
        return value.split("(")[0].strip()  # Return the part before the parentheses
    return value.strip()

# Function to match a terraform block to a JSON rule
def match_terraform_to_json(terraform_block, json_rules):
    # Check for specific IP address in ingress rules
    if (
        terraform_block.get("ip_protocol") is None and  # Handle None for ingress
        "cidr_ipv4" in terraform_block
    ):
        for rule in json_rules:
            if (
                rule.get("GroupId") == terraform_block.get("rule_id") and
                rule.get("IsEgress") is False and
                rule.get("IpProtocol") == "-1" and  # Match -1 for all traffic
                rule.get("FromPort") == -1 and
                rule.get("ToPort") == -1 and
                rule.get("CidrIpv4") == terraform_block.get("cidr_ipv4")  # Check for specific CIDR
            ):
                return rule

    # Check for rules that reference another security group
    if (
        terraform_block.get("ip_protocol") is None and
        "referenced_security_group_id" in terraform_block
    ):
        for rule in json_rules:
            if (
                rule.get("GroupId") == terraform_block.get("rule_id") and
                rule.get("IsEgress") is False and
                rule.get("IpProtocol") == "-1" and
                rule.get("FromPort") == -1 and
                rule.get("ToPort") == -1 and
                rule.get("ReferencedGroupInfo", {}).get("GroupId") == terraform_block.get("referenced_security_group_id")
            ):
                return rule

    # Check for egress rules specifically
    if (
        terraform_block.get("ip_protocol") == -1 and  # Check for All traffic
        terraform_block.get("cidr_ipv4") == "0.0.0.0/0"  # Check for CIDR 0.0.0.0/0
    ):
        for rule in json_rules:
            if (
                rule.get("GroupId") == terraform_block.get("rule_id") and
                rule.get("IsEgress") is True and
                rule.get("IpProtocol") == "-1" and
                rule.get("FromPort") == -1 and
                rule.get("ToPort") == -1 and
                rule.get("CidrIpv4") == "0.0.0.0/0"  # Match specific CIDR for egress
            ):
                return rule

    # Match other rules (including ingress)
    for rule in json_rules:
        terraform_protocol = terraform_block.get("ip_protocol", "")
        json_protocol = rule.get("IpProtocol", "")
        
        if isinstance(terraform_protocol, str):
            terraform_protocol = terraform_protocol.lower()
        if isinstance(json_protocol, str):
            json_protocol = json_protocol.lower()

        # Match based on protocol, ports, CIDR, and description
        description_match = (
            terraform_block.get("description") == rule.get("Description", "")
        )
        
        # Check for matching rule
        if (
            terraform_protocol == json_protocol and
            rule.get("FromPort") == terraform_block.get("from_port") and
            rule.get("ToPort") == terraform_block.get("to_port") and
            rule.get("IsEgress") == ("egress" in terraform_block.get("rule_name", "").lower()) and
            rule.get("GroupId") == terraform_block.get("rule_id")
        ):
            # Additional condition to match description or unique identifiers
            if description_match or (
                "ReferencedGroupInfo" in rule and 
                "referenced_security_group_id" in terraform_block and 
                rule["ReferencedGroupInfo"]["GroupId"] == terraform_block["referenced_security_group_id"]
            ) or (
                "PrefixListId" in rule and 
                "prefix_list_id" in terraform_block and 
                rule["PrefixListId"] == terraform_block["prefix_list_id"]
            ):
                return rule

    return None

# Main function to generate Terraform blocks and corresponding import commands
def generate_terraform_and_imports(csv_file, json_file, output_file, output_script_file):
    # Load the CSV and JSON files
    df = pd.read_csv(csv_file)
    try:
        with open(json_file, 'r') as file:
            json_rules = json.load(file)  # Directly load the list of rules
    except json.JSONDecodeError as e:
        print(f"Error reading JSON file: {e}")
        return

    terraform_blocks = []
    ingress_counters = {}
    egress_counters = {}

    # Define the GroupName to exclude
    excluded_group_name = "eks-cluster-sg-sitrd-pre-eks-cluster-01-135820731"

    # Open the BAT script file for writing the Terraform import commands
    with open(output_script_file, 'w') as script_file:
        script_file.write("@echo off\n")

        # Dictionary to count repeated security group rule IDs
        rule_id_counts = {}

        # Loop through each row in the DataFrame
        for index, row in df.iterrows():
            group_name = row['GroupName'].replace(" ", "-").lower()
            
            # Skip the excluded GroupName
            if group_name == excluded_group_name:
                continue

            is_egress = "outbound" in row['Type'].lower() or "egress" in row['Type'].lower()

            from_port = None
            to_port = None
            protocol = None
            cidr_ipv4 = "0.0.0.0/0"

            if not pd.isna(row['FromPort']) and not pd.isna(row['ToPort']):
                from_port = int(row['FromPort'])
                to_port = int(row['ToPort'])
                protocol = row['IpProtocol']
            else:
                if is_egress and pd.notna(row['IpRanges']) and "0.0.0.0/0" in clean_value(row['IpRanges']):
                    protocol = -1

            terraform_block = {
                "rule_name": f"{group_name}-temp-rule{index + 1}",  # Temporary name
                "rule_id": row['GroupId'],
                "description": "",
                "ip_protocol": protocol.lower() if isinstance(protocol, str) else protocol,
                "from_port": from_port,
                "to_port": to_port
            }

            if pd.notna(row['IpRanges']):
                terraform_block["cidr_ipv4"] = clean_value(row['IpRanges'])
                terraform_block["description"] = extract_description(row['IpRanges'])
            elif pd.notna(row['UserIdGroupPairs']):
                terraform_block["referenced_security_group_id"] = clean_value(row['UserIdGroupPairs'])
                terraform_block["description"] = extract_description(row['UserIdGroupPairs'])
            elif pd.notna(row['PrefixListIds']):
                terraform_block["prefix_list_id"] = clean_value(row['PrefixListIds'])
                terraform_block["description"] = extract_description(row['PrefixListIds'])

            # Increment counters based on egress or ingress
            if is_egress:
                if group_name not in egress_counters:
                    egress_counters[group_name] = 0
                egress_counters[group_name] += 1
                rule_name = f"{group_name}-egress{egress_counters[group_name]}"
                resource_type = "aws_vpc_security_group_egress_rule"
            else:
                if group_name not in ingress_counters:
                    ingress_counters[group_name] = 0
                ingress_counters[group_name] += 1
                rule_name = f"{group_name}-ingress{ingress_counters[group_name]}"
                resource_type = "aws_vpc_security_group_ingress_rule"

            terraform_block["rule_name"] = rule_name

            # Format the Terraform block
            terraform_txt = f"""
resource "{resource_type}" "{rule_name}" {{
  security_group_id = "{terraform_block['rule_id']}"
  ip_protocol = {terraform_block['ip_protocol']}
"""
            if from_port is not None:
                terraform_txt += f'  from_port = {from_port}\n'
            if to_port is not None:
                terraform_txt += f'  to_port = {to_port}\n'
            if "cidr_ipv4" in terraform_block:
                terraform_txt += f'  cidr_ipv4 = "{terraform_block["cidr_ipv4"]}"\n'
            if "referenced_security_group_id" in terraform_block:
                terraform_txt += f'  referenced_security_group_id = "{terraform_block["referenced_security_group_id"]}"\n'
            if "prefix_list_id" in terraform_block:
                terraform_txt += f'  prefix_list_id = "{terraform_block["prefix_list_id"]}"\n'
            if terraform_block["description"]:
                terraform_txt += f'  description = "{terraform_block["description"]}"\n'

            terraform_txt += "}\n"
            terraform_blocks.append(terraform_txt)

            # Try to find a matching JSON rule for this Terraform block
            matching_rule = match_terraform_to_json(terraform_block, json_rules)
            if matching_rule:
                rule_id = matching_rule['SecurityGroupRuleId']

                # Count occurrences of each rule ID
                if rule_id in rule_id_counts:
                    rule_id_counts[rule_id] += 1
                else:
                    rule_id_counts[rule_id] = 1

                terraform_import_command = f"terraform import {resource_type}.{rule_name} {rule_id}\n"
                script_file.write(terraform_import_command)
            else:
                print(f"Warning: No matching JSON rule found for Terraform block {rule_name}")

        script_file.write("pause\n")

    # # Quick fix just to not change all the code. Might get back to this later.
    for i in range(len(terraform_blocks)):
        block = terraform_blocks[i]
        
        # Replace None in ip_protocol with -1 and wrap tcp/udp in quotes
        block = block.replace('ip_protocol = None', 'ip_protocol = -1')  # Change None to -1
        block = block.replace('ip_protocol = tcp', 'ip_protocol = "tcp"')  # Wrap tcp in quotes
        block = block.replace('ip_protocol = udp', 'ip_protocol = "udp"')  # Wrap udp in quotes

        terraform_blocks[i] = block  # Update the block

    # Write the Terraform blocks to a text file
    with open(output_file, 'w') as file:
        file.writelines(terraform_blocks)

    print(f"Terraform blocks have been written to {output_file}")
    print(f"Terraform import script has been created: {output_script_file}")

    # Print counts of repeated rule IDs
    print("\nRepeated Security Group Rule IDs:")
    for rule_id, count in rule_id_counts.items():
        if count > 1:
            print(f"Rule ID: {rule_id} - Count: {count}")

# Example usage
csv_file = "security_rules.csv"  # Path to your CSV file
json_file = "security_group_rules.json"  # Path to your JSON file
output_file = "terraform_security_rules.txt"  # Output file for Terraform blocks
output_script_file = "terraform_import_script.bat"  # Output BAT script file for Terraform import commands
generate_terraform_and_imports(csv_file, json_file, output_file, output_script_file)
