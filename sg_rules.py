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

def extract_description(value):
    """Extracts content within parentheses from a string."""
    return value[value.find("(") + 1:value.find(")")] if "(" in value and ")" in value else ""

def clean_value(value):
    """Cleans the value by removing content within parentheses."""
    return value.split("(")[0].strip() if "(" in value and ")" in value else value.strip()

def match_terraform_to_json(terraform_block, json_rules):
    """Matches a Terraform block to the corresponding JSON rule."""
    rule_id = terraform_block["rule_id"]
    for rule in json_rules:
        if rule_id != rule["GroupId"]:
            continue

        is_egress = rule["IsEgress"]
        if is_egress != ("egress" in terraform_block["rule_name"]):
            continue

        terraform_protocol = str(terraform_block.get("ip_protocol", "")).lower()
        json_protocol = str(rule.get("IpProtocol", "")).lower()
        
        # Check for "All traffic" rules
        if terraform_protocol != "-1" and terraform_protocol != json_protocol:
            continue

        if terraform_protocol != "-1":
            if terraform_block.get("from_port") != rule.get("FromPort") or terraform_block.get("to_port") != rule.get("ToPort"):
                continue

        # Address types validation
        terraform_address = (
            terraform_block.get("cidr_ipv4") or 
            terraform_block.get("prefix_list_id") or 
            terraform_block.get("referenced_security_group_id")
        )
        json_address = (
            rule.get("CidrIpv4") or 
            rule.get("PrefixListId") or 
            rule.get("ReferencedGroupInfo", {}).get("GroupId")
        )
        
        if terraform_address != json_address:
            continue

        # Description comparison
        if terraform_block.get("description", "").lower() != rule.get("Description", "").lower():
            continue

        return rule  # All conditions matched, return the rule

    return None

def generate_terraform_and_imports(csv_file, json_file, output_file, output_script_file):
    """Generates Terraform blocks and import commands based on CSV and JSON data."""
    df = pd.read_csv(csv_file)
    with open(json_file, 'r') as file:
        json_data = json.load(file)

    # Access the "SecurityGroupRules" array
    json_rules = json_data.get("SecurityGroupRules", [])

    terraform_blocks = []
    ingress_counters = {}
    egress_counters = {}
    excluded_group_name = "eks-cluster-sg-sitrd-pre-eks-cluster-01-135820731"

    with open(output_script_file, 'w') as script_file:
        script_file.write("@echo off\n")
        rule_id_counts = {}

        for index, row in df.iterrows():
            group_name = row['GroupName'].replace(" ", "-").lower()
            if group_name == excluded_group_name:
                continue

            is_egress = "outbound" in row['Type'].lower() or "egress" in row['Type'].lower()
            from_port = to_port = protocol = None
            cidr_ipv4 = "0.0.0.0/0"

            # Set protocol based on conditions
            if is_egress and pd.notna(row['IpRanges']) and "0.0.0.0/0" in clean_value(row['IpRanges']):
                protocol = -1
            elif not is_egress and (pd.isna(row['FromPort']) or pd.isna(row['ToPort'])):
                protocol = -1
            elif not pd.isna(row['FromPort']) and not pd.isna(row['ToPort']):
                from_port = int(row['FromPort'])
                to_port = int(row['ToPort'])
                protocol = row['IpProtocol']

            terraform_block = {
                "rule_name": f"{group_name}-temp-rule{index + 1}",
                "rule_id": row['GroupId'],
                "description": "",
                "ip_protocol": protocol,
                "from_port": from_port,
                "to_port": to_port
            }

            # Populate CIDR, prefix list, or referenced security group ID
            if pd.notna(row['IpRanges']):
                terraform_block["cidr_ipv4"] = clean_value(row['IpRanges'])
                terraform_block["description"] = extract_description(row['IpRanges'])
            elif pd.notna(row['UserIdGroupPairs']):
                terraform_block["referenced_security_group_id"] = clean_value(row['UserIdGroupPairs'])
                terraform_block["description"] = extract_description(row['UserIdGroupPairs'])
            elif pd.notna(row['PrefixListIds']):
                terraform_block["prefix_list_id"] = clean_value(row['PrefixListIds'])
                terraform_block["description"] = extract_description(row['PrefixListIds'])

            counters = egress_counters if is_egress else ingress_counters
            counters[group_name] = counters.get(group_name, 0) + 1
            rule_name = f"{group_name}-{'egress' if is_egress else 'ingress'}{counters[group_name]}"
            resource_type = "aws_vpc_security_group_egress_rule" if is_egress else "aws_vpc_security_group_ingress_rule"
            terraform_block["rule_name"] = rule_name

            # Generate Terraform block
            terraform_txt = f"""
resource "{resource_type}" "{rule_name}" {{
  security_group_id = "{terraform_block['rule_id']}"
  ip_protocol = "{terraform_block['ip_protocol']}"
"""
            if from_port is not None:
                terraform_txt += f'  from_port = {from_port}\n'
            if to_port is not None:
                terraform_txt += f'  to_port = {to_port}\n'
            for key in ["cidr_ipv4", "referenced_security_group_id", "prefix_list_id"]:
                if key in terraform_block:
                    terraform_txt += f'  {key} = "{terraform_block[key]}"\n'
            if terraform_block["description"]:
                terraform_txt += f'  description = "{terraform_block["description"]}"\n'
            terraform_txt += "}\n"
            terraform_blocks.append(terraform_txt)

            # Match and write import commands
            matching_rule = match_terraform_to_json(terraform_block, json_rules)
            if matching_rule:
                rule_id = matching_rule['SecurityGroupRuleId']
                rule_id_counts[rule_id] = rule_id_counts.get(rule_id, 0) + 1
                script_file.write(f'terraform import {resource_type}.{rule_name} {rule_id}\n')
            else:
                print(f"Warning: No matching JSON rule found for Terraform block {rule_name}")

    # Write all Terraform blocks at once
    with open(output_file, 'w') as output_file_handle:
        output_file_handle.write("\n".join(terraform_blocks))

    print(f"Terraform blocks generated: {len(terraform_blocks)}")
    print(f"Terraform import commands generated: {len(rule_id_counts)}")


# Fill with your file names
csv_file = "security_rules.csv"
json_file = "security_group_rules.json"
output_file = "terraform_security_rules.txt"
output_script_file = "terraform_import_script.bat"
generate_terraform_and_imports(csv_file, json_file, output_file, output_script_file)
