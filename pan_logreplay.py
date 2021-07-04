from os import write
import panclient
import csv, argparse
from requests.utils import quote
import xml.etree.ElementTree as ET
from distutils.version import LooseVersion, StrictVersion

def get_matchable_rows(csv_logfile: str):
    #Get rid of the BoM marker by using utf-8-sig
    reader = csv.DictReader(open(csv_logfile, mode='r', encoding='utf-8-sig'))
    #Current supported test options in PANOS 10.1. If they arent present e.g. < 10.1 they will be ignored.
    #Convert CSV columns to API parameters
    csv_to_api_mappings = {
        "Application" : "application",
        "Category" : "category",
        "Destination" : "destination",
        "Destination address" : "destination",
        "Destination Device Model" : "destination-model",
        "Destination Category" : "destination-category",
        "Destination OS" : "destination-os",
        "Destination OS Family" : "destination-osfamily",
        "Destination Profile" : "destination-profile",
        "Destination Vendor" : "destination-vendor",
        "Destination Port" : "destination-port",
        "Source Zone" : "from",
        "IP Protocol" : "protocol",
        "Destination Zone" : "to",
        "Source address" : "source",
        "Source Device Category" : "source-category",
        "Source Device Model" : "source-model",
        "Source Device Profile" : "source-profile",
        "Source Device Vendor" : "source-vendor",
        "Source Device OS" : "source-os",
        "Source Device OS Family" : "source-os",
        "Source User" : "source-user"
    }

    mapped_rows = []
    for row in reader:
        new_normalised_row = {}
        #Loop through the columns, translate them and grab the ones we are interested in
        for key, value in row.items():
            if key in row and key in csv_to_api_mappings:
                new_key_name = csv_to_api_mappings[key]
                #We need to convert TCP/UDP/ICMP to 6/17/1 (IP Protocol numbers)
                if new_key_name == "Rule":
                    new_normalised_row["Old Rule"] = value[:31]
                if new_key_name == "protocol":
                    value = translate_ip_protocol(value)
                new_normalised_row[new_key_name] = value
        #Save the old rule name for later comparison
        new_normalised_row["Old Rule"] = row["Rule"]
        if new_normalised_row:
            mapped_rows.append(new_normalised_row)
    
    return mapped_rows


def translate_ip_protocol(protocol: str):
    #Translate ip protocol from tcp/udp/icmp to numerical value e.g. TCP -> 6, UDP -> 17
    if protocol == "tcp":
        return 6
    if protocol == "udp":
        return 17
    if protocol == "icmp":
        return 1
    else:
        #All other protocols *should* be represented as their numerical value already
        #TODO: Check IPSEC/ESP protocols
        return int(protocol)

def get_rule_match(normalised_row: dict, client: panclient.PanClient, pre_81=False):
    ignored_keys = ["Old Rule"]
    element_string = "<test><security-policy-match>"
    for key, value in normalised_row.items():
        #Ignore our 'Old Rule' field and any future others
        if key in ignored_keys:
            continue

        #Remove destination port if we arent TCP or UDP
        if normalised_row["protocol"] not in [6,17] and key == "destination-port":
            continue

        #Skip fields which are optional and empty
        if value == "":
            continue
        
        element_string += "<" + key + ">" + str(value) + "</" + key + ">"
    
    element_string += "</security-policy-match></test>"

    result = client.get_xml_response("op", {"cmd" : quote(element_string)})
    return result

def is_pre_81_version(client: panclient.PanClient):
    result = client.get_xml_response("op", {"cmd" : "<show><system><info></info></system></show>"})
    if not client.check_errors(result):
        print("Error getting version from PANOS")
    
    root_node = ET.fromstring(result)
    version_text = root_node.find("result/system/sw-version").text
    return LooseVersion(version_text) < LooseVersion("8.1.0")

def create_comparison_csv(input_csv_filename: str, output_csv_filename: str, client: panclient.PanClient, output_progress: bool=True):

    #PANOS 8.1 and below have a 31 rulename char limit
    rulename_31_limit = is_pre_81_version(client)

    rows = get_matchable_rows(input_csv_filename)
    if len(rows) == 0:
        raise Exception("No valid rows found in " + input_csv_filename)

    #Python 3.3+ outputs a nested list like ([1,2,3]), workaround to flatten
    column_names = list(rows[0])
    column_names.append("New Rule")
    column_names.append("Equal")

    writer = csv.DictWriter(open(output_csv_filename, mode="w", newline=""), fieldnames=column_names)
    writer.writeheader()

    


    position = 1
    count = len(rows)

    for row in rows:
        if rulename_31_limit:
            #If pre 8.1, we need to shorten old rule name
            row["Old Rule"] = row["Old Rule"][:31]
        xml_output = get_rule_match(row, client, pre_81=rulename_31_limit)
        
        if not client.check_errors(xml_output):
            print("Error on row: " + str(row))
            continue

        root_node = ET.fromstring(xml_output)

        try:
            # Check if the result is empty. If so, we havent hit any rules
            new_rule_name = ""
            if len(root_node.find("result")) == 0:
                new_rule_name = "[None]"
            else:
                #We have hit a named rule, record it here
                new_rule_name = root_node.find("./result/rules/entry").attrib["name"]
        except Exception as e:
            print("Error while checking response. PANOS response below\n" + xml_output + "\n\n" + str(e))



        new_row = row
        new_row["New Rule"] = new_rule_name
        if rulename_31_limit:
            #Need to trim > 31 char rule names, since 8.1 and below only support 31 chars.
            new_row['Old Rule'] = new_row["Old Rule"[:31]]
        new_row["Equal"] = (new_row["Old Rule"] == new_rule_name)
        writer.writerow(new_row)
        if output_progress:
            rules_are_equal = (row["Old Rule"] == new_rule_name)
            print("[" + str(position) + "/" + str(count) + "] Old Rule: " + row["Old Rule"] + " == " + new_rule_name + ": " + str(rules_are_equal))
            position += 1
    



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_log_csv", help="PANOS CSV Log Export file")
    parser.add_argument("output_log_csv", help="Comparison CSV to output")

    parser.add_argument("hostname", help="PANOS firewall to test against")
    parser.add_argument("apikey")

    args = parser.parse_args()

    client = panclient.PanClient(args.hostname, args.apikey)
    create_comparison_csv(args.input_log_csv, args.output_log_csv, client)

main()