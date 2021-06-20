# pan_logreplay

A utility which allows you to replay log exports (CSV format, from PANOS directly) against a live firewall using the test security-policy-match API function.

Does not send live traffic, just simulates it against the rulebase



# Usage

    python3 pan_logreplay.py <input_logs> <output_report> <PANOS-FW> <apikey>

Where:

input_logs is the CSV log export from an existing firewall

output_report is the location to save the results

PANOS-FW is an existing PANOS firewall (version 7-10.10 should work)

apikey is an API key which allows API calls against the PANOS-FW
