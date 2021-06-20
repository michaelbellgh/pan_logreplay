import requests, os, time
import xml.etree.ElementTree as ET
from requests.utils import quote
from enum import Enum

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PanClient:

    params = {
        'hostname' : ''
    }

    options = {
        'verify_certs' : False,
        'https_port' : 443
    }

    device_type = Enum('Panorama', 'Standalone FW')

    api_key = ''

    system_info = {}

    error_dict = {
    '400' : 'Bad request',
    '403' : 'Forbidden',
    '1' : 'Unknown command',
    '2' : 'Internal error',
    '3' : 'Internal error',
    '4' : 'Internal error',
    '5' : 'Internal error',
    '6' : 'Bad Xpath',
    '7' : 'Object not present',
    '8' : 'Object not unique',
    '10' : 'Reference count not zero',
    '11' : 'Internal error',
    '13' : 'Internal error. (Possible config lock)',
    '12' : 'Invalid object',
    '14' : 'Operation not possible',
    '15' : 'Operation denied',
    '16' : 'Unauthorized',
    '17' : 'Invalid command',
    '18' : 'Malformed command',
    '19' : 'Success',
    '20' : 'Success',
    '21' : 'Internal error',
    '22' : 'Session timed out'}

    def log_error(self, error, level):
        print("[" + level + "]: " + error)

    def construct_api_url(self, cmd_type, cmd):
        hostname = self.params['hostname'] 
        key = self.api_key
        port = self.options['https_port']
        
        url = F"https://{hostname}:{port}/api/?key={key}&type={cmd_type}&{cmd}"
        return url
        
    def get_xml(self, url):
        response = requests.get(url, verify=self.options['validate_certs'])
        return response.text
    
    def get_xml_response(self, cmd_type, dict_params):
        hostname = self.params['hostname']
        port = self.options['https_port']
        url = F"https://{hostname}:{port}/api/?type={cmd_type}"
        for k,v in dict_params.items():
            url += "&" + k + "=" + v
        
        url += "&key=" + self.api_key

        response = requests.get(url, verify=self.options['validate_certs'])
        if self.options["debug"] == True:
            print(response.request.url)
        if self.options["debug"] == True:
            print(response.text)
        return response.text

        #Converts command e.g show system info to <show><system><info></info></system></show>
    def convert_cmd_to_xml(self, cmd, data=None):
        input_items = cmd if isinstance(cmd, list) else cmd.split(" ")

        final_output = ""
        for item in input_items:
            final_output += "<" + quote(item) + ">"
        
        if data is not None:
            final_output += quote(str(data))

        for item in reversed(input_items):
            final_output += "</" + quote(item) + ">"

        return final_output

        


    def get_api_key(self, username, password):
        hostname = self.params['hostname']
        port = self.options['https_port']
        url = F"https://{hostname}:{port}/api/?type=keygen&user={username}&password={password}"

        response = requests.get(url, verify=self.options['validate_certs'])
        root = ET.fromstring(response.text)
        key = root.find('result/key')

        if key is not None:
            return key.text
        else:
            self.log_error("Invalid credentials / API key not found", "ERROR")
            return None


    def check_errors(self, root_node):
        if isinstance(root_node, str):
            root_node = ET.fromstring(root_node)
        if root_node.attrib['status'] == 'success':
            if 'code' not in root_node.attrib:
                return True
            if root_node.attrib['code'] in ('19', '20'):
                return True
            elif root_node.attrib['code'] in ('7'):
                self.log_error("Response returned success, but object not present", "WARN")
                return True
            else:
                self.log_error("Response returned success, but non standard response code: " + root_node.attrib['code'], "WARN")
                return True
        elif 'code' in root_node.attrib:
            self.log_error("Response returned error code: " + root_node.attrib['code'] + "\n" + str(root_node.text), "ERROR")
            return False
        elif 'code' not in root_node.attrib:
            self.log_error("Response returned error", "ERROR")
            return False

    def wait_for_job(self, job_id):
        cmd = "<show><jobs><id>" + job_id + "</id></jobs></show>"
        rootNode = ET.fromstring(self.get_xml_response("op", {"cmd" : cmd }))

        if self.check_errors(rootNode):
            while(rootNode.find("./result/job/status").text != "FIN"):
                time.sleep(1)
                rootNode = ET.fromstring(self.get_xml_response("op", {"cmd" : cmd }))
            return rootNode
        else:
            print("[ERROR] Waiting for job " + job_id + " failed with response " + ET.tostring(rootNode))

    def commit(self, force=False, wait_for_completion=True, partial_admin_commit=""):
        cmd = "<commit>"
        if partial_admin_commit != "":
            cmd += "<partial><admin><member>" + partial_admin_commit + "</member></admin></partial>"
        if force:
            cmd += "<force></force>"
        cmd += "</commit>"

        response = self.get_xml_response("commit", {"cmd" : cmd })
        rootNode = ET.fromstring(response)
        if self.check_errors(rootNode):
            job_id = rootNode.find("./result/job").text
            if wait_for_completion:
                self.wait_for_job(job_id)
            return job_id
        else:
            print("[ERROR] Queuing commit failed with error '" + ET.tostring(rootNode) + "'")

    def push_device_groups(self, device_group, include_template=True, merge_with_candidate_config=True, validate_only=False, wait_for_job=True):
        cmd = '<commit-all><shared-policy><device-group><entry name="' + device_group + '"></entry></device-group>'
        if include_template:
            cmd += "<include-template>yes</include-template>"
        if merge_with_candidate_config:
            cmd += "<merge-with-candidate-cfg>yes</merge-with-candidate-cfg>"
        if validate_only:
            cmd += "<validate-only>yes</validate-only>"
        #This should not be done by automation! (in most cases) So we set to no
        cmd += "<force-template-values>no</force-template-values>"
        
        cmd += "</shared-policy></commit-all>"

        response = self.get_xml_response("commit", {"action" : "all", "cmd" : cmd })
        rootNode = ET.fromstring(response)

        if self.check_errors(rootNode):
            job_id = rootNode.find("./result/job").text
            if wait_for_job:
                self.wait_for_job(job_id)
            return job_id
        else:
            print("[ERROR] Queuing commit failed with error '" + ET.tostring(rootNode) + "'")



            



    def __init__(self, hostname, apikey, verify_certs=False, https_port=443,debug=False):
        self.params['hostname'] = hostname
        self.options['https_port'] = https_port
        self.options['validate_certs'] = verify_certs

        self.options["debug"] = debug

        self.api_key = apikey
        

    #Method to generate class from credentials. Not preferred, use __init__/apikey where possible
    @staticmethod
    def from_credentials(hostname: str,  username: str, password: str, verify_certs: bool=False, https_port: int=443):
        username = quote(username)
        password = quote(password)
        url = F"https://{hostname}:{https_port}/api/?type=keygen&user={username}&password={password}"

        response = requests.get(url, verify=verify_certs)
        root = ET.fromstring(response.text)
        key = root.find('result/key')

        if key is not None:
            return PanClient(hostname, key, verify_certs=verify_certs, https_port=https_port)
        else:
            print("Invalid credentials / API key not found", "ERROR")
            return None

        