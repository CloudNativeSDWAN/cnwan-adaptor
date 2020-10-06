#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright 2020 Cisco

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""
Script to change the mode of the vManage appliance 
The basic rest_api_lib functions (login, get_request, post_request) are literally from: https://github.com/CiscoDevNet/Getting-started-with-Cisco-SD-WAN-REST-APIs/blob/master/rest_api_lib.py

USAGE:
python3 vsmart_switch.py vmanage_ip username password mode
mode = cli | vmanage
"""







import sys
import json
import requests
import time
import pprint

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)





class rest_api_lib:
    def __init__(self, vmanage_ip, username, password):
        self.vmanage_ip = vmanage_ip
        self.session = {}
        self.login(self.vmanage_ip, username, password)

    def login(self, vmanage_ip, username, password):
        """Login to vmanage"""
        base_url_str = 'https://%s:8443/'%vmanage_ip

        login_action = '/j_security_check'

        #Format data for loginForm
        login_data = {'j_username' : username, 'j_password' : password}

        #Url for posting login data
        login_url = base_url_str + login_action
        url = base_url_str + login_url

        sess = requests.session()
        #If the vmanage has a certificate signed by a trusted authority change verify to True
        login_response = sess.post(url=login_url, data=login_data, verify=False)


        if b'<html>' in login_response.content:
            print ("Login Failed")
            print('Login Failed, credentials may be invalid')

        #update token to session headers

        #URL for retrieving client token
        token_url = base_url_str + 'dataservice/client/token'

        login_token = sess.get(url=token_url, verify=False)

        if login_token.status_code == 200:
            if b'<html>' in login_token.content:
                print("Login Token Failed")
                print('Error obtaining login token, credentials may be invalid')

            sess.headers['X-XSRF-TOKEN'] = login_token.content
            #self.session[vmanage_host] = sess

        self.session[vmanage_ip] = sess

    def get_request(self, mount_point):
        """GET request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        print("GET ", url)

        retries = Retry(total=7, backoff_factor=1, status_forcelist=[400, 404])
        self.session[self.vmanage_ip].mount('https://', HTTPAdapter(max_retries=retries))

        response = self.session[self.vmanage_ip].get(url, verify=False)
        print("Status Code: ", response.status_code)
        print('Response: ', response)
        return response


    def post_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """POST request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        print("POST  ", url)
        print('SENDING THIS PAYLOAD: ', payload)

        response = self.session[self.vmanage_ip].post(url=url, data=payload, headers=headers, verify=False)
        print("Status Code: ", response.status_code)
        print('Response: ', response)
        return response


    def put_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """PUT request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        print("PUT ", url)
        print('Sending this payload: ', payload)

        response = self.session[self.vmanage_ip].put(url=url, data=payload, headers=headers, verify=False)
        print("Status Code: ", response.status_code)

        return response

    def delete_request(self, mount_point, headers={'Content-Type': 'application/json'}):
        """DELETE request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        print("DELETE ", url)

        response = self.session[self.vmanage_ip].delete(url=url, headers=headers, verify=False)
        print("Status Code: ", response.status_code)

        return response





    def get_controller_info(self):
        reply = self.get_request('system/device/controllers')
        if reply.status_code != 200:
            print("GET error", reply.json())
            sys.exit(1)
        response = json.loads(reply.content)
        return response["data"]


    def get_device_ip(self, device_uuid, device_type):
        reply = self.get_request('system/device/management/systemip')
        if reply.status_code != 200:
            print("GET error", reply.json())
            sys.exit(1)
        response = json.loads(reply.content)
        print(response)


        vsmart_ip = None
        for elem in response["data"]:
            if elem["deviceType"] == device_type and \
                elem["chasisNumber"] == device_uuid:
                vsmart_ip = elem["managementSystemIP"]
                break

        if vsmart_ip is None:
            print("FATAL: cannot finde vsmart IP")
            sys.exit(1)


        print("vsamrt IP:", vsmart_ip)
        return vsmart_ip

    def get_attached_config(self, device_uuid):
        reply = self.get_request('config/attached/'+ device_uuid + '?type=CFS')
        if reply.status_code != 200:
            print("GET error", reply.json())
            sys.exit(1)
        response = json.loads(reply.content)
        return response["config"]



    def get_running_config(self, device_uuid):
        reply = self.get_request('template/config/running/'+ device_uuid)
        if reply.status_code != 200:
            print("GET error", reply.json())
            sys.exit(1)
        response = json.loads(reply.content)
        return response["config"]



    def post_cli_template(self, name, desc, deviceType, config):
        #Create a CLI template with a given config
        payload = {
           "templateName" : name,
           "templateDescription" : desc,
           "deviceType" : deviceType,
           "templateConfiguration" : config,
           "factoryDefault" : False,
           "configType" : "file"
        }
        reply = self.post_request('template/device/cli', payload)
        if reply.status_code != 200:
            print(" POST error", reply.json())
            sys.exit(1)
        data = reply.json()
        print (data)
        return data["templateId"]


    def post_cli_mode(self, deviceId, deviceIP, deviceType):


        devices = {'deviceId':deviceId,'deviceIP':deviceIP}
        payload = {'deviceType':deviceType,'devices':[devices]}

        reply = self.post_request('template/config/device/mode/cli', payload)
        if reply.status_code != 200:
            print(" POST error", reply.json())
            sys.exit(1)
        data = reply.json()
        print (data)
        return data




    def get_device_inputs(self, template_id, device_ids):

        payload = {
            'templateId': template_id,
            'deviceIds': device_ids,
            'isEdited': False,
            'isMasterEdited': False
        }
        response = self.post_request('template/device/config/input', payload)
        if response.status_code != 200:
            print("POST error", response.status_code, response.json())
            sys.exit(1)
        else:
            device_inputs = response.json()['data']
            print("Response JSON of device inputs is: ")
            pprint.pprint(response.json())
            for dev_input in device_inputs:
                dev_input['csv-templateId'] = template_id
            print("Returning this device inputs: ", device_inputs)
            return device_inputs


    def post_attch_cli_template(self, templateId, device_inputs):

        payload = {
              "deviceTemplateList":[
              {
                "templateId":templateId,
                "device": device_inputs,
                "isEdited": False,
                "isMasterEdited": False
              }
              ]
        }


        reply = self.post_request('template/device/config/attachcli', payload)
        if reply.status_code != 200:
            print(" POST error", reply.json())
            sys.exit(1)
        data = reply.json()
        print (data)
        return data

if __name__ == "__main__":
    if len (sys.argv) != 5:
        print ("Usage: python3 vsmart_switch.py vmanage_ip username password mode")
        print("mode = cli | vmanage")
        sys.exit(1)
    else:
        vmanage_ip = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        mode = sys.argv[4]
    if mode not in ['cli', 'vmanage']:
        print("mode = cli | vmanage")
        sys.exit(1)
    else:
        ep = rest_api_lib(vmanage_ip, username, password)


        vsmart_uuid = None
        device_data = ep.get_controller_info()
        for elem in device_data:
            if elem["deviceType"] == "vsmart":
                vsmart_uuid = elem["uuid"]
                break
        if vsmart_uuid is None:
            print("FATAL: cannot find vsmart UUID")
            sys.exit(1)

        print("Using this UUID:", vsmart_uuid)




        if mode == 'vmanage':


            #First we need to create a template for vsmart if it's not yet defined. This depends on Lori code for the automation part
            # In theory the full process is this one, but we're using the existing CLI config in vsmart instead of the feature templates
            # 1-Get feature template (GET dataservice/template/feature)
            # 2-Get device UUID (GET dataservice/device)
            # 3-Create a device template from the feature template (POST dataservice/template/device/feature)
            # 4-Get template ID of the previously generated template (GET dataservice/template/device)
            # 5-Attach template to device (POST dataservice/template/device/config/input). Also returns device input vars
            # 6-Attach device template with input vars (POST dataservice/template/device/config/config)


            #Get CLI config of vsmart
            config = ep.get_running_config(vsmart_uuid)

            #Create CLI template
            template_id = ep.post_cli_template('CLI_template_for_vSmart',     \
                'template to attach to vSmart to switch it to vmanage mode',  \
                'vsmart', config)


            #This is a device template, not a feature template
            # template_id = '4d586796-29a2-48e9-a2b2-54b300400194'

            inputs = ep.get_device_inputs(template_id, [vsmart_uuid])
            #Update device config (attach to switch to vmanage mode)
            operation_id = ep.post_attch_cli_template(template_id, inputs)

        else:
            #Temporal bypass due to API error
            #vsmart_ip = ep.get_device_ip(vsmart_uuid, 'vsmart')
            vsmart_ip = '192.168.127.3'
            operation_id = ep.post_cli_mode(vsmart_uuid, vsmart_ip, 'controller')





#Check status

        # Fetch the status of the operation
        while(1):
            time.sleep(3)
            response = ep.get_request('device/action/status/' + operation_id["id"])
            if response.status_code == 200:
                status = response.json()
                if status['summary']['status'] == "done":
                    if len(status['summary']['count']) == 0:
                        print("\nError while changing mode, more info")
                        pprint.pprint(status)
                        sys.exit(1)
                    elif 'Success' in status['summary']['count']:
                        print("\nUpdated templates successfully")
                        sys.exit(0)
                    elif 'Failure' in status['summary']['count']:
                        print("\nFailed to update IPsec templates")
                        print("Failed to update templates", str(status["data"][0]["activity"]))
                        sys.exit(1)
            else:
                print("GET error", response.json())
