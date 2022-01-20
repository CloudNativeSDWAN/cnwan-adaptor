#! /usr/bin/env python
"""
Copyright 2020 Cisco

SPDX-License-Identifier: Apache-2.0

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
Class with REST Api GET and POST libraries that communicate with vManage
The basic rest_api_lib functions (login, get_request, post_request) are literally from: https://github.com/CiscoDevNet/Getting-started-with-Cisco-SD-WAN-REST-APIs/blob/master/rest_api_lib.py
"""

import sys
import time
import json
import requests
import logging
import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


import metadata_adaptor.server_errors as err
logger = logging.getLogger(__name__)


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
            raise err.NoConfigData('Login Failed, credentials may be invalid')

        #update token to session headers

        #URL for retrieving client token
        token_url = base_url_str + 'dataservice/client/token'

        login_token = sess.get(url=token_url, verify=False)

        if login_token.status_code == 200:
            if b'<html>' in login_token.content:
                logger.error("Login Token Failed")
                raise err.NoConfigData('Error obtaining login token, credentials may be invalid')

            sess.headers['X-XSRF-TOKEN'] = login_token.content
            #self.session[vmanage_host] = sess

        self.session[vmanage_ip] = sess

    def get_request(self, mount_point):
        """GET request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        logger.debug("GET %s", url)
        return self.session[self.vmanage_ip].get(url, verify=False)


    def post_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """POST request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        logger.debug ("POST  %s", url)
        logger.debug ('SENDING THIS PAYLOAD: %s', payload)

        response = self.session[self.vmanage_ip].post(url=url, data=payload, headers=headers, verify=False)
        logger.debug ("Status Code:  %s", response.status_code)
        logger.debug ('Response:  %s', response)
        return response


    def put_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """PUT request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        logger.debug ("PUT %s", url)
        logger.debug ('Sending this payload: %s', payload)

        response = self.session[self.vmanage_ip].put(url=url, data=payload, headers=headers, verify=False)
        logger.debug ("Status Code:  %s", response.status_code)

        return response

    def delete_request(self, mount_point, headers={'Content-Type': 'application/json'}):
        """DELETE request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        logger.debug ("DELETE %s", url)

        response = self.session[self.vmanage_ip].delete(url=url, headers=headers, verify=False)
        logger.debug ("Status Code:  %s", response.status_code)

        return response

    def test_disconnect(self):
        try:
            reply = self.get_request('template/policy/definition/data')
            response = json.loads(reply.content)
        except json.JSONDecodeError:
            return True
        except Exception as e:
            logger.error("Unexpected communication error with vmanage: %s", str(e))
            
        return False
        
# DATA POLICES
    
    def get_data_policy_id_by_name(self, policyName):
        reply = self.get_request('template/policy/definition/data')        
        if reply.status_code != 200:
            raise err.GETError('get_traffic_policy_id_by_name', reply.status_code, reply.json())
        
        response = json.loads(reply.content)
        policies = response['data']       
        for elem in policies:
            if elem["name"] == policyName:
                return elem['definitionId']
        return None
    
    def get_data_policy_by_id(self, policy_id):
        reply = self.get_request('template/policy/definition/data/' + policy_id)
        if reply.status_code != 200:
            raise err.GETError('get_data_policy_by_id', reply.status_code, reply.json())

        data_policy = json.loads(reply.content)
        del data_policy['definitionId']
        del data_policy['lastUpdated']
        del data_policy['owner']
        del data_policy['infoTag']
        del data_policy['referenceCount']
        del data_policy['references']
        if 'activatedId' in data_policy.keys():
            del data_policy['activatedId']
        del data_policy['isActivatedByVsmart']

        logger.debug("Data policy loaded: %s", pprint.pformat(data_policy))
        return data_policy


    def put_data_policy(self, policyId, policy, call_origin):
        reply = self.put_request('template/policy/definition/data/' + policyId, policy)
        if reply.status_code != 200:
            raise err.PUTError(call_origin, reply.status_code, reply.json())
        response = json.loads(reply.content)
        return response


# SLA / APP-AWARE ROUTING POLICIES        
    
    def get_approute_policy_id_by_name(self, policyName):
        reply = self.get_request('template/policy/definition/approute' )        
        if reply.status_code != 200:
            raise err.GETError('get_approute_policy_id_by_name', reply.status_code, reply.json())

        response = json.loads(reply.content)        
        policies = response['data']       
        for elem in policies:
            if elem["name"] == policyName:
                return elem['definitionId']
        return None


    def get_approute_policy_by_id(self, policy_id):
        reply = self.get_request('template/policy/definition/approute/' + policy_id)
        if reply.status_code != 200:
            raise err.GETError('get_approute_policy_by_id', reply.status_code, reply.json())

        approute_policy = json.loads(reply.content)
        del approute_policy['definitionId']
        del approute_policy['lastUpdated']
        del approute_policy['owner']
        del approute_policy['infoTag']
        del approute_policy['referenceCount']
        del approute_policy['references']
        if 'activatedId' in approute_policy.keys():
            del approute_policy['activatedId']
        del approute_policy['isActivatedByVsmart']

        logger.debug("AppRoute policy loaded: %s", pprint.pformat(approute_policy))
        return approute_policy


    def put_approute_policy(self, policyId, policy, call_origin):
        reply = self.put_request('template/policy/definition/approute/' + policyId, policy)
        if reply.status_code != 200:
            raise err.PUTError(call_origin, reply.status_code, reply.json())
        response = json.loads(reply.content)
        return response

    # FUNCTIONS TO UPDATE ACTIVE POLICIES
    # src: https://github.com/suchandanreddy/sdwan-app-route-policy/blob/9a3bae2f0560e6dbf5062662692d4e443f8f99a3/modify-app-policy-color.py#L76
    # These functions are in Configuration - Device Template in the API reference
    
    def get_device_ids(self, template_id, call_origin):
        response = self.get_request('template/device/config/attached/' + template_id)
        if response.status_code != 200:
            raise err.GETError(call_origin, response.status_code, response.json())
        else:
            logger.debug("Response JSON of device ids: %s", response.json())
            device_ids = []
            for device in response.json()['data']:
                device_ids.append(device['uuid'])
            logger.debug("Returning this device ids: %s", device_ids)
            return device_ids

    def get_device_inputs(self, template_id, device_ids, call_origin):

        payload = {
            'templateId': template_id,
            'deviceIds': device_ids,
            'isEdited': True,
            'isMasterEdited': False
        }
        response = self.post_request('template/device/config/input', payload)
        if response.status_code != 200:
            raise err.POSTError(call_origin, response.status_code, response.json())
        else:
            device_inputs = response.json()['data']
            logger.debug("Response JSON of device inputs is: %s", response.json())
            for dev_input in device_inputs:
                dev_input['csv-templateId'] = template_id
            logger.debug("Returning this device inputs: %s", device_inputs)
            return device_inputs


    def post_attach_cli(self, payload, call_origin):
        reply = self.post_request('template/device/config/attachcli', payload)
        if reply.status_code != 200:
            raise err.POSTError(call_origin, reply.status_code, reply.json())
        else:
            response = reply.json()
            logger.debug("Attach cli response: %s", response)
            return response

    def update_active_policy(self, master_templates, call_origin):
        inputs = []
        for template_id in master_templates:
            device_ids = self.get_device_ids(template_id, call_origin)
            device_inputs = self.get_device_inputs(template_id, device_ids, call_origin)
            inputs.append((template_id, device_inputs))

        device_template_list = []
        for (template_id, device_input) in inputs:
            device_template_list.append({
                'templateId': template_id,
                'isEdited': True,
                'device': device_input
            })

        # api_url for CLI template 'template/device/config/attachcli'

        payload = {'deviceTemplateList': device_template_list}
        response = self.post_attach_cli(payload, call_origin)
        process_id = response["id"]

        # Fetch the status of template push
        while(1):
            time.sleep(3)
            template_status_res = self.get_request('device/action/status/' + process_id)
            if template_status_res.status_code == 200:
                template_push_status = template_status_res.json()
                if template_push_status['summary']['status'] == "done":
                    if 'Success' in template_push_status['summary']['count']:
                        logger.info("\nUpdated templates successfully")
                        return 1
                    elif 'Failure' in template_push_status['summary']['count']:
                        logger.errort("\nFailed to update IPsec templates")
                        logger.error(err.UpdateError(call_origin, \
                    "Failed to update templates", str(template_push_status["data"][0]["activity"])))
            else:
                raise err.GETError(call_origin, template_status_res.status_code, template_status_res.json())