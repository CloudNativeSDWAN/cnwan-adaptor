#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
Script to create policies expected by the CN-WAN adaptor
The basic rest_api_lib functions (login, get_request, post_request) are literally from: https://github.com/CiscoDevNet/Getting-started-with-Cisco-SD-WAN-REST-APIs/blob/master/rest_api_lib.py

USAGE A: on a python intepreter/as a library:

import create_empty_sdwan_policies as api
ep = api.rest_api_lib('vmanage_ip','username','password')

#Create an empty data traffic policy
ep.create_data_traffic_policy('test_standaolone', '3g', 'ipsec')
ep.create_approute_policy('test_standaolone-appr', '00_SLA_Class', 'blue')

#Create the merge policy for both traffic and approute
ep.create_merge_policy(MERGE_POLICY)

USAGE B: as a python script
python3 create_policies_json_input.py vmanage_ip username password
"""




import sys
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def create_traffic_data_empty_match(name, tunnel, encap):
    payload =  {
        "name": name,
        "type": "data",
        "description": "Traffic Data Policy for traffic profile " + name,
        "sequences": [
            {
              "sequenceId": 10,
              "sequenceName": "Traffic Engineering",
              "baseAction": "accept",
              "sequenceType": "trafficEngineering",
              "sequenceIpType": "ipv4",
              "match": {
                "entries": [
                  
                ]
              },
              "actions": [
                {
                  "type": "set",
                  "parameter": [
                    {
                      "field": "localTlocList",
                      "value": {
                        "color": tunnel,
                        "encap": encap
                      }
                    }
                  ]
                },
                {
                  "type": "count",
                  "parameter": name +  '_' + str(10)
                }
              ]
            }
        ],
        "defaultAction": {
          "type": "accept"
        }

    }

    return payload
    


def create_app_route_empty_match(name, sla_ref, prefColor=None):
    
    sla_params = [  {'field': 'name', 'ref': sla_ref}]
        
    if prefColor is not None:
        sla_params.append({ "field": "preferredColor", "value": prefColor})
     
    payload = {
        "name": name,
        "type": "appRoute",
        "description": "Application Aware Routing Policy for traffic profile " + name,
        "sequences": [
            {
                "sequenceId": 10,
                "sequenceName": "App Route",
                "sequenceType": "appRoute",
                "sequenceIpType": "ipv4",
                "match": {
                    "entries": [
                        
                    ]
                },
                "actions": [
                    {
                        "type": "count",
                        "parameter": name +  '_' + str(10)
                    },
                    {
                        "type": "slaClass",
                        "parameter": sla_params
                    }
                ]
            }
        ]
    }
    return payload


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
        print("GET %s", url)
        return self.session[self.vmanage_ip].get(url, verify=False)


    def post_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """POST request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        print("POST  %s", url)
        print('SENDING THIS PAYLOAD: %s', payload)

        response = self.session[self.vmanage_ip].post(url=url, data=payload, headers=headers, verify=False)
        print("Status Code:  %s", response.status_code)
        print('Response:  %s', response)
        return response


    def put_request(self, mount_point, payload, headers={'Content-Type': 'application/json'}):
        """PUT request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        payload = json.dumps(payload)
        print("PUT %s", url)
        print('Sending this payload: %s', payload)

        response = self.session[self.vmanage_ip].put(url=url, data=payload, headers=headers, verify=False)
        print("Status Code:  %s", response.status_code)

        return response

    def delete_request(self, mount_point, headers={'Content-Type': 'application/json'}):
        """DELETE request"""
        url = "https://%s:8443/dataservice/%s"%(self.vmanage_ip, mount_point)
        print("DELETE %s", url)

        response = self.session[self.vmanage_ip].delete(url=url, headers=headers, verify=False)
        print("Status Code:  %s", response.status_code)

        return response


    def get_sla_id_by_name(self, name):
        sla_list = self.get_sla_class_list('get_sla_id_by_name')
        sla_id = None
        for sla in sla_list["data"]:
            if sla["name"] == name:
                sla_id = sla["listId"]
                break
        if sla_id is None:
            print("Cannot find SLA Class " + name)
            return None
        else:
            return sla_id

    def get_sla_class_list(self, call_origin):
        reply = self.get_request('template/policy/list')
        if reply.status_code != 200:
            print("GET error", reply.json())
        response = json.loads(reply.content)
        return response  
    
    def post_data_policy(self, policy):
        reply = self.post_request('template/policy/definition/data/', policy)
        if reply.status_code != 200:
            print("POST error", reply.json())
        response = json.loads(reply.content)
        return response
    
    def post_approute_policy(self, payload):
        reply = self.post_request('template/policy/definition/approute', payload)
        if reply.status_code != 200:
            print("POST error", reply.json())
        response = json.loads(reply.content)
        return response

    
 
    def create_data_traffic_policy(self, name, tunnel, encap):
        policy = create_traffic_data_empty_match(name, tunnel, encap)
        self.post_data_policy(policy)
        
    def create_approute_policy(self, policy_name, sla_name, prefColor=None):
        
        sla_ref = self.get_sla_id_by_name(sla_name)
        if sla_ref is None:
            print("Ignoring policy " + policy_name + " because SLA is not defined")
        else:
            policy = create_app_route_empty_match(policy_name, sla_ref, prefColor)
            self.post_approute_policy(policy)
    
    def create_merge_policy(self, name):
        approute_merge = {
          "name": name,
          "type": "appRoute",
          "description": "merge policy for CN-WAN traffic profiles using AppRoute policies",
          "sequences": [],
  
        }
        reply = self.post_approute_policy(approute_merge)   
        appr_id = reply["definitionId"]
        
        data_merge= {
            "name": name,
            "type": "data",
            "description": "merge policy for CN-WAN traffic profiles using data policies",
            "sequences": [],
            "defaultAction": { "type": "accept" }
        }
        
        reply = self.post_data_policy(data_merge)
        data_id = reply["definitionId"]
        
        return appr_id, data_id
        



    def create_site_list(self, site_name, site_list):
        """Create a new site list to use in the policies
        """
        payload = {
            "name": site_name,
            "type": "site",
            "entries":[]
        }
    
        for site_id in site_list:
            payload["entries"].append({"siteId" : site_id})
    
        reply = self.post_request('template/policy/list/site', payload)
        if reply.status_code != 200:
            print( "POST error", reply.json())
        data = reply.json()
        
        return data["listId"]

    def create_vpn_list(self, name, vpn_list):
        """Create a new vpn list to use in the policies
    
        """
    
        payload = {
            "name": name,
            "type": "vpn",
            "entries":[]
        }
        
        for vpn in vpn_list:
            payload["entries"].append({"vpn" : vpn})
    
        reply = self.post_request('template/policy/list/vpn', payload)
        if reply.status_code != 200:
            print(" POST error", reply.json())
        data = reply.json()
            
        return data["listId"]
    
    
    def create_sla(self, name, latency, loss, jitter):
        
        payload = {
            "name": name,
            "type": "sla",
            "description": "CN-WAN-defined SLA " + name,
            "entries": [
                {
                    "jitter": jitter,
                    "latency": latency,
                    "loss": loss
                }
            ]
        }
        
        reply = self.post_request('template/policy/list/sla', payload)
        if reply.status_code != 200:
            print(" POST error", reply.json())
    
    
    def create_centralized_policy(self, name, desc, appr_id, data_id, site_id, vpn_id):
        """Attach a data policy to a vsmart
    
        """
   
        payload= {
            "policyType": "feature",
            "policyName": name,
            "policyDescription": desc,  
            "policyDefinition": {
                  "assembly": [
                  {
                    "definitionId": appr_id,
                    "type": "appRoute",
                    "entries": [
                      {
                        "siteLists": [ site_id ],
                        "vpnLists": [ vpn_id ]
                      }
                    ]
                  },
                  {
                    "definitionId": data_id,
                    "type": "data",
                    "entries": [
                      {
                        "direction": "service",
                        "siteLists": [ site_id ],
                        "vpnLists": [ vpn_id ]
                      }
                    ]
                  }
                ]
              }
            }
            
    
    
    
        response = self.post_request('template/policy/vsmart', payload)
        if response.status_code != 200:
            print("POST error", response.json())
        
        #usually this command does not return anything
        if response.text != '':
            print (response)
        else:
            print ("Warning: empty response")
        
        
        #Get the ID of this policy, (the command does not return it)
            
        #Get templates list
        reply = self.get_request('template/policy/vsmart')
        if reply.status_code != 200:
            print("GET error", reply.json())
        
        response = json.loads(reply.content)
        policies = response['data']
    
        policy = None
        for elem in policies:
            if elem["policyName"] == name:
                policy = elem
                break
    
        if policy is None:
            print("Policy name not found, aborting.")
            sys.exit(-1)
        else:
            #Get ID
            return policy['policyId']
            
        

    

if __name__ == "__main__":
    if len (sys.argv) != 4:
        print ("Usage: python3 create_policies_json_input.py vmanage_ip username password")
        sys.exit(0)
    else:
        vmanage_ip = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        
        try:
            with open('policies_definition.json') as f:
                data = json.load(f)
        except Exception as e:
            print("Error opening input file or cannot find the file policies_definition.json")
            print("Make sure to define all your policies in this file.")
            print (e)
            sys.exit(-1)
        
        ep = rest_api_lib(vmanage_ip, username, password)
        
        if "data_policies" in data.keys():
            for elem in data["data_policies"]:
                ep.create_data_traffic_policy(elem[1], elem[2], elem[3])
        
        if "sla_defs" in data.keys():
            for elem in data["sla_defs"]:
                ep.create_sla(elem[0], elem[1], elem[2], elem[3])
        
        if "app_aware_policies" in data.keys():
            for elem in data["app_aware_policies"]: 
                if elem[3] == "" or len(elem) <4:    
                    ep.create_approute_policy(elem[1], elem[2])
                else:
                    ep.create_approute_policy(elem[1], elem[2], elem[3])
        
        
        # Merge policies        
        appr_merge_id, data_merge_id = ep.create_merge_policy(data["merge_policy_name"])
                
        # Centralized policy configuration
        #VPN List
        vpn_list_id = ep.create_vpn_list("vpn_cnwan_policies", data["vpn_list"])

        #Site List
        site_list_id = ep.create_site_list("sites_cnwan_policies", data["site_list"])

        #Attach to sites
        central_policy_id = ep.create_centralized_policy("CN-WAN centralized policy", \
          "centralized policy containing CN-WAN merge policies", \
              appr_merge_id, data_merge_id, site_list_id, vpn_list_id)
    
        payload_bypass = { "isEdited": "false" }

        #Activate the new policy, it automatically deactivates the old one
        response = ep.post_request('template/policy/vsmart/activate/' + central_policy_id, payload_bypass)
        if response.status_code != 200:
            print ("POST error", response.json())
        data = response.json()
        print(data)
        
        
    
        
        
