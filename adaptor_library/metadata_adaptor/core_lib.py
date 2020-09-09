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

#! /usr/bin/env python
import os
import logging
import pprint
logging.basicConfig(filename='adaptor.log', level=logging.DEBUG, \
                    datefmt='%a, %d %b %Y %H:%M:%S')
logger = logging.getLogger(__name__)
                    


import metadata_adaptor.server_errors as err
import metadata_adaptor.template_generator as templates
import metadata_adaptor.vmanage_functions as vmg

class api_endpoint:

    def __init__(self):

        
        #Load config  via env vars
        SDWAN_IP = os.environ.get("SDWAN_IP")
        SDWAN_USERNAME = os.environ.get("SDWAN_USERNAME")
        SDWAN_PASSWORD = os.environ.get("SDWAN_PASSWORD")
        MERGE_POLICY = os.environ.get("MERGE_POLICY")

        # SDWAN Controller endpoint
        self.api_endpoint = None

        # Internal vars        
        self.srv_endpoints = {}
        self.app_route_traffic_profiles = {}
        self.data_traffic_profiles = {}
        self.metadata_keys = []

        # SDWAN Controller credentials
        self.credentials = {}
        self.credentials['sdwanControllerIpAddress'] = None
        self.credentials['user'] = None
        self.credentials['password'] = None
        self.credentials['sdwanMergedPolicyName'] = None



        # SDWAN controller login if env vars    
        if (SDWAN_IP is not None) and (SDWAN_USERNAME is not None) \
            and (SDWAN_PASSWORD is not None) and (MERGE_POLICY is not None):
            self.credentials['sdwanControllerIpAddress'] = SDWAN_IP
            self.credentials['user'] = SDWAN_USERNAME
            self.credentials['password'] = SDWAN_PASSWORD
            self.credentials['sdwanMergedPolicyName'] = MERGE_POLICY
            self.post_credentials(self.credentials)
            
            logger.info('Connecting to server %s', SDWAN_IP)
        

    def check_config(self):

        if self.credentials['sdwanControllerIpAddress'] is None or \
                self.credentials['user'] is None or \
                self.credentials['password'] is None:
            logger.error("Credentials of SDWAN controller are not defined.")
            raise err.NoConfigData('Controller credentials user/password or IP')
            
    def test_connection(self):
        if self.api_endpoint.test_disconnect():
            logger.info("Connection lost to the SDWAN controller, re-authenticating.")
            self.post_credentials(self.credentials)
        

            

### SDWAN CONTROLLER CREDENTIALS

    def get_credentials(self):
        return self.credentials

    def post_credentials(self, cred):
        try:
            self.api_endpoint = vmg.rest_api_lib(cred['sdwanControllerIpAddress'], \
                    cred['user'], cred['password'])
        except Exception as e:
            raise e
        self.credentials = cred
        

    def delete_credentials(self):
        self.credentials['sdwanControllerIpAddress'] = None
        self.credentials['user'] = None
        self.credentials['password'] = None
        self.credentials['sdwanMergedPolicyName'] = None


### SERVICE ENDPOINTS MANAGEMENT
        
    def get_service_endpoints_by_profile(self, profile):
        
        endpoints =[]
        
        for key, data in self.srv_endpoints.items():
            if data['trafficProfileName'] == profile:
                endpoints.append(key)
        
        return endpoints
    
    def delete_service_endpoint_by_profile(self, profile):
        
        to_delete = []
        
        for key, data in self.srv_endpoints.items():
            if data['trafficProfileName'] == profile:
                to_delete.append(key)
                
        for key in to_delete:
            del self.srv_endpoints[key]    
    

    def get_service_endpoints(self):

        temp = []
        for key, profile in self.srv_endpoints.items():
            temp_key = key.split('_')
            temp.append({
                "ipAddress": temp_key[0],
                "portNumber": temp_key[1],
                "trafficProfileName": profile
            })
        return temp

    def post_service_endpoint(self, ipAddress, portNumber, profileName):

        key = ipAddress + '_' + portNumber
        error = {}
        
        if key in self.srv_endpoints.keys():
            msg = "Ignoring request: the endpoint"  + key +  " is already defined"
            logger.warning( err.ElementAlreadyDefined("post_service_endpoint", msg))
            error['status'] = 400
            error['title'] = 'ENDPOINT ALREADY DEFINED'
            error['description'] = 'The endpoint IP: ' + ipAddress + ' and port '  + portNumber + ' is already defined.  Ignoring this event.'
            return True, error
        
        defined, profile_type = self.is_traffic_profile_defined(profileName)
        if not defined:
            logger.warning(err.CannotFindElement('post_service_endpoint', \
                'Traffic profile ' + profileName + ' is not defined, ignoring request.'))
            error['status'] = 400
            error['title'] = 'CANNOT FIND TRAFFIC PROFILE'
            error['description'] = 'The traffic profile ' + profileName +  ' is not defined. Ignoring this event.'
            return True, error
        
        
        try:

            if profile_type == 'AppRoute':
                   
                policy_name = self.app_route_traffic_profiles[profileName]['policyName']
                defined, policy_id = self.is_policy_defined(policy_name, profile_type)        
                if not defined:
                    raise err.CannotFindElement('post_service_endpoint', policy_name)
                    
                policy = self.api_endpoint.get_approute_policy_by_id(policy_id)
                payload = templates.add_approute_endpoint(policy, ipAddress, portNumber)
                response = self.api_endpoint.put_approute_policy(policy_id, payload, 'post_service_endpoint')
                self.srv_endpoints[key] = {
                    'trafficProfileName': profileName,
                    'policyId' : policy_id  }
                # Trigger update for centralized policies that are active
                # The masterTemplatesAffected array is empty if the policy is NOT active
                if len(response["masterTemplatesAffected"]) != 0:
                    self.api_endpoint.update_active_policy(response["masterTemplatesAffected"], 'post_service_endpoint')


            elif profile_type == 'Data':
                
                policy_name = self.data_traffic_profiles[profileName]['policyName']
                defined, policy_id = self.is_policy_defined(policy_name, profile_type)        
                if not defined: 
                   raise err.CannotFindElement('post_service_endpoint', policy_name) 
                
                policy = self.api_endpoint.get_data_policy_by_id(policy_id)
                payload = templates.add_data_endpoint(policy, ipAddress, portNumber)
                response = self.api_endpoint.put_data_policy(policy_id, payload, 'post_service_endpoint')
                self.srv_endpoints[key] = {
                    'trafficProfileName': profileName,
                    'policyId' : policy_id  }
                # Trigger update for centralized policies that are active
                # The masterTemplatesAffected array is empty if the policy is NOT active
                if len(response["masterTemplatesAffected"]) != 0:
                    self.api_endpoint.update_active_policy(response["masterTemplatesAffected"], 'post_service_endpoint')

                    
        except err.CannotFindElement as e:
            logger.warning('Ignoring request: Cannot find a policy called %s', e.elem)
        
        except Exception as e:
            logger.error('An error ocurred while communicating with the SDWAN controller.')
            logger.error('Details: %s', e)

        return False, error

    def delete_service_endpoint(self, ipAddress, portNumber):

        key = ipAddress + '_' + portNumber
        error = {}
        
        if key not in self.srv_endpoints.keys():
            logger.warning(err.CannotFindElement("delete_service_endpoint", "This endpoint is not defined, ignoring request."))
            error['status'] = 400
            error['title'] = 'ENDPOINT NOT FOUND'
            error['description'] = 'Cannot process DELETE event: resource  IP ' + ipAddress + ' and port '  + portNumber + ' does not exist. Ignoring this event.'
            return True, error
        
        traffic_profile = self.srv_endpoints[key]['trafficProfileName']
        policy_id = self.srv_endpoints[key]['policyId']

        try:
        
            if traffic_profile in self.app_route_traffic_profiles.keys():
                policy = self.api_endpoint.get_approute_policy_by_id(policy_id)
                payload = templates.remove_endpoint(policy, ipAddress, portNumber)
                response = self.api_endpoint.put_approute_policy(policy_id, payload, 'delete_service_endpoint')
                del self.srv_endpoints[key]
                if len(response["masterTemplatesAffected"]) != 0:
                    self.api_endpoint.update_active_policy(response["masterTemplatesAffected"], 'delete_service_endpoint')

            elif traffic_profile in self.data_traffic_profiles.keys():               
                policy = self.api_endpoint.get_data_policy_by_id(policy_id)
                payload = templates.remove_endpoint(policy, ipAddress, portNumber)
                response = self.api_endpoint.put_data_policy(policy_id, payload, 'delete_service_endpoint')
                del self.srv_endpoints[key]
                if len(response["masterTemplatesAffected"]) != 0:
                    self.api_endpoint.update_active_policy(response["masterTemplatesAffected"], 'delete_service_endpoint')

            else:

                logger.warning(err.CannotFindElement('delete_service_endpoint', \
                'Traffic profile ' + traffic_profile + ' is not defined, ignoring request.'))

        except Exception as e:
            logger.error('An error ocurred while communicating with the SDWAN controller.')
            logger.error('Exception name: %s', repr(e))
            logger.error('Details: %s', e)
        
        return False, error
            


    def put_service_endpoint(self, ipAddress, portNumber, profileName):
        error_data = {}
        
        #Check if the profile is defined        
        profile_defined, profile_type = self.is_traffic_profile_defined(profileName)
        
        if not profile_defined:    
            logger.warning(err.CannotFindElement("put_service_endpoint", \
                "The traffic profile " + profileName + "  is not defined, ignoring this request"))
            error_data['status'] = 400
            error_data['title'] = 'CANNOT FIND TRAFFIC PROFILE'
            error_data['description'] = 'The traffic profile ' + profileName +  ' is not defined. Ignoring this event.'
            return True, error_data
        
        #Check if the policy is defined
        if profile_type == 'AppRoute':
            policyName = self.app_route_traffic_profiles[profileName]['policyName']

        else:
            policyName = self.data_traffic_profiles[profileName]['policyName']

        policy_defined, _ = self.is_policy_defined(policyName, profile_type)
            
        if not policy_defined:
            logger.warning(err.CannotFindElement("put_service_endpoint", \
                'Ignoring request: Cannot find a policy called '+ policyName ))
            return False, error_data
        
        # Do the actual work
        error, error_data = self.delete_service_endpoint(ipAddress, portNumber)
        if error:
            return error, error_data
        else:
            error, error_data =  self.post_service_endpoint(ipAddress, portNumber, profileName)
            return error, error_data
        
       


    def create_data_policy_with_all_endpoints(self, previous_cnwan_remove = []):
        
        # Collect all endpoint + tunnel info for each profile
        cnwan_seqs = []
        
        
        for name, data in self.data_traffic_profiles.items():
            
            defined, policy_id = self.is_policy_defined(data['policyName'], 'Data')
            if defined:    

                previous_cnwan_remove.append(data['policyName'])                
                policy = self.api_endpoint.get_data_policy_by_id(policy_id)
                if len(policy['sequences']) > 1:
                    temp_seqs = templates.change_seq_name(policy, data['policyName'])
                    for seq in temp_seqs:
                        cnwan_seqs.append(seq)
            else:
                logger.warning('In create_data_policy_with_all_endpoints, ignoring metadata value %s because \
                               policy %s does not exist in the SD-WAN controller.', name, data['policyName'])
    
        # Rertrieve and update merge policy
        policy_id = self.api_endpoint.get_data_policy_id_by_name(self.credentials['sdwanMergedPolicyName'])
        policy = self.api_endpoint.get_data_policy_by_id(policy_id)
        policy['sequences'] = templates.add_cnwan_sequences_to_merge_policy(policy['sequences'], cnwan_seqs, previous_cnwan_remove)
        logger.debug("New merge policy is %s", pprint.pformat(policy['sequences']))
        response = self.api_endpoint.put_data_policy(policy_id, policy, 'create_data_policy_with_all_endpoints')
                       
        # Trigger update for centralized policies that are active
        # The masterTemplatesAffected array is empty if the policy is NOT active
        if len(response["masterTemplatesAffected"]) != 0:
            self.api_endpoint.update_active_policy(response["masterTemplatesAffected"], 'create_data_policy_with_all_endpoints')
            
    def create_approute_policy_with_all_endpoints(self,  previous_cnwan_remove = []):
        # Collect all endpoint + sla info for each profile
        cnwan_seqs = []
        
        for name, data in self.app_route_traffic_profiles.items():
        
            defined, policy_id = self.is_policy_defined(data['policyName'], 'AppRoute')
            if defined:    
            
                previous_cnwan_remove.append(data['policyName'])
                policy = self.api_endpoint.get_approute_policy_by_id(policy_id)
                if len(policy['sequences']) > 1:
                    temp_seqs = templates.change_seq_name(policy, data['policyName'])
                    for seq in temp_seqs:
                        cnwan_seqs.append(seq)
            else:
                logger.warning('In create_approute_policy_with_all_endpoints, ignoring metadata value %s because \
                    policy %s does not exist in the SD-WAN controller.', name, data['policyName'])
                
        # Rertrieve and update merge policy
        policy_id = self.api_endpoint.get_approute_policy_id_by_name(self.credentials['sdwanMergedPolicyName'])
        policy = self.api_endpoint.get_approute_policy_by_id(policy_id)
        policy['sequences'] = templates.add_cnwan_sequences_to_merge_policy(policy['sequences'], cnwan_seqs, previous_cnwan_remove)  
        logger.debug("New merge policy for AppRoute is %s", pprint.pformat(policy['sequences']))
        response = self.api_endpoint.put_approute_policy(policy_id, policy, 'create_approute_policy_with_all_endpoints')
                       
        # Trigger update for centralized policies that are active
        # The masterTemplatesAffected array is empty if the policy is NOT active
        if len(response["masterTemplatesAffected"]) != 0:
            self.api_endpoint.update_active_policy(response["masterTemplatesAffected"], 'create_approute_policy_with_all_endpoints')
    
    def is_traffic_profile_defined(self, profileName):
        if profileName in self.app_route_traffic_profiles.keys():
            return True, 'AppRoute'
        elif profileName in self.data_traffic_profiles.keys():
            return True, 'Data'
        else:
            return False, None



### POLICY MANAGEMENT
    
    def is_policy_defined(self, policyName, policyType):
        if policyType == 'AppRoute':
            policy_id = self.api_endpoint.get_approute_policy_id_by_name(policyName)
            
        elif policyType == 'Data':
            policy_id = self.api_endpoint.get_data_policy_id_by_name(policyName)
            
        else:          
            return False, None
        
        
        if policy_id is None:
            return False, None
        else:
            return True, policy_id
        
    def is_policy_in_mappings(self, policyName, policyType):
        
        if policyType == 'AppRoute':
            for name, data in self.app_route_traffic_profiles.items(): 
                if data['policyName'] == policyName:
                    return True, name
        
        elif policyType == 'Data':
            for name, data in self.data_traffic_profiles.items():
                if data['policyName'] == policyName:
                    return True, name
        
        return False, None
       
    
    def empty_approute_policy(self, policy_name, call_origin):
        policy_id = self.api_endpoint.get_approute_policy_id_by_name(policy_name)
        policy = self.api_endpoint.get_approute_policy_by_id(policy_id)
        payload = templates.create_empty_policy(policy)
        response = self.api_endpoint.put_approute_policy(policy_id, payload, call_origin)
        
    
    def add_endpoint_array_approute_policy(self, policy_id, endpoints, call_origin):        
        policy = self.api_endpoint.get_approute_policy_by_id(policy_id)
        payload = templates.add_array_endpoints_to_approute_policy(endpoints, policy)
        response = self.api_endpoint.put_approute_policy(policy_id, payload, call_origin)
        
        
    
    def empty_data_policy(self, policy_name, call_origin):
        policy_id = self.api_endpoint.get_data_policy_id_by_name(policy_name)
        policy = self.api_endpoint.get_data_policy_by_id(policy_id)
        payload = templates.create_empty_policy(policy)
        response = self.api_endpoint.put_data_policy(policy_id, payload, call_origin)
        
    
    
    def add_endpoint_array_data_policy(self, policy_id, endpoints, call_origin):
        policy = self.api_endpoint.get_data_policy_by_id(policy_id)
        payload = templates.add_array_endpoints_to_data_policy(endpoints, policy)
        response = self.api_endpoint.put_data_policy(policy_id, payload, call_origin)

        
        

### EXPOSED API FUNCITONS

    def get_mappings(self):

        temp = []
        for name, data in self.app_route_traffic_profiles.items():
            profile = {
                "metadataKey" : str(self.metadata_keys),
                "metadataValue": name,
                "policyType": "AppRoute",
                "policyName" : data['policyName']
            }
            temp.append(profile)

        for name, data in self.data_traffic_profiles.items():
            profile = {
                "metadataKey" : str(self.metadata_keys),
                "metadataValue": name,
                "policyType": "Data",
                "policyName" : data['policyName']

            }
            temp.append(profile)

        return temp

    def post_mapping(self, mapping):

        if mapping["metadataKey"] not in self.metadata_keys:
            self.metadata_keys.append(mapping["metadataKey"])
            logger.info('Detected new metadata key %s, adding to list.', mapping["metadataKey"])
            
        
        name = mapping['metadataValue']
        profile_type = mapping['policyType']
        policy_defined_in_mapping, mapping_name = self.is_policy_in_mappings(mapping['policyName'], profile_type)

        if name in self.app_route_traffic_profiles.keys() or \
           name in self.data_traffic_profiles.keys():
            
            msg = 'Ignoring request: the traffic profile ' + name + ' is already defined '
            logger.warning(err.ElementAlreadyDefined("post_traffic_profile", msg))

        
        elif policy_defined_in_mapping:
            
            msg = 'Ignoring request: the policy ' + mapping['policyName'] + ' is already defined in the mapping ' + mapping_name
            logger.warning(msg)
            raise err.DuplicatePolicy(msg)
            
        else:
            
            if profile_type == 'AppRoute':
                self.app_route_traffic_profiles[name] = {
                    'policyName': mapping['policyName']
                }
    
            elif profile_type == 'Data':
                self.data_traffic_profiles[name] = {
                    'policyName' : mapping['policyName']
                }
                
            else:
                logger.warning('Ignoring request: unknow traffic policy type.')
                logger.warning(err.UnsupportedPolicyType(profile_type, ['AppRoute', 'Data']))


        

    def delete_mapping(self, profile_name):
        self.check_config()
        self.test_connection()
        
        if profile_name in self.app_route_traffic_profiles.keys():            
            
            #Delete endpoints from the policy
            policy_name = self.app_route_traffic_profiles[profile_name]['policyName']
            policy_defined, _ = self.is_policy_defined(policy_name, 'AppRoute')
            if policy_defined:

                self.empty_approute_policy(policy_name,'delete_mapping')
            
                # Regenerate merge policy
                self.create_approute_policy_with_all_endpoints()
            
            
            # Delete associated endpoints from internal variable
            self.delete_service_endpoint_by_profile(profile_name)
            
            # Delete traffic profile from internal variable
            del self.app_route_traffic_profiles[profile_name]
            

        elif profile_name in self.data_traffic_profiles.keys():
                
            #Delete endpoints from the policy
            policy_name = self.data_traffic_profiles[profile_name]['policyName']
            policy_defined, _ = self.is_policy_defined(policy_name, 'Data')
            if policy_defined:
                
                self.empty_data_policy(policy_name, 'delete_traffic_profile')
                #No active policies affected because these profiles are never active

                # Regenerate merge policy
                self.create_data_policy_with_all_endpoints()
            
            # Delete associated endpoints from internal variable
            self.delete_service_endpoint_by_profile(profile_name)

                
            # Delete traffic profile from internal variable
            del self.data_traffic_profiles[profile_name]
        
        else:
            logger.warning(err.CannotFindElement("delete_traffic_profile",\
                "This traffic profile does not exist, ignoring request."))


    def put_mapping(self, profile_name, data):
        self.check_config()
        self.test_connection()
        
        
        profile_defined, profile_type = self.is_traffic_profile_defined(profile_name)
        # Verify new policiy is defined
        policy_defined, new_policy_id = self.is_policy_defined(data['policyName'], data['policyType'])
        #Verify policy NOT in use in other mappings
        policy_defined_in_mapping, mapping_name = self.is_policy_in_mappings(data['policyName'], data['policyType'])
        
        if not profile_defined:
            logger.warning(err.CannotFindElement("put_traffic_profile", \
                "This traffic profile does not exist, ignoring request."))
        
        
        elif not policy_defined:
            logger.warning(err.CannotFindElement("put_traffic_profile", \
                "The policy " + str(data['policyName']) +" does not exist in the sdwan controller, ignoring request."))
                            
        
        elif policy_defined_in_mapping:
            
            msg = 'Ignoring request: the policy ' + data['policyName'] + ' is already defined in the mapping ' + mapping_name
            logger.warning(msg)
            raise err.DuplicatePolicy(msg)
        
        else:
            #List affected endpoints  
            endpoints = self.get_service_endpoints_by_profile(profile_name)
        
            if profile_type == 'AppRoute':
                #Empty old policy
                policy_name = self.app_route_traffic_profiles[profile_name]['policyName']
                self.empty_approute_policy(policy_name, 'put_traffic_profile')
                
                if data['policyType'] == 'AppRoute':
                # AppRoute to AppRoute
                    #Add enpoints to new policy
                    self.add_endpoint_array_approute_policy(new_policy_id, endpoints, 'put_traffic_profile')
                    
                    #Update internal var
                    old_policy = [ self.app_route_traffic_profiles[profile_name]['policyName'] ]
                    self.app_route_traffic_profiles[profile_name]['policyName'] = data['policyName']
                    
                    # Regenerate merge policy
                    self.create_approute_policy_with_all_endpoints(old_policy)
                    
                else:
                # AppRoute to Data
                    #Add endpoints to new policy
                    self.add_endpoint_array_data_policy(new_policy_id, endpoints, 'put_traffic_profile')
                    

                    
                    #Change type of profile
                    old_policy = [ self.app_route_traffic_profiles[profile_name]['policyName'] ]
                    self.data_traffic_profiles[profile_name] = {
                        'policyName' : data['policyName']
                    }               
                    del self.app_route_traffic_profiles[profile_name]

                    # Regenerate merge policies
                    self.create_data_policy_with_all_endpoints()
                    self.create_approute_policy_with_all_endpoints(old_policy)
                    
            elif profile_type == 'Data':
                #Empty old policy
                policy_name = self.data_traffic_profiles[profile_name]['policyName']
                self.empty_data_policy(policy_name, 'put_traffic_profile')
                
                if data['policyType'] == 'Data':
                # Data to Data     
                    
                    #Add endpoints to new policy
                    self.add_endpoint_array_data_policy(new_policy_id, endpoints, 'put_traffic_profile')
                    
                    # Update internal var
                    old_policy = [ self.data_traffic_profiles[profile_name]['policyName'] ]
                    self.data_traffic_profiles[profile_name]['policyName'] = data['policyName']
                    
                    # Regenerate merge policy
                    self.create_data_policy_with_all_endpoints(old_policy)

                        
                else:
                # Data to AppRoute
                    
                    #Add endpoints to new policy
                    self.add_endpoint_array_approute_policy(new_policy_id, endpoints, 'put_traffic_profile')
                    
                    #Change type of profile        
                    old_policy = [ self.data_traffic_profiles[profile_name]['policyName'] ]
                    self.app_route_traffic_profiles[profile_name] = {
                        'policyName': data['policyName']
                    }
                    del self.data_traffic_profiles[profile_name]
                    
                    # Regenerate merge policies
                    self.create_data_policy_with_all_endpoints(old_policy)
                    self.create_approute_policy_with_all_endpoints()

            #Update internal endpoint variable
            for ep in endpoints:
                self.srv_endpoints[ep]['policyId'] = new_policy_id



    def extract_profile(self, service):
        if 'metadata' not in service:
            return None
        
        for elem in service['metadata']:
            if elem['key'] in self.metadata_keys:
                return elem['value']
        return None
    
    def get_md_key_not_defined(self, service):
        if 'metadata' not in service:
            return ['MISSING METADATA ARRAY']
        
        not_def = []
        for elem in service['metadata']:
            if elem['key'] not in self.metadata_keys:
                not_def.append(elem['key'])
        
        return not_def

    def events(self, updates):
        self.check_config()
        self.test_connection()
        error_events =[]
        
        for elem in updates:
            ipAddress = elem['service']['address']
            portNumber = str(elem['service']['port'])
            profileName = self.extract_profile(elem['service'])
            logger.debug('Processing %s event on endpoint %s:%s',  elem['event'], ipAddress, portNumber)
            
            
            
            if elem['event'] == 'delete':
                error, error_data = self.delete_service_endpoint(ipAddress, portNumber)
                if error:
                    error_data['resource'] = elem['service']['name']
                    error_events.append(error_data)
                    
            elif profileName is None:
                #Unknown metadata key 
                error = {}
                error['status'] = 400
                error['resource'] = elem['service']['name']
                error['title'] = 'MISSING METADATA KEY'
                error['description'] = 'The metadata key ' + str(self.get_md_key_not_defined(elem['service'])) + ' is \
                    not currently defined in the adaptor. Ignoring this event.'
                error_events.append(error)
                
            elif elem['event'] == 'create':
                error, error_data = self.post_service_endpoint(ipAddress, portNumber, profileName)
                if error:
                    error_data['resource'] = elem['service']['name']
                    error_events.append(error_data)
            
            elif elem['event'] == 'update':
                error, error_data = self.put_service_endpoint(ipAddress, portNumber, profileName)
                if error:
                    error_data['resource'] = elem['service']['name']
                    error_events.append(error_data)

            else:
                #Unknown operation
                error = {}
                error['status'] = 405
                error['resource'] = elem['service']['name']
                error['title'] = 'Unsupoorted eventy type'
                error['description'] = 'The event ' + elem['event'] + ' is not currently \
                    supported. Supported events: create, update and delete.'
                error_events.append(error)
                
    
        self.create_data_policy_with_all_endpoints()
        self.create_approute_policy_with_all_endpoints()                
            
        if len(error_events) != 0:
            logger.warning('The following elements were ingored: %s', error_events)
            raise err.PartialEventsError(error_events)

