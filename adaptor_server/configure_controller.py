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
import connexion
import six
import sys
import traceback

from cnwan_adaptor.models.credentials import Credentials  # noqa: E501
from cnwan_adaptor.models.mapping import Mapping  # noqa: E501
from cnwan_adaptor.models.mapping_update import MappingUpdate  # noqa: E501
from cnwan_adaptor.models.service_endpoint_events import ServiceEndpointEvents  # noqa: E501
from cnwan_adaptor import util

import metadata_adaptor.core_lib as sdwan
import metadata_adaptor.server_errors as err

api = sdwan.api_endpoint()


def process_exception(e):

    response = {}
    ex_type = type(e)
    
    
    tb = sys.exc_info()[2]
    extract_tb =  traceback.extract_tb(tb)
    

    if ex_type is err.NoConfigData:
        # No credentials in config
        response['status'] = 503
        response['title'] = 'AUTHENTICATION ERROR'
        response['description'] = 'SD-WAN Controller credentials invalid or \
            not set via environment variables nor via POST /credentials'
        return response, 503
    
    if ex_type is err.PartialEventsError:
        response['status'] = 207
        response['errors'] = e.error_array
        response['title'] = 'INVALID RESOURCES'
        response['description'] = 'Some resources have not been processed successfully. List of failed resources is included.'
        return response, 207
    
    if ex_type is err.DuplicatePolicy:
        response['status'] = 400
        response['title'] = 'POLICY ALREADY DEFINED IN ANOTHER MAPPING'
        response['description'] = e.message
        return response, 400
    

    response['status'] = 500
    response['title'] = 'UNKNOWN INTERNAL SERVER ERROR: Exception name ' \
          + repr(e) + 'Internal exception description'  + str(e) 
    response['description'] =  'TRACEBACK: ' + str(traceback.format_list(extract_tb))
    

    
    return response, 500

def delete_credentials():  # noqa: E501
    """Delete SDWAN controller credentials

     # noqa: E501


    :rtype: None
    """
    try:
        api.delete_credentials()
    except Exception as e:
        response, code = process_exception(e)
        return response, code

    response= {'detail':'Delete OK'}
    return response, 200

def delete_mapping(metadata_value):  # noqa: E501
    """Delete mapping

     # noqa: E501

    :param traffic_profile: Traffic profile name
    :type traffic_profile: str

    :rtype: None
    """
    try:
        api.delete_mapping(metadata_value)
    except Exception as e:
        response, code = process_exception(e)
        return response, code

    response = {}
    response['detail'] = 'Delete OK'
    return response, 201

def events(body):  # noqa: E501
    """Send metadata updates for several endpoints at the same time

     # noqa: E501

    :param body: An array of endpoints to update, with the associated operation and metadata
    :type body: list | bytes

    :rtype: None
    """
    if connexion.request.is_json:
        #body = [ServiceEndpointEvents.from_dict(d) for d in connexion.request.get_json()]  # noqa: E501
        body = connexion.request.get_json()
        print(body)
        try:
            api.events(body)
        except Exception as e:
            response, code = process_exception(e)
            return response, code

        response= {}
        return response, 204
    else:
        return "expecting a JSON file", 400


def get_credentials():  # noqa: E501
    """Get current SDWAN controller credentials

     # noqa: E501


    :rtype: Credentials
    """
    try:
        response = api.get_credentials()
    except Exception as e:
        response = {}
        response['detail'] = 'Unknow Internal Server Error'
        response['Internal exception description'] = str(e)
        response['Excpetion name'] = repr(e)
        return response, 500

    return response, 200

def get_mappings():  # noqa: E501
    """Get current mappings

     # noqa: E501


    :rtype: List[Mapping]
    """
    try:
        response = api.get_mappings()
    except Exception as e:
        response, code = process_exception(e)
        return response, code

    return response, 200


def post_credentials(body):  # noqa: E501
    """Configure SDWAN controller credentials

     # noqa: E501

    :param body: SDWAN controller User, Password and IP address or URL
    :type body: dict | bytes

    :rtype: None
    """
    if connexion.request.is_json:
        #body = Credentials.from_dict(connexion.request.get_json())  # noqa: E501
        body = connexion.request.get_json()
        print("RX data", body)
        try:
            api.post_credentials(body)
        except Exception as e:
            response, code = process_exception(e)
            return response, code

        response= {'detail':'Config OK'}
        return response, 200

    else:
        return "expecting a JSON file", 400


def post_mapping(body):  # noqa: E501
    """Create a new mapping entry

     # noqa: E501

    :param body: Definition of a new mapping
    :type body: dict | bytes

    :rtype: None
    """
    if connexion.request.is_json:
        #body = Mapping.from_dict(connexion.request.get_json())  # noqa: E501
        body = connexion.request.get_json()
        print("RX data", body)
        try:
            api.post_mapping(body)
        except Exception as e:
            response, code = process_exception(e)
            return response, code

        response= {'detail':'Config OK'}
        return response, 200
    else:
        return "expecting a JSON file", 400

def put_mapping(body, metadata_value):  # noqa: E501
    """Update the definition of an existing mapping

     # noqa: E501

    :param body: mapping definition
    :type body: dict | bytes
    :param metadata_value: Metadata value
    :type metadata_value: str

    :rtype: None
    """
    if connexion.request.is_json:
        #body = MappingUpdate.from_dict(connexion.request.get_json())  # noqa: E501
        body = connexion.request.get_json()
        print("RX data", body)
        try:
            api.put_mapping(metadata_value, body)
        except Exception as e:
            response, code = process_exception(e)
            return response, code

        response= {'detail':'Update OK'}
        return response, 200
    else:
        return "expecting a JSON file", 400
