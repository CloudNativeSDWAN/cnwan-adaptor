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


#!/usr/bin/env python2
# -*- coding: utf-8 -*-


#src: https://docs.python.org/3/tutorial/errors.html
class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class NoConfigData(Error):
    """There is no configuration data. """
    def __init__(self, missing_data):
        self.missing_data = missing_data

class GETError(Error):
    def __init__(self, function, status_code, message):
        self.function = function
        self.status_code = status_code
        self.message = message
        self.http_message = 'GET'

class POSTError(Error):
    def __init__(self, function, status_code, message):
        self.function = function
        self.status_code = status_code
        self.message = message
        self.http_message = 'POST'
        
class DELETEError(Error):
    def __init__(self, function, status_code, message):
        self.function = function
        self.status_code = status_code
        self.message = message
        self.http_message = 'DELETE'
        
class PUTError(Error):
    def __init__(self, function, status_code, message):
        self.function = function
        self.status_code = status_code
        self.message = message
        self.http_message = 'PUT'
        
class CannotFindElement(Error):
    def __init__(self, function, elem):
        self.function = function
        self.elem = elem

class ElementAlreadyDefined(Error):
    def __init__(self, function, desc):
        self.function = function
        self.desc = desc
        
class UnsupportedPolicyType(Error): 
    def __init__(self, req, supported):
        self.req = req
        self.supported = supported
        
class UpdateError(Error):
    def __init__(self, function, message, description):
        self.function = function
        self.message = message
        self.description = description
        
class PartialEventsError(Error):
    def __init__(self, error_array):
        self.error_array = error_array
        

        