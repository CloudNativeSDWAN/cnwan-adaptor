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


#!/usr/bin/env python3
# -*- coding: utf-8 -*-


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
    
def create_app_route_empty_match(name, sla_params):
    
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



def build_sla_params(actions):
    sla_id = None
    color = None
    params = []
    
    for act in actions:
        if act["type"] == "slaClass":
            for param in act["parameter"]:
                if param["field"] == "name":
                    sla_id = param["ref"]
                elif param["field"] == "preferredColor":
                    color = param["value"]
    
    params.append({ "field": "name", "ref": sla_id })
            
    if color is not None:
        params.append({ "field": "preferredColor", "value": color})
        
    return params
    
    
def add_approute_endpoint(policy, ipAddress, portNumber):
    last_seq_id = policy["sequences"][-1]["sequenceId"]
    name = policy["name"]
    sla_params = build_sla_params(policy["sequences"][-1]["actions"])
    
    
    
    #Src flow
    if len(policy["sequences"][-1]["match"]["entries"]) == 0:
        # Fill in the empty policy
        policy["sequences"][-1]["match"]["entries"].append(
            { "field": "sourcePort", "value": portNumber})
        
        policy["sequences"][-1]["match"]["entries"].append(
            { "field": "sourceIp","value": ipAddress + '/32'})
    
        # Counter
        policy["sequences"][-1]["actions"].append(
            { "type": "count", 
              "parameter": name +  '_' + str(last_seq_id ) })
    
    else:
        src_seq = {
            "sequenceId": last_seq_id + 1,
            "sequenceName": "App Route",
            "sequenceType": "appRoute",
            "sequenceIpType": "ipv4",
            "match": {
                "entries": [
                    { "field": "sourcePort", "value": portNumber},
                    { "field": "sourceIp","value": ipAddress + '/32'}
                ]
            },
            "actions": [
                {
                    "type": "count",
                    "parameter": name +  '_' + str(last_seq_id + 1)
                },
                {
                    "type": "slaClass",
                    "parameter": sla_params
                }
            ]
        }
        last_seq_id = last_seq_id + 1
        policy["sequences"].append(src_seq)
    
    #Dest flow
    dst_seq = {
            "sequenceId": last_seq_id + 1,
            "sequenceName": "App Route",
            "sequenceType": "appRoute",
            "sequenceIpType": "ipv4",
            "match": {
                "entries": [
                    { "field": "destinationPort", "value": portNumber},
                    { "field": "destinationIp","value": ipAddress + '/32'}
                ]
            },
            "actions": [
                {
                    "type": "count",
                    "parameter": name +  '_' + str(last_seq_id + 1)
                },
                {
                    "type": "slaClass",
                    "parameter": sla_params
                }
            ]
        }
    
    policy["sequences"].append(dst_seq)
   
    return policy




def add_data_endpoint(policy, ipAddress, portNumber):
    last_seq_id = policy["sequences"][-1]["sequenceId"]
    name = policy["name"]
    tunnel = policy["sequences"][0]["actions"][0]['parameter'][0]['value']['color']
    encap = policy["sequences"][0]["actions"][0]['parameter'][0]['value']['encap']
    
    
    #Src flow
    if len(policy["sequences"][-1]["match"]["entries"]) == 0:
        # Fill in the empty policy
        policy["sequences"][-1]["match"]["entries"].append(
            { "field": "sourcePort", "value": portNumber })
        
        policy["sequences"][-1]["match"]["entries"].append(
            { "field": "sourceIp","value": ipAddress + '/32' })
    
        policy["sequences"][-1]["actions"].append(
            { "type": "count",
              "parameter": name + '_' + str(last_seq_id) })
        
    else:
        src_seq = {
          "sequenceId": last_seq_id + 1,
          "sequenceName": "Traffic Engineering",
          "baseAction": "accept",
          "sequenceType": "trafficEngineering",
          "sequenceIpType": "ipv4",
          "match": {
            "entries": [
                { "field": "sourcePort", "value": portNumber},
                { "field": "sourceIp","value": ipAddress + '/32'}
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
              "parameter": name + '_' + str(last_seq_id + 1) 
            }
          ]
        }
        last_seq_id = last_seq_id + 1
        policy["sequences"].append(src_seq)
    #Dst flow
    dst_seq = {
      "sequenceId": last_seq_id + 1,
      "sequenceName": "Traffic Engineering",
      "baseAction": "accept",
      "sequenceType": "trafficEngineering",
      "sequenceIpType": "ipv4",
      "match": {
        "entries": [
           { "field": "destinationPort", "value": portNumber},
           { "field": "destinationIp","value": ipAddress + '/32'}
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
          "parameter":  name + '_' + str(last_seq_id + 1) 
        }
      ]
    }    
    policy["sequences"].append(dst_seq)
    
    
    return policy

def extract_from_entries(entries):
    
    for ent in entries:
        if ent['field'] in ['sourceIp', 'destinationIp']:
            ip = ent['value'].split('/')[0]
        else:
            port = ent['value']
    return ip, port
        
    
def extract_tunnel_encap(actions):
    tunnel = None
    encap = None
    for act in actions:
        if act['type'] == 'set':
            tunnel = act['parameter'][0]['value']['color']
            encap = act['parameter'][0]['value']['encap']
        
    return tunnel, encap
        

def remove_endpoint(policy, ip_del, port_del):
        
    new_seqs = []
    for seq in policy["sequences"]:
        ip, port = extract_from_entries(seq["match"]["entries"])
        if port == port_del and ip == ip_del:
            continue    
        else:
            # Save sequences we want
            new_seqs.append(seq)
    
    
    if len(new_seqs) != 0:
        policy["sequences"] = new_seqs                
    else:
    #regenerate policy with empty match
        if policy["type"] == "appRoute":
            sla_params = build_sla_params(policy['sequences'][0]['actions'])
            regen = create_app_route_empty_match(policy['name'], sla_params)
            policy["sequences"] = regen["sequences"]        
        else:
            tunnel, encap = extract_tunnel_encap(policy['sequences'][0]['actions'])
            regen = create_traffic_data_empty_match(policy['name'], tunnel, encap)
            policy["sequences"] = regen["sequences"]
            
    return policy


def create_empty_policy(policy):
    
    if policy["type"] == "appRoute":
        sla_params = build_sla_params(policy['sequences'][0]['actions'])
        regen = create_app_route_empty_match(policy['name'], sla_params)
        policy["sequences"] = regen["sequences"]        
    else:
        tunnel, encap = extract_tunnel_encap(policy['sequences'][0]['actions'])
        regen = create_traffic_data_empty_match(policy['name'], tunnel, encap)
        policy["sequences"] = regen["sequences"]
     
    return policy

def change_seq_name(policy, new_name):
    
    for seq in policy['sequences']:    
        seq['sequenceName'] =  new_name
        
    return policy['sequences']


def add_cnwan_sequences_to_merge_policy(merge_seqs, cnwan_seqs, previous_cnwan_remove):
    """
    Renumber sequences in the following order:
        1- Sequences already present in the merge policy (if present). Ignore 
           sequences that come from the previous run and are related to cnwan
        2- Sequences corresponding to CN-WAN-defined endpoints
    """
    new_seqs = []
    seqid = 10
    
    for seq in merge_seqs:
        if seq['sequenceName'] in previous_cnwan_remove:
            #Remove cnwan_seqs from previous runs
            continue
        else:
            seq['sequenceId'] = seqid
            new_seqs.append(seq)
            seqid = seqid + 10
        
    for seq in cnwan_seqs:
        seq['sequenceId'] = seqid
        new_seqs.append(seq)
        seqid = seqid + 10
        
    
    return new_seqs
    

def add_array_endpoints_to_data_policy(endpoints, policy):
    
    for ep in endpoints:
        data = ep.split('_')
        ip = data[0]
        port = data[1]
        policy = add_data_endpoint(policy, ip, port)
        
        
    return policy


def add_array_endpoints_to_approute_policy(endpoints, policy):
    
    for ep in endpoints:
        data = ep.split('_')
        ip = data[0]
        port = data[1]
        policy = add_approute_endpoint(policy, ip, port)
        
        
    return policy
        
        
    
    
