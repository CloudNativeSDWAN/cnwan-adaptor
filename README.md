# CNWAN Adaptor

The CNWAN Adaptor is part of the Cloud Native SD-WAN (CNWAN) project. Please check the [CNWAN documentation](https://github.com/CloudNativeSDWAN/cnwan-docs) for the general project overview and architecture. You can contact the CNWAN team at [cnwan@cisco.com](mailto:cnwan@cisco.com).

## Overview
This CNWAN Adaptor takes as input several cloud parameters, such as endpoint IP and port, and associated metadata (e.g. traffic profiles), and sends them to a SDWAN controller. The controller implements policies to steer traffic flows for these endpoints to the desired tunnel or apply a SLA on them.

The adaptor needs valid credentials for the SDWAN controller (user, password, and IP or domain name).


To see all the possible API calls, run the adaptor and type [http://localhost:80/ui/](http://localhost:80/ui/) in your browser. In addition, the file [CNWAN Adaptor.postman_collection.json](./CNWAN_Adaptor.postman_collection.json) contains a Postman collection with examples of all the API functions. In particular, the Adaptor provides the `/cnwan/events` API endpoint [http://localhost:80/cnwan/events](http://localhost:80/cnwan/events) for the CNWAN Reader to send events.


## Requirements
* Docker Engine 19.03.8+
* Cisco vManage, tested against versions 20.3.1 (recommended) and 19.2.1.


## Usage
The adaptor runs in a Docker container:

```bash
# build the image
docker build -t cnwan_adaptor .

# starting up a container
docker run -p 80:8080 cnwan_adaptor
```

It is possible to specify the SDWAN controller credentials through environment variables:

```bash
docker run -p 80:8080 \
-e SDWAN_IP=sample.server.com \
-e SDWAN_USERNAME=user \
-e SDWAN_PASSWORD=xxxxx \
-e MERGE_POLICY=merge_policy_name \
cnwan_adaptor
```

## Quickstart
If you want a minimal working setup, the script [setup_kubecon_demo.sh](examples/setup_kubecon_demo.sh) sets everything up a for you in the adaptor and your SD-WAN controller. Before running it, please:

* Install the bash utility `jq`
* Take a look at the [policies_definition.json](examples/policies_definition.json) file and adapt it to your environment (tunnels, VPNs and deployment sites). The default values will re-create the [CN-WAN demo presented at KubeCon EU 2020](https://www.cisco.com/c/en/us/training-events/events/kubecon-europe.html#~demos-and-presentations). You can add as many policies and SLAs as you need. In addition, specify the metadata keys and values used by the CNWAN reader.

## SDWAN controller configuration



The adaptor supports both vManage [Application Aware Routing](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/vedge-20-x/policies-book/application-aware-routing.html) (SLAs) and [Traffic Data](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/vedge-20-x/policies-book/data-policies.html) (send traffic to a specific tunnel color) policies.

The adaptor requires the following configuration in vManage (the script [setup_kubecon_demo.sh](examples/setup_kubecon_demo.sh) automates this process):

1. Switching vSmart to vManage mode
2. Creating two empty policies with the same name, one in the Application Aware Routing and other in the Traffic Data sections of Traffic Policy section (in the Custom Options section).
3. A centralized policy referencing the previous two policies, and the sites and VPNs that need these policies.
4. Creating as many [Application Aware Routing](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/vedge-20-x/policies-book/application-aware-routing.html) and [Traffic Data](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/policies/vedge-20-x/policies-book/data-policies.html) policies as needed by the user. The first allow applying a user-defined SLA to the flows, while the latter steer flows through a specific tunnel color.
5. The traffic data policies need a `Traffic Engineering` rule with an empty match and the action `Local TLOC`, specifying the desired color tunnel and encapsulation.
6. The Application Aware Routing policies need an `AppRoute` rule with an empty match and the action `SLA Class List` with the desired SLA class.
6. Send the name of the empty policy to the adaptor in the `sdwanMergedPolicyName` variable in the `credentials` schema (`POST credentials`). The empty policy will be used to merge all the policies into a single one, so later it can be activated.
7. Linking the policies in vManage to the metadata values in the CNWAN reader. Use `POST mappings` this way:
  * `metadataKey` is the key used in the CNWAN reader
  * `metadataValue` is the value used in the CNWAN reader
  * `policyName` is the name of one of the policies defined in step 3
  * `policyType` is `AppRoute` for an Application Aware Routing or `Data` for Traffic Data policies.
8. Note that the `metadataValue` to `policyName` mapping is 1:1 (two metadata values cannot share the same `policyName`). On the other hand, a single `metadataKey` supports any number of `metadataValue`.


## How it works

![Schematic of the CNAWAN Adaptor](examples/adaptor_summary.png)

Internally, the adaptor works this way:
1. Configuration stage:
  1. NetOps define a `Centralized Policy` that references the merge policies, and apply it to the Sites and VPNs they need.
  2. NetOps define as many `AppAware` and `Traffic Data` policies as needed in the SDWAN controller.
  3. NetOps bind these policies to the `metadataValue` in Service Directory using the `POST /mappings` API in the adaptor
2. The adaptor listens to events from the CNWAN reader
3. When the adaptor receives a list of events from the Reader:
  1. Adds each endpoint to the appropriate policy using the previously defined mappings to locate the policy corresponding to each  `metadataValue`. Eg. an endpoint with `metadataValue = video` will be added to the `prefer_biz_internet` policy.  
  2. Copies all endpoints in all CNWAN policies to the merge policy
  3. Triggers the process to update the device templates with the new configuration
  4. The `/events` API call supports adding, removing and updating endpoint information. 

## Other features

* **Live mapping update:** It is possible to issue a `PUT /mapping` at any moment, and the adaptor will move all endpoints from such mapping to the new policy and update accordingly. This feature also supports moving from `TrafficData` to `AppAware`, and viceversa.
* **NetOps-defined policies:** It is possible to add user-defined policies unrelated to the CNWAN operations. Just add them as separate sequences in the merge policy. **WARNING!** Make sure the sequence name is *different* from the policy names used in the CNWAN mappings, otherwise the adaptor will overwrite them with its data. The user-defined policies will be activated along with the CNWAN endpoint sequences.  


## More info


This adaptor was generated by the [swagger-codegen](https://github.com/swagger-api/swagger-codegen) project. By using the
[OpenAPI-Spec](https://github.com/swagger-api/swagger-core/wiki) from a remote server, you can easily generate a server stub.  This
is an example of building a swagger-enabled Flask server.
This example uses the [Connexion](https://github.com/zalando/connexion) library on top of Flask.


## Using the library without the server
It is possible to use the metadata_adaptor python library without the server. It exposes several high level functions equivalent to he ones in the adaptor. To use the library:

```bash
cd adaptor_library
# Generate the package
python3 setup.py sdist bdist_wheel
# Install the package
pip3 install requests
pip3 install dist/metadata_adaptor-2.0.0.tar.gz

# Use the library
python3
import metadata_adaptor.core_lib as sdwan
api = sdwan.api_endpoint()

# Example 1: configure controller credentials
cred = {
    "user": "XXXXXX",
    "password": "XXXXXX",
    "sdwanControllerIpAddress": "sample.server.com",
    "sdwanMergedPolicyName" : "your_merge_policy"
}
api.post_credentials(cred)

# Example 2: create a new mapping
mapping = {
    'metadataKey' : 'traffic-profile',
    'metadataValue' : 'nice_name_to_remember_your_mapping',
    'policyType' : 'Data',
    'policyName' : 'sample_policy_in_controller'
}
api.post_mapping(mapping)
```

You can find all the library functions in [core_lib.py](adaptor_library/metadata_adaptor/core_lib.py)
