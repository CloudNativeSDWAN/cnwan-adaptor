# Copyright 2020 Cisco
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


if [ $# -ne 3 ]
  then
    echo "Usage setup_kubecon_demo.sh vmanage_ip username password"
    exit 1
fi
set -e

vmanage_ip=$1
username=$2
password=$3

# Create python venv
python3 -m venv venv
source venv/bin/activate
pip3 install requests

# Configure SDWAN controller
# Switch vsmart to vManage mode
python3 vsmart_switch.py $vmanage_ip $username $password vmanage
# Create empty policies
python3 create_policies_json_input.py $vmanage_ip $username $password
deactivate



# Build and run the adaptor
temp=`jq '.merge_policy_name' policies_definition.json`
merge_policy_name="${temp//\"}"
cd ..
docker build -t cnwan_adaptor .
docker run --name cnwan_adaptor -d -p 8080:8080 \
     -e SDWAN_IP=$vmanage_ip \
     -e SDWAN_USERNAME=$username \
     -e SDWAN_PASSWORD=$password \
     -e MERGE_POLICY=$merge_policy_name \
     cnwan_adaptor


sleep 3
# Configure the adaptor with the mappings
cd examples

metadata_key=`jq '.metadataKey' policies_definition.json`
num_data_policies=`jq '."data_policies" | length' policies_definition.json`
num_appr_policies=`jq '."app_aware_policies" | length' policies_definition.json`


for ((pos=0;pos<$num_data_policies;pos++));
do

  metadata_value=`jq ."data_policies"[$pos][0] policies_definition.json`
  policy_name=`jq ."data_policies"[$pos][1] policies_definition.json`
  payload="{\"metadataKey\": $metadata_key, \"metadataValue\": $metadata_value, \"policyName\": "$policy_name", \"policyType\": \"Data\"}"
  echo "POST /mappings $metadata_value -> $policy_name"
  curl -H "Content-Type: application/json" \
      -d "$payload" \
      http://localhost:8080/mappings
done

for ((pos=0;pos<$num_appr_policies;pos++));
do

  metadata_value=`jq ."app_aware_policies"[$pos][0] policies_definition.json`
  policy_name=`jq ."app_aware_policies"[$pos][1] policies_definition.json`
  payload="{\"metadataKey\": $metadata_key, \"metadataValue\": $metadata_value, \"policyName\": "$policy_name", \"policyType\": \"AppRoute\"}"
  echo "POST /mappings $metadata_value -> $policy_name"
  curl -H "Content-Type: application/json" \
      -d "$payload" \
      http://localhost:8080/mappings
done


echo "Done!"
echo "The CNWAN adaptor is ruuning at http://localhost:8080/ui/"
