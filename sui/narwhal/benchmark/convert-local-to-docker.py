#!/usr/bin/env python3
import json
import argparse
import os
from collections import OrderedDict


def modify_and_save_json_committee(filename):
    if not os.path.exists(filename):
        print(f"Error: Committee File {filename} does not exist.")
        return

    with open(filename, 'r') as f:
        data = json.load(f, object_pairs_hook=OrderedDict)
        print("committee.json")
        pretty_data = json.dumps(data, indent=4)
        print(pretty_data)

    # Extract the port numbers and sort them
    port_and_keys = []
    
    for authority_key, authority_value in data['authorities'].items():
        primary_address = authority_value['primary_address']
        port = int(primary_address.split('/')[-1])
        port_and_keys.append((port, authority_key))
    port_and_keys.sort()
    print("committee sorted ports", port_and_keys)
    primary_address = "3000"
    # Update the primary_address field based on sorted port numbers
    for index, (_, authority_key) in enumerate(port_and_keys):
        new_primary_address = f"/dns/primary_{index}/udp/{primary_address}"
        data['authorities'][authority_key]['primary_address'] = new_primary_address

    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def extract_port(address):
    import re
    try:
        return int(re.search(r'/(\d+)', address).group(1))
    except AttributeError:
        return None
    
def modify_and_save_json_workers(filename):
    if not os.path.exists(filename):
        print(f"Error: File {filename} does not exist.")
        return

    with open(filename, 'r') as f:
        data = json.load(f, object_pairs_hook=OrderedDict)
        print("workers.json")
        pretty_data = json.dumps(data, indent=4)
        print(pretty_data)

    worker_port_and_keys = []

    for worker_key, worker_value in data['workers'].items():
        worker_address = worker_value['0']['worker_address']
        port = int(worker_address.split('/')[-1])
        if port is not None:
            worker_port_and_keys.append((port, worker_key))

    # sort key based on worker_address
    worker_port_and_keys.sort()

    # Create a new OrderedDict to hold the sorted data but in original key order
    new_workers_data = OrderedDict()
    worker_address_port = "4002"
    transactions_port = "4001"
    

    print("Ordered worker_address ports", worker_port_and_keys)
    for index, (_, workers_key) in enumerate(worker_port_and_keys):
        new_address = f"/dns/worker_{index}/udp/{worker_address_port}"
        new_transactions = f"/dns/worker_{index}/tcp/{transactions_port}/http"
        data['workers'][workers_key]['0']['worker_address'] = new_address
        data['workers'][workers_key]['0']['transactions'] = new_transactions
        new_workers_data[workers_key] = data['workers'][workers_key]


    # Replace the original 'workers' field with the sorted but originally ordered new data
    data['workers'] = new_workers_data

    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)


def modify_and_save_json_parameter(filename):
    if not os.path.exists(filename):
        print(f"Error: Parameter File {filename} does not exist.")
        return

    with open(filename, 'r') as f:
        data = json.load(f)

    data["consensus_api_grpc"]["socket_addr"] = "/ip4/0.0.0.0/tcp/0/http"
    data["prometheus_metrics"]["socket_addr"] = "/ip4/0.0.0.0/tcp/0/http"

    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Modify fields in JSON files.')
    parser.add_argument('--committee.json', dest='committee_filename', required=True,
                        help='The JSON file containing committee information.')
    parser.add_argument('--workers.json', dest='worker_filename', required=True,
                        help='The JSON file containing worker information.')
    parser.add_argument('--parameters.json', dest='parameter_filename', required=True,
                        help='The JSON file containing parameter information.')

    args = parser.parse_args()

    modify_and_save_json_committee(args.committee_filename)
    modify_and_save_json_workers(args.worker_filename)
    modify_and_save_json_parameter(args.parameter_filename)

    print("Files have been modified.")
