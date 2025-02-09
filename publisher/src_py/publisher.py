import re
import argparse
import time
import random
import sys
import socket
import os
import requests
import datetime
import json
import dicttoxml

def fetch_data_new():
    interfaces = os.listdir("/sys/class/net/")
    # looping through all interfaces does not work as some files are not readable (!TODO - investigate why)
    return {"enx0c37962a29ea": get_interface_info("enx0c37962a29ea")}


def read_file(path):
    try:
        with open(path, 'r') as f:
            print(path)
            # return f.read().strip()
            return f.read()
    except FileNotFoundError:
        return None

def get_interface_info(iface):
    iface_path = f"/sys/class/net/{iface}/"
    stats_path = f"{iface_path}/statistics/"
    
    interface = {
        "name": iface,
        "description": "",              #not sure where to find this information
        "type": read_file(iface_path + "type"),
        "enabled": read_file(iface_path + "carrier") == "1",
        "admin-status": "up" if "UP" in read_file(iface_path + "flags") else "down",
        "oper-status": read_file(iface_path + "operstate"),
        "last-change": "",              # not available directly
        "if-index": read_file(iface_path + "ifindex"),
        "phys-address": read_file(iface_path + "address"),
        "higher-layer-if": [],              # ??? 
        "lower-layer-if": [],               # ??? not available directly
        "speed": read_file(iface_path + "speed"),
        "statistics": {
            "discontinuity-time":   "",             # not available directly
            "in-octets": read_file(stats_path + "rx_bytes"),
            "in-unicast-pkts": read_file(stats_path + "rx_packets"),
            "in-broadcast-pkts": read_file(stats_path + "rx_broadcast"),
            "in-multicast-pkts": read_file(stats_path + "rx_multicast"),
            "in-discards": read_file(stats_path + "rx_dropped"),
            "in-errors": read_file(stats_path + "rx_errors"),
            "in-unknown-protos": None,              # not directly available
            "out-octets": read_file(stats_path + "tx_bytes"),
            "out-unicast-pkts": read_file(stats_path + "tx_packets"),
            "out-broadcast-pkts": read_file(stats_path + "tx_broadcast"),
            "out-multicast-pkts": read_file(stats_path + "tx_multicast"),
            "out-discards": read_file(stats_path + "tx_dropped"),
            "out-errors": read_file(stats_path + "tx_errors"),
        }
    }
    return interface
    


def fetch_data():
    #!TODO - IN-PROGRESS- change this to the interface YANG model defined in RFC8343
    interface_info_rx = ["bytes","packets","errs","drop","fifo","frame","compressed","multicast"]
    interface_info_tx = ["bytes","packets","errs","drop","fifo","colls","carrier","compressed"]
    #print(interface_info_rx[0])
    interface_data_rx = {}
    interface_data_tx = {}
    with open("/proc/net/dev",'r',encoding="utf-8") as f:
        data = f.readlines()[2:]    #skipping first two lines as they are the data headers
        for line in data:
            
            interface_name =line[0: line.find(':')]
            print(interface_name)
            interface_data_combined = line[line.find(':')+1:]
            split_data = re.findall(r'\d+', interface_data_combined)
            
            interface_data_rx[interface_name] = split_data[:8]
            interface_data_tx[interface_name] = split_data[9:]
            

    return (interface_data_rx, interface_data_tx)

def valid_ipv4_ipv6(addr):
    try:
        socket.inet_pton(socket.AF_INET,addr)
    except:
        try:
            socket.inet_pton(socket.AF_INET6,addr)
        except:
            return False
        
        return True
    
    return True

def get_capabilities(url):
    try:
        response = requests.get(url, verify=False, headers={'Accept': 'application/json, application/xml'})
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"Failed to discover capabilities: {e}")
        raise KeyboardInterrupt

def send_notification(url, payload, headers):
    try:
        response = requests.post(url, data=payload, headers=headers, verify=False)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"Failed to send notification: {e}")
        raise KeyboardInterrupt


def main():
    try:
        parser = argparse.ArgumentParser(
                prog="publisher.py",
                description="Sets up a HTTPS publisher, in accordance with RFC____",
                epilog="-------------------------------")                             ## To be done : Add appropriate epilog
        parser.add_argument("ip",type=str,help="IP Address to send YANG notification. Can be IPV4 or IPV6. IPv4 addresses follow dotted decimal format, as implemented in inet_pton(). IPv6 addresses also follow inet_pton() implementation standards. See RFC 2373 for further details on the representation of Ipv6 addresses")
        parser.add_argument("-t",type=float,help="Time interval between requests (in seconds)")
        parser.add_argument("-r",type=int,help="Sends notifications randomly, with the time interval being a random number between (0,argument)")
        parser.add_argument("-p",type=int,help="Port number to send YANG notification.")
        parser.parse_args()
        args = parser.parse_args()
        # print(args.ip)

        time_interval = args.t if args.t else 2
        
        print(args.ip)
        if( not valid_ipv4_ipv6(args.ip)):
            print("Invalid IP Address")
            raise KeyboardInterrupt
        
        
        if(args.p):
            capabilities_url = f"https://{args.ip}:{args.p}/capabilities"
            notification_url = f"https://{args.ip}:{args.p}/relay-notification"
        else:
            capabilities_url = f"https://{args.ip}/capabilities"
            notification_url = f"https://{args.ip}/relay-notification"

        capabilities_response = get_capabilities(capabilities_url)
        capabilities = capabilities_response
        
        # capabilities_response = requests.get(capabilities_url,verify=False)
        # capabilities_response.raise_for_status()
        # capabilities = json.loads(capabilities_response.text)

        content_type = capabilities_response.headers.get('Content-Type')
        print(f"Capabilities discovered through content-type header: {capabilities}")
        print("Body of capabilities response:")
        print(capabilities_response.text)

        if 'json' in capabilities_response.text:
            print("Receiver supports JSON encoding")
        if 'xml' in capabilities_response.text:
            print("Receiver supports XML encoding")
        if 'json' not in capabilities_response.text and 'xml' not in capabilities_response.text:
            print("Receiver does not support any valid encoding type!")
            raise AssertionError("Receiver does not support any valid encoding type!")
            

        while(True):
            if(args.r):
                time_interval = random.randint(0,args.r)
                if(args.t):
                    print("Error: argument -r cannot be accompanied by any other argument like -t")
                    sys.exit(0)

            time.sleep(time_interval)
            (interface_data_rx,interface_data_tx) = fetch_data()
            # interface_data_yang8343 = fetch_data_new()
            interface_data_yang8343 = {
                    "interfaces": fetch_data_new()
                }

            #DEBUG
            # print(interface_data_rx)
            # print(interface_data_tx)
            print(datetime.datetime.now().isoformat() + 'Z')
            

            payload = {
            "notification": {
                "eventTime": datetime.datetime.now().isoformat() + 'Z',
                "interface_data_rx": interface_data_rx,
                "interface_data_tx": interface_data_tx
                    }
                }
            headers = {'Content-Type': f'{content_type}'}  
            
            if 'json' in capabilities.text:
                payload = json.dumps(payload)
            elif 'xml' in capabilities.text:
                payload = dicttoxml.dicttoxml(payload)

            response = send_notification(notification_url, payload, headers)

            
    except requests.exceptions.RequestException as e:
        print(f"Failed to discover capabilities OR Send notification(s): {e}")

    except KeyboardInterrupt or AssertionError:
        print("\n\nTerminating Publisher\n")

if __name__ == "__main__":
    main()  

