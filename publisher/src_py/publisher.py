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

def fetch_data():
    
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

def main():
    try:
        parser = argparse.ArgumentParser(
                prog="publisher.py",
                description="Sets up a HTTPS publisher, in accordance with RFC____",
                epilog="---Fill in here---")
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
        

        #response = os.system(f"ping -c 5 {args.ip}")
        #print(response)
        
        if(args.p):
            capabilities_url = f"https://{args.ip}:{args.p}/capabilities"
            url = f"https://{args.ip}:{args.p}/relay-notification"
        else:
            capabilities_url = f"https://{args.ip}/capabilities"
            url = f"https://{args.ip}/relay-notification"
        
        capabilities_response = requests.get(capabilities_url,verify=False)
        capabilities_response.raise_for_status()
        capabilities = capabilities_response
        # capabilities = json.loads(capabilities_response.text)

        content_type = capabilities_response.headers.get('Content-Type')
        print(f"Capabilities discovered through content-type header: {capabilities}")
        print("Body of capabilities response:")
        print(capabilities.text)

        if 'json' in capabilities.text:
            print("Receiver supports JSON encoding")
        if 'xml' in capabilities.text:
            print("Receiver supports XML encoding")
        if 'json' not in capabilities.text and 'xml' not in capabilities.text:
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

            print(interface_data_rx)
            print(interface_data_tx)

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


            try:
                response = requests.post(url, json=payload, headers=headers,verify=False)
                response.raise_for_status()
                print(f"Notification sent successfully: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Failed to send notification: {e}")

            
    except requests.exceptions.RequestException as e:
        print(f"Failed to discover capabilities: {e}")

    except KeyboardInterrupt or AssertionError:
        print("\n\nTerminating Publisher\n")

if __name__ == "__main__":
    main()  

