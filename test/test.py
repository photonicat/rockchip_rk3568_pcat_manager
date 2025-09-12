#!/usr/bin/env python3

import socket
import json
import sys

def send_command(command_dict):
    """Send command to pcat-manager socket and return response"""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect('/tmp/pcat-manager.sock')
        command_json = json.dumps(command_dict)
        s.send(command_json.encode() + b'\0')
        response = s.recv(1024)
        return json.loads(response.decode().strip('\0'))
    except Exception as e:
        return {"error": str(e)}
    finally:
        s.close()

def print_section(title):
    """Print a section header"""
    print(f"\n=== {title} ===")

def print_response(response, title):
    """Print formatted response"""
    print(f"\n--- {title} ---")
    if "error" in response:
        print(f"Error: {response['error']}")
    elif response.get("code") == 0:
        for key, value in response.items():
            if key != "code":
                print(f"{key}: {value}")
    else:
        print(f"Command failed with code: {response.get('code')}")
        print(f"Full response: {response}")

def get_all_info():
    """Get and print all available information from pcat-manager"""
    
    print("PCAT Manager - Complete System Information")
    print("=" * 50)
    
    # PMU Firmware Version
    response = send_command({"command": "pmu-fw-version-get"})
    print_response(response, "PMU Firmware Version")
    
    # PMU Status
    response = send_command({"command": "pmu-status"})
    print_response(response, "PMU Status")
    
    # PMU I/O Status
    response = send_command({"command": "pmu-io-get"})
    print_response(response, "PMU I/O Status")
    
    # Modem Status
    response = send_command({"command": "modem-status-get"})
    print_response(response, "Modem Status")
    
    # Modem Network Info
    response = send_command({"command": "modem-network-get"})
    print_response(response, "Modem Network Information")
    
    # Network Route Mode
    response = send_command({"command": "network-route-mode-get"})
    print_response(response, "Network Route Mode")
    
    # Charger Auto Start Status
    response = send_command({"command": "charger-on-auto-start-get"})
    print_response(response, "Charger Auto Start Status")
    
    # Schedule Power Event
    response = send_command({"command": "schedule-power-event-get"})
    print_response(response, "Scheduled Power Events")
    
    print("\n" + "=" * 50)
    print("Information gathering complete")

if __name__ == "__main__":
    get_all_info()
