# Import Deps
from ipaddress import IPv4Address
import re
import os
import pyperclip
import requests
import json

# TODO
# Help Function
# Better comments
# Find a way to do clipboard copying in virtualized linux envs without xforwarding
# Multi Threading

# Globals
previous_output = ""

# API Keys
abuseipdb_api_key = ''

# API Headers and URLs
# AbuseIPDB
abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
abuseipdb_headers = {
    'Accept': 'application/json',
    'Key': abuseipdb_api_key
}

# API Functions
def abuseipdb_lookup(ip_addresses):
    print("AbuseIPDB Lookup Results")
    print("-------------------------------------------------")
    results = []
    all_outputs = ""  # Initialize an all_outputs variable to concatenate all outputs.
    for ip in ip_addresses:
        abuseipdb_query = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        response = requests.get(abuseipdb_url, headers=abuseipdb_headers, params=abuseipdb_query)
        if response.status_code == 200:
            decoded_response = response.json()
            result = {
                'IPAddress': ip,
                'AbuseConfidenceScore': decoded_response['data']['abuseConfidenceScore'],
                'TotalReports': decoded_response['data']['totalReports']
            }
            results.append(result)
            score = result['AbuseConfidenceScore']
            individual_output = f"IP: {result['IPAddress']}, Abuse Confidence Score: {result['AbuseConfidenceScore']}, Reports: {result['TotalReports']}"
            if score > 60:
               all_outputs += f"\033[91m{individual_output}\033[0m\n"
            elif score > 30:
               all_outputs += f"\033[93m{individual_output}\033[0m\n"
            else:
               all_outputs += individual_output + "\n"   
    return results, all_outputs

# Hash Functions
def regex_sha256(text): # Regex to location in SHA256 hashes in text input
    pattern = r"\b[A-Fa-f0-9]{64}\b"
    output =  re.findall(pattern, text)
    return set(output)

def regex_sha1(text): # Regex to location in SHA1 hashes in text input
    pattern = r"\b[a-fA-F0-9]{40}\b"
    output = re.findall(pattern, text)
    return set(output)

def regex_md5(text): # Regex to location in MD5 hashes in text input
    pattern = r"([a-fA-F\d]{32})"
    output = re.findall(pattern, text)
    return set(output)
# IP Addresses Functions
def grep_ipv4(text): # Regex to locate any IPV4 addresses in text input
    pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    output = re.findall(pattern, text)
    return set(output)

# Text Manipulation Functions
def newline_to_space(text): # Takes text input and replaces newline characters with a space
    return text.replace('\n', ' ').strip()

def remove_blank_lines(text): # Strips text input of newline characters
    output_clean = "\n".join([line for line in text.split('\n') if line.strip()])
    return output_clean

# URI(s) Functions
def return_urls(text):
    pattern = r"(((https://)|(http://))?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"
    return re.findall(pattern, text)

def defang_urls(text):
    return_urls(text)

def tuple_to_strings(text):
    output = return_urls(text)
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    clean = []
    for url_tuple in output:
        for url in url_tuple:
            if url and '.' in url:  # Check if it's a URL
                if url.startswith(('http://', 'https://')) and not url.startswith('/'):
                    clean.append(url)
            elif url and not url.startswith(('http://', 'https://')) and not url.startswith('/'):
                clean.append(url)
    return set(clean)

# File Functions
def executable_finder(text):
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    pattern = r"([^,\s]+\.exe|[^,\s]+\.bat|[^,\s]+\.cmd|[^,\s]+\.sh|[^,\s]+\.bin)\b"
    output = re.findall(pattern, text)
    return set(output)


# Main Menu Functions
def menu_operations():
    global text, previous_output
    while True:
        print("\nMenu:")
        print("1) Find Hashes")
        print("2) IP Submenu")
        print("3) Text Manipulation")
        print("4) Find URIs")
        print("7) File Finder")
        print("8) Exit")
        print("9) Clear Terminal")
        print("10) Input data")
        print("11) Store Previous Output to Clipboard")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            os.system('clear')  # Clear terminal
            hash_submenu()

        elif choice == "2":
            output = ip_submenu()

        elif choice == "3":
            os.system('clear')
            text_manipulation_submenu()
            
        elif choice == "4":
            os.system('clear')  # Clear terminal
            URI_submenu()

        elif choice == "7":
            os.system('clear')  # Clear terminal
            file_finder_submenu()
        
        elif choice == "9":
            os.system('clear')

        elif choice == "10":
            get_input()

        elif choice == "11":
            copy_output(previous_output)

        elif choice == "8":
            os.system('clear')  # Clear terminal
            break
        else:
            print("Invalid option, please try again.")

# Submenu Functions
def URI_submenu():
    global text, previous_output
    output = []
    while True:
        print("\nURI Submenu:")
        print("1) Find URI")
        print("2) Find URI [DEFANGED]")
        print("3) Clear Terminal")
        print("4) Copy Previous Output to Clipboard")
        print("5) Return to Main Menu")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            output = ""
            output2 = tuple_to_strings(text)
            for i in output2:
                print(i)
                output += '\n' + i
        elif choice == "2":
            output = ""
            output2 = tuple_to_strings(text)
            for i in output2:
                print(i.replace('.', '[.]'))
                i = i.replace('.', '[.]')
                output += '\n' + i
        elif choice == "3":
            os.system("clear")
        elif choice == "4":
            copy_output(output)
        elif choice == "5":
            os.system('clear')
            break

# Hash Submenu Function
def hash_submenu():
    global text, previous_output
    while True:
        print("\nHash Submenu:")
        print("1) Find SHA256")
        print("2) Find SHA1")
        print("3) Find MD5")
        print("4) Store Previous Output to Clipboard")
        print("5) Back to Main Menu")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            output = regex_sha256(text)
            print_output(output)
        elif choice == "2":
            output = regex_sha1(text)
            print_output(output)
        elif choice == "3":
            output = regex_md5(text)
            print_output(output)
        elif choice == "4":
            copy_output(previous_output)
        elif choice == "5":
            os.system('clear')  # Clear terminal
            break
        else:
            print("Invalid option, please try again.")

# File Finder Submenu Function
def file_finder_submenu():
    global text, previous_output
    while True:
        print('\n File Finder Submenu:')
        print("1) Find Executables")
        print("2) Return to Main Menu")
        print("3) Store Previous Output to Clipboard")
        print("9) Clear Terminal")
        choice = input("Enter your choice: ")

        if choice == "1":
            output = ""
            output2 = executable_finder(text)
            for exe in output2:
                output += '\n' + exe
            print_output(output2)
        elif choice == "3":
            copy_output(output)
        elif choice == "9":
            os.system("clear")
        elif choice == "2":
            os.system('clear')
            break

# Text Manipulation Submenu Function
def text_manipulation_submenu():
    global text, previous_output
    while True:
        print('\n Text Manipulation Submenu:')
        print("1) Newline to Spaces")
        print("2) Remove Blank Lines")
        print("3) Return to Main Menu")
        print("4) Store Previous Output to Clipboard")
        print("9) Clear Terminal")
        choice = input("Enter your choice: ")
        if choice == "1":
            output = newline_to_space(text)
            previous_output = output
            print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
            print(output)
        elif choice == "2":
            output = remove_blank_lines(text)
            previous_output = output
            print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
            print(output)
        elif choice == "3":
            os.system("clear")
            break
        elif choice == "4":
            copy_output(previous_output)
        elif choice == "9":
            os.system('clear')

# IP Submenu Function
def ip_submenu():
    global text, previous_output
    while True:
        print('\n IP Address(es) Submenu:')
        print("1) Get IPV4 Addresses")
        print("2) AbuseIPDB Lookup [Could take a while for lots of lookups]")
        print("3) Return to Main Menu")
        print("4) Store Previous Output to Clipboard")
        print("9) Clear Terminal")
        choice = input("Enter your choice: ")
        output = ""
        if choice == "1":
            ips = grep_ipv4(text)
            for ip in ips:
                output += ip + '\n'
            previous_output = output.strip()
            print_output(ips)
        elif choice == "2":
            os.system('clear')  # Clear terminal
            ips_for_lookup = grep_ipv4(text)  # Using grep_ipv4 to get IPs from text
            if not ips_for_lookup:  # Check if the list is empty
                print("No IPs found.")
                output = "No IPs found."
            else:
                lookup_results, abuse_output = abuseipdb_lookup(ips_for_lookup)
                previous_output = abuse_output  # Capture the last abuseipdb output result for copying.
                for result in lookup_results:
                    formatted_result = f"IP: {result['IPAddress']}, Score: {result['AbuseConfidenceScore']}, Reports: {result['TotalReports']}"
                    output += formatted_result + '\n'
                print(abuse_output)
        elif choice == "3":
            os.system('clear')
            break
        elif choice == "4":
            copy_output(previous_output)
        elif choice == "9":
            os.system("clear")

# Output operations        
def print_output(output):
    global previous_output
    os.system('clear')
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    for i in output:
        print(i)
    previous_output = '\n'.join(output)

def copy_output(output):
    if output:
        pyperclip.copy(output)
        print("Output copied to clipboard.")
    else:
        print("No output to copy.")

def get_input():
    global text
    while True:
        choice = input("\nEnter 'I' for input or 'F' for file path: ")
        if choice.upper() == 'I':
            print("Enter your text (type DONE! or press Ctrl + D (Linux) or Ctrl + Z (Windows) to finish):")
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    os.system('clear')
                    break

                if line.strip().upper() == "DONE!":
                    os.system('clear')
                    break
                lines.append(line)
            
            text = '\n'.join(lines)
            os.system('clear')
            break
        elif choice.upper() == 'F':
            file_path = input("Enter the file path: ")
            try:
                with open(file_path, 'r') as file:
                    text = file.read()
                break
            except FileNotFoundError:
                print("File not found. Please enter a valid file path.")
        else:
            print("Invalid option, please try again.")

# Main
if __name__ == "__main__":
    text = ''
    menu_operations()
