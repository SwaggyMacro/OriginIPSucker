import concurrent
import gc
import os
import socket
import ipaddress
import traceback

import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import urllib3

urllib3.disable_warnings()


class SCAN_TYPE:
    """
    Enum class for the type of scan to be performed
    """
    IP_PORT = 1
    WEB = 2
    IP_PORT_WEB = 3


VALID_IPS = []
lock = Lock()


def save_valid_ip(ip, port):
    with lock:
        if {'ip': ip, 'port': port} in VALID_IPS:
            return
        VALID_IPS.append({'ip': ip, 'port': port})
        with open(f'{SCAN_BLOCK}_valid_ips.txt', 'a') as f:
            f.write(f'{{"ip": "{ip}", "port": {port}}}\n')


def check_port(ip, port: int = 80, timeout: int = 2):
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_obj:
            result = socket_obj.connect_ex((ip, port))
            if result == 0:
                return ip, port
    except Exception as e:
        return e
    return None


def fetch_content_with_custom_ip(domain, ip, title=None, content=None):
    url = f'http://{ip}'
    headers = {'Host': domain}
    try:
        response = requests.get(url, headers=headers, timeout=3, verify=False)
        if response.status_code == 200:
            encoding = response.encoding if 'charset' in response.headers.get('content-type', '').lower() else 'utf-8'
            try:
                html_content = response.content.decode(encoding, errors='replace')
            except LookupError:
                html_content = response.content.decode('utf-8', errors='replace')
            if title:
                try:
                    site_title = html_content.split('<title>')[1].split('</title>')[0]
                    title = True if title.lower() in site_title.lower() else False
                except IndexError:
                    title = False
            else:
                title = False
            if content:
                # find the content text
                try:
                    content = html_content.index('content')
                except ValueError:
                    content = False
            else:
                content = None
            return True if title or content else False, html_content
        else:
            return False, f'Error: The server responded with status code {response.status_code}'
    except requests.RequestException as e:
        return False, f'Request failed: {e}'


# def scan_network(network, pbar):
#     for ip in network.hosts():
#         port_result = check_port(str(ip), 80)
#         if port_result:
#             save_valid_ip(*port_result)
#         # web_result, web_content = fetch_content_with_custom_ip('baidu.com', str(ip), '百度', '')
#         # if web_result:
#         #     print(web_content)
#         #     print(f'Found valid IP: {ip}')
#
#         pbar.update(1)

def log_scanned_ip(ip, port, msg):
    with open(f'{SCAN_BLOCK}_scan_result', 'a') as f:
        f.write(str({'ip': ip, 'port': port, 'msg': msg}) + '\n')
        f.close()


def load_scanned_ip():
    result = []
    try:
        with open(f'{SCAN_BLOCK}_scan_result', 'r') as f:
            for line in f:
                try:
                    result.append(eval(line.strip()))
                except:
                    pass
    except FileNotFoundError:
        pass
    return result


def is_ip_scanned(ip):
    # SCAN_RESULT format: {'ip': '127.0.0.1', 'port': 80, 'msg': 'web'}
    return ip in SCANNED_IPS_DICT
    # scanned_ips = {scanned_ip['ip'] for scanned_ip in SCAN_RESULT}
    # return ip in scanned_ips


def scan_network(network, pbar, domain=None, scan_type=SCAN_TYPE.IP_PORT, title=None, content=None):
    try:

        global CURRENT_IP_INDEX
        web_result, port_result = None, None
        for ip in network.hosts():
            # start_time = time.time()
            if is_ip_scanned(str(ip)):
                # print(f'Skipping scanned IP: {ip}')
                CURRENT_IP_INDEX += 1
                pbar.update(1)
                # elapsed_time = time.time() - start_time
                # print(elapsed_time)
                continue

            if CURRENT_IP_INDEX % 1000 == 0:
                gc.collect()

            if scan_type == SCAN_TYPE.IP_PORT:
                port_result = check_port(str(ip), 80)
                if port_result:
                    save_valid_ip(*port_result)
            elif scan_type == SCAN_TYPE.WEB:
                web_result, web_content = fetch_content_with_custom_ip(domain, ip, title, content)
                if web_result:
                    # print(web_content)
                    print(f'Found valid IP: {ip}')
                    save_valid_ip(ip, 80)
            elif scan_type == SCAN_TYPE.IP_PORT_WEB:
                port_result = check_port(str(ip), 80)
                if port_result:
                    save_valid_ip(*port_result)
                web_result, web_content = fetch_content_with_custom_ip(domain, str(ip), title, content)
                if web_result:
                    print(web_content)
                    print(f'Found valid IP: {ip}')
                    save_valid_ip(ip, 80)
            log_scanned_ip(str(ip), 80,
                           'web' if scan_type == SCAN_TYPE.WEB and web_result else 'port' if scan_type == SCAN_TYPE.IP_PORT and port_result else 'web_port' if scan_type == SCAN_TYPE.IP_PORT_WEB and (
                                   port_result or web_result) else 'none')
            CURRENT_IP_INDEX += 1
            pbar.update(1)
    except:
        traceback.print_exc()


if __name__ == '__main__':
    os.environ["no_proxy"] = "*"  # Disable proxy for local requests

    SCAN_BLOCK = 'aliyun'  # aliyun, tencent, hk, ucloud

    CURRENT_IP_INDEX = 0

    SCAN_RESULT = load_scanned_ip()

    SCANNED_IPS_DICT = {data['ip']: data for data in SCAN_RESULT}

    Target = 'www.baidu.com'  # Target ip or domain, ip only if scanning for ports

    # Read IP ranges from the file
    with open(f'./ip_blocks/{SCAN_BLOCK}.txt', 'r') as file:
        ip_ranges = file.read().strip().split('\n')

    # Calculate total number of IPs to be scanned for the progress bar
    total_ips = sum(1 for ip_range in ip_ranges for ip in ipaddress.ip_network(ip_range, strict=False).hosts())

    # Set up the progress bar
    pbar = tqdm(total=total_ips, desc='IP Progress', miniters=1, unit='ip', dynamic_ncols=True)

    # Use threading to scan IP ranges
    with ThreadPoolExecutor(max_workers=1000) as executor:
        futures = {executor.submit(scan_network, ipaddress.ip_network(ip_range.strip(), strict=False), pbar,
                                   Target, SCAN_TYPE.WEB, ' ', None): ip_range for
                   ip_range in ip_ranges}

    # Wait for all the futures to complete
    for future in concurrent.futures.as_completed(futures):
        pass

    # Ensure the progress bar closes properly
    pbar.close()
