# -*- coding: utf-8 -*-
import re
import socket
import ssl

import ssl
import socket
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm


def get_ssl_cert(hostname, port=443, timeout=5):
    # create a ssl context
    context = ssl.create_default_context()
    # get all the certificates including untrusted, expired, etc.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # pack the socket connection into a ssl connection by using the context
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                certificate = ssock.getpeercert(binary_form=True)
    except (ConnectionRefusedError, TimeoutError) as e:
        cert_data = {
            "hostname": hostname,
            "error": f"Connection error: {e}"
        }
        return cert_data

    certificate = ssl.DER_cert_to_PEM_cert(certificate)

    # load the certificate data
    cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

    # parse the certificate data
    issuer = cert.issuer
    subject = cert.subject
    serial_number = cert.serial_number
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    # pack the data into a dictionary
    cert_data = {
        "issuer": issuer,
        "subject": subject,
        "serial_number": serial_number,
        "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S"),
        "valid_to": not_after.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": hostname
    }

    return cert_data


def fetch_threaded_ssl_cert(hostname, port=443, timeout=10, save_to_file=True, save_path='ssl_cert_results.txt'):
    result = get_ssl_cert(hostname, port, timeout)
    if save_to_file:
        save_result_to_file(str(result), save_path)


def load_ips_from_file(file_path):
    with open(file_path, 'r') as f:
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', f.read())
    return ips


def save_result_to_file(data, file_path):
    with open(file_path, 'a') as f:
        f.write(data + '\n')


if __name__ == "__main__":
    FETCH_BLOCK = 'aliyun'
    ips = load_ips_from_file(f'{FETCH_BLOCK}_valid_ips.txt')
    pbar = tqdm(total=len(ips), desc='IP Progress', miniters=1, unit='ip', dynamic_ncols=True)

    # Use threading to scan IP ranges
    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ips:
            # executor.submit(get_ssl_cert, ip, 443, 5)
            executor.submit(fetch_threaded_ssl_cert, ip, 443, 5, True, f'ssl_cert_{FETCH_BLOCK}_valid_ips_results.txt')
            pbar.update(1)
