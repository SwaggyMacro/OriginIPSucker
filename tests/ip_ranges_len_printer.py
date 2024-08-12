import ipaddress
import os

# foreach loop the ip_blocks directory
for file in os.listdir(os.path.join(os.getcwd(), '../ip_blocks')):
    if file.endswith('.txt'):
        with open(f'../ip_blocks/{file}', 'r') as f:
            ip_ranges = f.read().strip().split('\n')
            total_ips = sum(1 for ip_range in ip_ranges for ip in ipaddress.ip_network(ip_range, strict=False).hosts())
            print(f'{file}\'s IPv4 amount: {total_ips}')
