import requests
import json 
from tabulate import tabulate
import re


__author__ = 'Natsu'
__version__ = 'v0.1'

# ANSI color codes
class Colors:
    HEADER = '\033[95m'  # Purple
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'    # Reset color
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
class IPInfo: 
    '''' A class to fetch and handle information about IP addresses using the IPinfo API. '''
    def __init__(self, token: str, ip_list: list) -> None:
        '''
        Initializes the IPInfo instance with an API token and a list of IP addresses.
        
        :param token: The authentication token required for accessing the IPinfo API.
        :param ip_list: A list of IP addresses for which information is to be fetched.
        '''
        self.token = token
        self.ip_list = ip_list
        
    def get_info(self) -> dict:
        '''
        Fetches information for each IP address in the ip_list using the IPinfo API.
        '''
        data = {}
        for _ in self.ip_list: 
            url = f'https://ipinfo.io/{_}?token={self.token}'
            res = requests.get(url)
            data[_] =  json.loads(res.text)
        return data 
    
class IPChecker: 
    '''Class to check IP addresses using the VirusTotal API.'''
    
    def __init__(self, x_apikey, ipinfo_token, ip_list):
        '''
        Initialize the IPChecker object with an API key and a list of IP addresses.
        :param x_apikey: API key for accessing the VirusTotal API. 
        :param ip_list: List of IP addresses as strings to be checked.
        '''
        self.x_apikey = x_apikey
        self.ip_list = ip_list
        self.ipinfo = IPInfo(token=ipinfo_token, ip_list=ip_list).get_info()

    def get_an_ip_address_report(self) -> dict:
        '''
        Retrive reporst for a list of IP addresses using the VirusTotal API.
        
        Each IP address is queried to the VirusTotal API, and results are returned
        as a dictionary mapping IP addresses to their corresponding data fetched
        from the API.
        
        :return dict: A dictionary where each key is an IP address from the input list and
                each value is the data retrieved from the API for that IP address, if
                the query was successful. Unsuccessful queries will not be included.
        '''
        headers = {'x-apikey': self.x_apikey}
        result = {}
        for ip in self.ip_list:
            res = requests.get(url=f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers=headers)
            if res.status_code == 200:
                result[ip] = json.loads(res.text)['data']
        return result

    def output_template(self) -> dict:
        '''
        Compiles a summary of IP address reports into a dictionary.
        
        This method fetches reports from the get_an_ip_address_report method and summarizes the number
        of malicious and undetected judgments for each IP. If an IP's report is missing, `None` is assigned
        to its values in the summary.

        :return dict: A dictionary containing lists under keys 'IP', 'Malicious', and 'Undetected'.
                    Each list contains information corresponding to the list of IP addresses.
        '''
        res = self.get_an_ip_address_report()
        dic = {
            'ip': [],
            'asn': [],
            'malicious': [],
            'harmless': [],
            'undetected': [],
            'hostname': [],
            'anycast': [],
            'region': []
        }
        for ip in self.ip_list:
            if ip in res:
                total_detected = len (res[ip]['attributes']['last_analysis_results'])
                dic['ip'].append(f'{ip} ({res[ip]["attributes"]["country"]})')
                dic['asn'].append(res[ip]['attributes']['asn'])
                dic['malicious'].append(f"{Colors.WARNING}{res[ip]['attributes']['last_analysis_stats']['malicious']}/{total_detected}{Colors.ENDC}")
                dic['harmless'].append(f"{Colors.OKGREEN}{res[ip]['attributes']['last_analysis_stats']['harmless']}/{total_detected}{Colors.ENDC}")
                dic['undetected'].append(f"{res[ip]['attributes']['last_analysis_stats']['undetected']}/{total_detected}")
                if 'hostname' in self.ipinfo[ip].keys():
                    dic['hostname'].append(f"\033[92m {self.ipinfo[ip]['hostname']} \033[0m")
                else:
                    dic['hostname'].append(f'\033[92m Null \033[0m')
                if 'anycast' in self.ipinfo[ip].keys():
                    dic['anycast'].append(str(self.ipinfo[ip]['anycast']))
                else:
                    dic['anycast'].append('False')
                dic['region'].append(self.ipinfo[ip]['region'])
            
        return dic
    
def validate_ipv4(ip_addr, ipv4_regex = r'^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$') -> bool:
    '''
    Validate if a given string is a correctly formatted IPv4 address.
    
    :param ip_addr: The IP address to validate.
    :return bool: True if `ip_addr` is a valid IPv4 address, False otherwise.
    '''
    if (re.match(ipv4_regex, ip_addr)): 
        return True
    else: 
        return False

def get_input() -> list:
    '''
    Prompt the user to enter a series of IP addresses separated by spaces, validate each IP, and return the list of valid IPs.
    
    :return list: A list of valid IP addresses, or None if no valid IPs are entered.
    '''
    input_ip = input(f'[{Colors.OKBLUE}+{Colors.ENDC}] - Enter some IP addresses here: ')
    input_ip = input_ip.split()
    ip_list = [ip for ip in input_ip if validate_ipv4(ip)]
    return ip_list if ip_list else None

def main() -> None: 
    try: 
        ip_list = get_input()
        if not ip_list: 
            raise ValueError('[!] - No IP addresses were entered.')
        x_apikey = '194ef8939834f124b686293f67c17712dd85accd631bb9bdecaa96bd04ceeaf3'
        ipinfo_token = '78ed3c697b4845'
        ip_check = IPChecker(x_apikey=x_apikey, ipinfo_token=ipinfo_token, ip_list=ip_list)
        data = ip_check.output_template()
    
        rows = [dict(zip(data.keys(), col)) for col in zip(*data.values())]
        print(tabulate(rows, headers="keys", tablefmt="fancy_grid"))
        
    except ValueError as ve: 
        print (ve)
        exit(-1)
        
if __name__ == "__main__":
    main()  
    print (f'\n[{Colors.WARNING}!{Colors.ENDC}] - This tool is intended solely for coding practice and should be used as a reference only.')
    
    