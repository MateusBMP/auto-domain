import os, requests, sys
from ipaddress import ip_address, IPv4Address
from pydo import Client
from typing import Literal, TypeAlias

# 0: quiet, 1: error, 2: warning, 3: info
_VERBOSITY_LEVEL: TypeAlias = Literal[0, 1, 2, 3]

DOMAIN_NAME = os.environ.get('DOMAIN_NAME', None)
IPV4_SUBDOMAIN = os.environ.get('IPV4_SUBDOMAIN', None)
IPV6_SUBDOMAIN = os.environ.get('IPV6_SUBDOMAIN', None)
COMBINED_SUBDOMAIN = os.environ.get('COMBINED_SUBDOMAIN', None)
DIGITALOCEAN_TOKEN = os.environ.get('DIGITALOCEAN_TOKEN', None)
VERBOSITY: _VERBOSITY_LEVEL = 1 # Default verbosity level (error)

def error(message: str):
    if VERBOSITY >= 1:
        print("Error: " + message)

def warning(message: str):
    if VERBOSITY >= 2:
        print("Warning: " + message)

def info(message: str):
    if VERBOSITY >= 3:
        print("Info: " + message)

_IPType: TypeAlias = Literal["IPv4", "IPv6"]

def ip_type(ip: str) -> _IPType | None:
    try:
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
    except ValueError:
        return None

_RecordType: TypeAlias = Literal["A", "AAAA"]

class Record(object):
    def __init__(self, name: str, type: _RecordType, data: str | None = None, ttl: int = 60, id: str | None = None):
        self.id: str | None = id
        self.name: str = name
        self.type: _RecordType = type
        self.data: str | None = data
        self.ttl: int = ttl

    def create(self, do_client: Client, domain_name: str):
        if self.data is None:
            raise ValueError("Record data is not set.")
        if ip_type(self.data) is None:
            raise ValueError("Record data is not a valid IP address.")
        if self.type == "A" and ip_type(self.data) != "IPv4":
            raise ValueError("Record data is not a valid IPv4 address.")
        if self.type == "AAAA" and ip_type(self.data) != "IPv6":
            raise ValueError("Record data is not a valid IPv6 address.")
        req = self.__dict__()
        req.pop("id")
        do_client.domains.create_record(domain_name=domain_name, body=req)

    def update(self, do_client: Client, domain_name: str):
        if self.data is None:
            raise ValueError("Record data is not set.")
        if ip_type(self.data) is None:
            raise ValueError("Record data is not a valid IP address.")
        if self.type == "A" and ip_type(self.data) != "IPv4":
            raise ValueError("Record data is not a valid IPv4 address.")
        if self.type == "AAAA" and ip_type(self.data) != "IPv6":
            raise ValueError("Record data is not a valid IPv6 address.")
        req = self.__dict__()
        req.pop("id")
        do_client.domains.update_record(domain_name=domain_name, domain_record_id=self.id, body=req)

    def delete(self, do_client: Client, domain_name: str):
        if self.id is None:
            raise ValueError("Record ID is not set.")
        do_client.domains.delete_record(domain_name=domain_name, domain_record_id=self.id)

    def __dict__(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "data": self.data,
            "ttl": self.ttl,
        }
    
    def __str__(self):
        return (f"({self.id}) " if self.id is not None else "") + f"{self.type} {self.name} {self.data} TTL={self.ttl}"

class Ipify:
    IPV4_URL: str = "https://api.ipify.org?format=json"
    IPV6_URL: str = "https://api64.ipify.org?format=json"

    @staticmethod
    def retrieve(type: _IPType) -> str | None:
        url = Ipify.IPV4_URL if type == "IPv4" else Ipify.IPV6_URL
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            warning(f"Failed to retrieve external {type} address. Received status code: {r.status_code}.")
            return
        ip = r.json()["ip"]
        if ip_type(ip) != type:
            warning(f"External IP address is not a valid {type} address. Received: {ip}. Ignoring this address.")
            return
        return ip

def main():
    # Retrieve IPv4 address
    ipv4 = Ipify.retrieve("IPv4")

    # Retrieve IPv6 address
    ipv6 = Ipify.retrieve("IPv6")

    info("Current IPv4: " + str(ipv4))
    info("Current IPv6: " + str(ipv6))
    info("Domain: " + DOMAIN_NAME)

    # Retrieve DigitalOcean records
    client = Client(token=DIGITALOCEAN_TOKEN, timeout=30)
    resp = client.domains.list_records(domain_name=DOMAIN_NAME)
    stored_records: list[Record] = []
    for record in resp['domain_records']:
        if record["type"] in ['A', 'AAAA']:
            obj = Record(id = str(record["id"]), name = str(record["name"]), type = str(record["type"]), data = record["data"], ttl = int(record["ttl"]))
            stored_records.append(obj)
            info(f"Stored: {obj}")

    # Create the expected records list
    expected_records: list[Record] = []
    if IPV4_SUBDOMAIN is not None:
        obj = Record(name = IPV4_SUBDOMAIN, type = 'A', data = ipv4)
        expected_records.append(obj)
        info(f"Expected: {obj}")
    if IPV6_SUBDOMAIN is not None:
        obj = Record(name = IPV6_SUBDOMAIN, type = 'AAAA', data = ipv6)
        expected_records.append(obj)
        info(f"Expected: {obj}")
    if COMBINED_SUBDOMAIN is not None:
        obj_ipv4 = Record(name = COMBINED_SUBDOMAIN, type = 'A', data = ipv4)
        expected_records.append(obj_ipv4)
        info(f"Expected: {obj_ipv4}")
        obj_ipv6 = Record(name = COMBINED_SUBDOMAIN, type = 'AAAA', data = ipv6)
        expected_records.append(obj_ipv6)
        info(f"Expected: {obj_ipv6}")

    # Update DigitalOcean records
    for expected in expected_records:
        stored = [record for record in stored_records if record.name == expected.name]
        if len(stored) == 0:
            expected.create(client, DOMAIN_NAME)
            info(f"Created: {expected}")
        else:
            for record in stored:
                if record.type == expected.type:
                    if record.data != expected.data:
                        if expected.data is not None:
                            expected.id = record.id
                            expected.update(client, DOMAIN_NAME)
                            info(f"Updated: {expected}")
                        else:
                            record.delete(client, DOMAIN_NAME)
                            info(f"Deleted: {record}")
                    else:
                        info(f"No change: {record}")


if __name__ == "__main__":
    # Calculate verbosity level
    for arg in sys.argv:
        if arg == "-v" or arg == "--warning":
            VERBOSITY = 2
        elif arg == "-vv" or arg == "--info":
            VERBOSITY = 3
        elif arg == "-q" or arg == "--quiet":
            VERBOSITY = 0

    if DOMAIN_NAME is None:
        error("DOMAIN_NAME environment is not set.")
        sys.exit(1)

    if DIGITALOCEAN_TOKEN is None:
        error("DIGITALOCEAN_TOKEN environment is not set.")
        sys.exit(1)

    if IPV4_SUBDOMAIN is None and IPV6_SUBDOMAIN is None and COMBINED_SUBDOMAIN is None:
        error("At least one of IPV4_SUBDOMAIN, IPV6_SUBDOMAIN, or COMBINED_SUBDOMAIN environment must be set.")
        sys.exit(1)

    main()
