import os, requests, sys, random, socket, struct
from ipaddress import ip_address, IPv4Address
from pydo import Client
from typing import Literal, TypeAlias

# 0: quiet, 1: error, 2: warning, 3: info
_VERBOSITY_LEVEL: TypeAlias = Literal[0, 1, 2, 3]

# If true, mock DigitalOcean and IPify requests
_MOCK: bool = False

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


class Faker:
    @staticmethod
    def ipv4() -> str:
        return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    
    @staticmethod
    def ipv6() -> str:
        return socket.inet_ntop(socket.AF_INET6, struct.pack('>QQ', random.randint(1, 0xffffffffffffffff), random.randint(1, 0xffffffffffffffff)))


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
    IPV4_URL = "https://api.ipify.org?format=json"
    IPV6_URL = "https://api64.ipify.org?format=json"

    def retrieve(self, type: _IPType) -> str | None:
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


class Mock:
    def __init__(self):
        self.current_ipv4 = Faker.ipv4()
        self.current_ipv6 = Faker.ipv6()

    def make(self, cls):
        if cls == Client:
            return self.DigitalOceanClient(self)
        elif cls == Ipify:
            return self.IpifyAPI(self)
        else:
            raise ValueError(f"Mocking for {cls} is not supported.")

    class DigitalOceanClient(Client):
        def __init__(self, mock: 'Mock'):
            self.domains = self.Domains(mock)
            self.mock = mock

        class Domains:
            def __init__(self, mock: 'Mock'):
                self.mock = mock

            def list_records(self, domain_name: str):
                return {
                    "domain_records": [
                        {"id": 1, "name": IPV4_SUBDOMAIN, "type": "A", "data": self.mock.current_ipv4, "ttl": 60},
                        {"id": 2, "name": IPV6_SUBDOMAIN, "type": "AAAA", "data": self.mock.current_ipv6, "ttl": 60},
                        {"id": 3, "name": COMBINED_SUBDOMAIN, "type": "A", "data": self.mock.current_ipv4, "ttl": 60},
                    ]
                }
            
            def create_record(self, domain_name: str, body: dict):
                pass

            def update_record(self, domain_name: str, domain_record_id: str, body: dict):
                pass

            def delete_record(self, domain_name: str, domain_record_id: str):
                pass

    class IpifyAPI(Ipify):
        def __init__(self, mock: 'Mock'):
            self.mock = mock

        def retrieve(self, type: _IPType) -> str | None:
            return self.mock.current_ipv4 if type == "IPv4" else self.mock.current_ipv6


def main():
    # Initialize mock object if mocking is enabled
    mock = Mock() if _MOCK else None

    # Retrieve IPv4 and IPv6 addresses
    ipify = Ipify() if not _MOCK else mock.make(Ipify)
    ipv4 = ipify.retrieve("IPv4")
    ipv6 = ipify.retrieve("IPv6")

    info("Current IPv4: " + str(ipv4))
    info("Current IPv6: " + str(ipv6))
    info("Domain: " + DOMAIN_NAME)

    # Retrieve DigitalOcean records
    client = Client(token=DIGITALOCEAN_TOKEN, timeout=30) if not _MOCK else mock.make(Client)
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
        stored = [record for record in stored_records if (record.name == expected.name and record.type == expected.type)]
        if len(stored) == 0:
            expected.create(client, DOMAIN_NAME)
            info(f"Created: {expected}")
        else:
            for record in stored:
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
        elif arg == "--mock":
            _MOCK = True

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
