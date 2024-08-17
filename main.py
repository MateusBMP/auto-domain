import os
import requests
from ipaddress import ip_address, IPv4Address
from pydo import Client

DOMAIN_NAME = os.environ.get('DOMAIN_NAME', None)
IPV4_SUBDOMAIN = os.environ.get('IPV4_SUBDOMAIN', None)
IPV6_SUBDOMAIN = os.environ.get('IPV6_SUBDOMAIN', None)
COMBINED_SUBDOMAIN = os.environ.get('COMBINED_SUBDOMAIN', None)
DIGITALOCEAN_TOKEN = os.environ.get('DIGITALOCEAN_TOKEN', None)

def validIPAddress(ip: str) -> str:
    try:
        return "IPv4" if type(ip_address(ip)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"
    
def update_record(do_client: Client, record_id: str | None, record_data: str | None, subdomain: str, ip: str | None, type: str = 'A', ttl: int = 60):
    req = {
        "type": type,
        "name": subdomain,
        "data": ip,
        "ttl": ttl,
    }
    if ip is not None and record_id is None:
        do_client.domains.create_record(domain_name=DOMAIN_NAME, body=req)
        print("Created A " + subdomain + "." + DOMAIN_NAME + " " + ip)
    elif ip and record_id is not None and record_data != ip:
        do_client.domains.update_record(domain_name=DOMAIN_NAME, domain_record_id=record_id, body=req)
        print("Updated A " + subdomain + "." + DOMAIN_NAME + " " + ip)
    elif ip is None and record_id is not None:
        do_client.domains.delete_record(domain_name=DOMAIN_NAME, domain_record_id=record_id)
        print("Deleted A " + subdomain + "." + DOMAIN_NAME + " " + record_data)

def main(set_ipv4: bool, set_ipv6: bool, set_combined: bool):
    # Retrieve IPv4 address
    r1 = requests.get("https://api.ipify.org?format=json")

    if r1.status_code != 200:
        print("Error retrieving IP address.")
        return

    ipv4 = r1.json()["ip"]

    if validIPAddress(ipv4) != "IPv4":
        ipv4 = None

    # Retrieve IPv6 address
    r2 = requests.get("https://api64.ipify.org?format=json")

    if r2.status_code != 200:
        print("Error retrieving IPv6 address.")
        return

    ipv6 = r2.json()["ip"]

    if validIPAddress(ipv6) != "IPv6":
        ipv6 = None

    print("IPv4: " + str(ipv4))
    print("IPv6: " + str(ipv6))

    # Retrieve DigitalOcean records
    client = Client(token=DIGITALOCEAN_TOKEN)
    resp = client.domains.list_records(domain_name=DOMAIN_NAME)

    records = resp["domain_records"]
    record_id_ipv4 = None
    record_data_ipv4 = None
    record_id_ipv6 = None
    record_data_ipv6 = None
    # Find the record with the matching name
    for record in records:
        if record["name"] == IPV4_SUBDOMAIN and record["type"] == "A":
            record_id_ipv4 = record["id"]
            record_data_ipv4 = record["data"]
        elif record["name"] == IPV6_SUBDOMAIN and record["type"] == "AAAA":
            record_id_ipv6 = record["id"]
            record_data_ipv6 = record["data"]

    print("Record ID IPv4: " + str(record_id_ipv4))
    print("Record Data IPv4: " + str(record_data_ipv4))
    print("Record ID IPv6: " + str(record_id_ipv6))
    print("Record Data IPv6: " + str(record_data_ipv6))

    # Update DigitalOcean records
    if set_ipv4:
        update_record(do_client = client,
                      record_id = record_id_ipv4,
                      record_data = record_data_ipv4,
                      subdomain = IPV4_SUBDOMAIN,
                      ip = ipv4,
                      type='A',
                      ttl=60)

    if set_ipv6:
        update_record(do_client = client,
                      record_id = record_id_ipv6,
                      record_data = record_data_ipv6,
                      subdomain = IPV6_SUBDOMAIN,
                      ip = ipv6,
                      type='AAAA',
                      ttl=60)

    if set_combined:
        update_record(do_client = client,
                      record_id = record_id_ipv4,
                      record_data = record_data_ipv4,
                      subdomain = COMBINED_SUBDOMAIN,
                      ip = ipv4,
                      type='A',
                      ttl=60)

        update_record(do_client = client,
                      record_id = record_id_ipv6,
                      record_data = record_data_ipv6,
                      subdomain = COMBINED_SUBDOMAIN,
                      ip = ipv6,
                      type='AAAA',
                      ttl=60)


if __name__ == "__main__":
    if DOMAIN_NAME is None:
        print("DOMAIN_NAME is not set.")
        exit(1)

    if DIGITALOCEAN_TOKEN is None:
        print("DIGITALOCEAN_TOKEN is not set.")
        exit(1)

    main(set_ipv4 = True if IPV4_SUBDOMAIN is not None else False, 
         set_ipv6 = True if IPV6_SUBDOMAIN is not None else False,
         combined_subdomain = True if COMBINED_SUBDOMAIN is not None else False)
