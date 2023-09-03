import os
import requests
from ipaddress import ip_address, IPv4Address
from pydo import Client

def validIPAddress(IP: str) -> str:
    try:
        return "IPv4" if type(ip_address(IP)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"

def main():
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
    client = Client(token=os.environ.get("DIGITALOCEAN_TOKEN"))
    resp = client.domains.list_records(domain_name=os.environ.get("DOMAIN_NAME"))

    records = resp["domain_records"]
    record_id_ipv4 = None
    record_data_ipv4 = None
    record_id_ipv6 = None
    record_data_ipv6 = None
    # Find the record with the matching name
    for record in records:
        if record["name"] == os.environ.get("SUBDOMAIN"):
            if record["type"] == "A":
                record_id_ipv4 = record["id"]
                record_data_ipv4 = record["data"]
            elif record["type"] == "AAAA":
                record_id_ipv6 = record["id"]
                record_data_ipv6 = record["data"]

    print("Record ID IPv4: " + str(record_id_ipv4))
    print("Record Data IPv4: " + str(record_data_ipv4))
    print("Record ID IPv6: " + str(record_id_ipv6))
    print("Record Data IPv6: " + str(record_data_ipv6))

    # Update DigitalOcean records
    req_ipv4 = {
        "type": "A",
        "name": os.environ.get("SUBDOMAIN"),
        "data": ipv4,
        "ttl": 60,
    }
    if ipv4 and record_id_ipv4 is None:
        client.domains.create_record(domain_name=os.environ.get("DOMAIN_NAME"), body=req_ipv4)
        print("Created A " + os.environ.get("SUBDOMAIN") + "." + os.environ.get("DOMAIN_NAME") + " " + ipv4)
    elif ipv4 and record_id_ipv4 is not None and record_data_ipv4 != ipv4:
        client.domains.update_record(domain_name=os.environ.get("DOMAIN_NAME"), domain_record_id=record_id_ipv4, body=req_ipv4)
        print("Updated A " + os.environ.get("SUBDOMAIN") + "." + os.environ.get("DOMAIN_NAME") + " " + ipv4)
    elif ipv4 is None and record_id_ipv4 is not None:
        client.domains.delete_record(domain_name=os.environ.get("DOMAIN_NAME"), domain_record_id=record_id_ipv4)
        print("Deleted A " + os.environ.get("SUBDOMAIN") + "." + os.environ.get("DOMAIN_NAME") + " " + record_data_ipv4)

    req_ipv6 = {
        "type": "AAAA",
        "name": os.environ.get("SUBDOMAIN"),
        "data": ipv6,
        "ttl": 60,
    }
    if ipv6 and record_id_ipv6 is None:
        client.domains.create_record(domain_name=os.environ.get("DOMAIN_NAME"), body=req_ipv6)
        print("Created AAAA " + os.environ.get("SUBDOMAIN") + "." + os.environ.get("DOMAIN_NAME") + " " + ipv6)
    elif ipv6 and record_id_ipv6 is not None and record_data_ipv6 != ipv6:
        client.domains.update_record(domain_name=os.environ.get("DOMAIN_NAME"), domain_record_id=record_id_ipv6, body=req_ipv6)
        print("Updated AAAA " + os.environ.get("SUBDOMAIN") + "." + os.environ.get("DOMAIN_NAME") + " " + ipv6)
    elif ipv6 is None and record_id_ipv6 is not None:
        client.domains.delete_record(domain_name=os.environ.get("DOMAIN_NAME"), domain_record_id=record_id_ipv6)
        print("Deleted AAAA " + os.environ.get("SUBDOMAIN") + "." + os.environ.get("DOMAIN_NAME") + " " + record_data_ipv6)

if __name__ == "__main__":
    main()