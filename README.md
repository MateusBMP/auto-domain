# Public IP Address Checker and Digital Ocean DNS Updater

## Overview

This Python script is designed to check the current public IPv4 and IPv6 addresses of a system and compare them with Digital Ocean DNS records. If any discrepancies are found, the script will automatically update the DNS records to reflect the current public IP addresses. This can be useful for maintaining accurate DNS records for services hosted on dynamic IP addresses.

## Prerequisites

Before using this script, make sure you have the following prerequisites installed:

- Python 3.10
- Pipenv (Python package manager and virtual environment tool)

You will also need a Digital Ocean API token for authentication.

## Installation

1. Clone the repository or download the script:

```bash
git clone https://github.com/yourusername/public-ip-dns-updater.git
```

2. Change into the project directory:

```bash
cd auto-domain
```

3. Create a virtual environment and install the required Python packages using Pipenv:

```bash
pipenv install
```

4. Copy the provided `.env.example` file and create a new `.env` file:

```bash
cp .env.example .env
```

5. Edit the `.env` file to include your specific configuration:

```dotenv
DIGITALOCEAN_API_TOKEN=your_digital_ocean_api_token_here
DOMAIN=example.com
SUBDOMAIN=subdomain  # @ for root domain
```

## Usage

Run the script `main.py` using Pipenv:

```bash
pipenv run python main.py
```

The `main.py` script will perform the following steps:

1. Fetch the current public IPv4 and IPv6 addresses of your system.
2. Query Digital Ocean's API to retrieve the existing DNS records for the specified domain/subdomain.
3. Compare the current public IP addresses with the existing DNS records.
4. If there is a mismatch, update the DNS records with the current IP addresses using Digital Ocean's API.

You can schedule the `main.py` script to run periodically (e.g., using a cron job) to ensure your DNS records are always up to date.

## Contributions

Contributions to this project are welcome. If you encounter any issues or have suggestions for improvements, please create an issue or submit a pull request on the GitHub repository.

## License

This script is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Disclaimer:** Use this script responsibly and ensure you have proper authorization to modify DNS records. Be aware that updating DNS records can affect your online services, so use it with caution.
