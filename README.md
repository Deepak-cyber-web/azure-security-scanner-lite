# Azure Security Scanner Lite

## Project Overview

Azure Security Scanner Lite is a small, read-only Azure Cloud Security Posture Assessment tool for a college industrial-training project. It discovers and checks:

- Azure Storage Accounts
- Azure Key Vaults
- Azure Network Security Groups

It reports common configuration issues, calculates a simple project-specific score, and creates JSON and HTML reports. It never retrieves secrets or keys, changes resources, remediates findings, or attempts exploitation.

## Requirements

- Python 3.11+
- Azure CLI
- An Azure subscription
- Reader permission at subscription or resource-group scope

## Setup

```text
python -m venv .venv
```

Windows:

```text
.venv\Scripts\activate
```

Linux/macOS:

```text
source .venv/bin/activate
```

Install dependencies:

```text
pip install -r requirements.txt
```

Authenticate with Azure CLI:

```text
az login
```

The application uses `AzureCliCredential`; it does not require client secrets.

## Run

Scan the active subscription:

```text
python main.py
```

Scan one resource group:

```text
python main.py --resource-group rg-security-demo
```

Select a subscription explicitly:

```text
python main.py --subscription-id <subscription-id>
```

The terminal shows discovered resource counts, severity-tagged findings, and the score. Reports are written to `output/findings.json` and `output/report.html`.

## Checks

Storage checks cover blob public access, minimum TLS, HTTPS-only traffic, and an informational public-network-access review. Key Vault checks cover public network access and purge protection. NSG checks inspect custom inbound Allow rules for Internet-wide SSH, RDP, sensitive service ports, and unrestricted any-port access. Outbound and Deny rules are ignored by design.

## Scoring

The score starts at 100 and subtracts 15 for each failed Critical finding, 10 for High, 5 for Medium, and 2 for Low. Informational findings do not reduce the score. This is a simple project-specific method and is not Microsoft's official Secure Score.

## Demo

For a demonstration resource group such as `rg-security-demo`, intentionally misconfigured settings can show legacy TLS, public blob access, Key Vault public access or missing purge protection, and open NSG administration ports. Review findings carefully before changing any lab resources.
