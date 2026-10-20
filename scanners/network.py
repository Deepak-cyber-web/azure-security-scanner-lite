"""Security checks for inbound rules in Azure Network Security Groups."""

from typing import Any, Iterable

from discovery import ResourceDiscovery
from models import Finding
from scanners.storage import value_text

INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "::/0"}
SENSITIVE_PORTS = {"21": "FTP", "23": "Telnet", "1433": "MSSQL", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "9200": "Elasticsearch", "27017": "MongoDB"}


def rule_values(rule: Any, singular: str, plural: str) -> list[str]:
    """Read either Azure's singular or plural rule property."""
    plural_value = getattr(rule, plural, None)
    if plural_value:
        values = plural_value if isinstance(plural_value, (list, tuple)) else [plural_value]
    else:
        value = getattr(rule, singular, None)
        values = [] if value is None else [value]
    return [value_text(item, "") for item in values]


def port_tokens(values: Iterable[str]) -> set[str]:
    """Expand simple ports, ranges, comma lists, and wildcard ports."""
    tokens: set[str] = set()
    for value in values:
        for part in value.replace(" ", "").split(","):
            if part == "*":
                tokens.add("*")
            elif "-" in part:
                start, end = part.split("-", 1)
                try:
                    tokens.update(str(port) for port in range(int(start), int(end) + 1))
                except ValueError:
                    tokens.add(part)
            elif part:
                tokens.add(part)
    return tokens


class NetworkSecurityScanner:
    """Find internet-wide inbound ALLOW exposure in custom NSG rules."""

    def __init__(self, resources: Iterable[Any]) -> None:
        self.resources = resources

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for nsg in self.resources:
            name = getattr(nsg, "name", "unknown")
            group = ResourceDiscovery.resource_group(nsg)
            properties = getattr(nsg, "properties", nsg)
            rules = getattr(properties, "security_rules", []) or []
            for rule in rules:
                direction = value_text(getattr(rule, "direction", ""), "").upper()
                access = value_text(getattr(rule, "access", ""), "").upper()
                if direction != "INBOUND" or access != "ALLOW":
                    continue
                sources = rule_values(rule, "source_address_prefix", "source_address_prefixes")
                if not any(source.lower() in INTERNET_SOURCES for source in sources):
                    continue
                ports = port_tokens(rule_values(rule, "destination_port_range", "destination_port_ranges"))
                protocol = value_text(getattr(rule, "protocol", "*"), "*")
                rule_name = getattr(rule, "name", "unnamed")
                priority = getattr(rule, "priority", "unknown")
                source_text = ", ".join(sources) or "unknown"
                port_text = ", ".join(sorted(ports)) or "unknown"
                common = f"NSG {name}, rule {rule_name}, priority {priority}; protocol {protocol}, source {source_text}, destination port {port_text}."
                if "*" in ports:
                    findings.append(Finding(
                        "NSG-004", "Network Security Group", name, group, "CRITICAL",
                        "NSG permits unrestricted inbound Internet traffic", common, f"{source_text} -> *", "Restrict inbound Internet traffic to required ports and trusted sources.", "FAIL"))
                for port, service in {"22": "SSH", "3389": "RDP"}.items():
                    if port in ports:
                        check_id = "NSG-001" if port == "22" else "NSG-002"
                        title = f"{service} exposed to the Internet"
                        recommendation = "Restrict SSH to trusted source addresses, VPN connectivity, or Azure Bastion." if port == "22" else "Restrict RDP access to approved administration networks or use Azure Bastion."
                        findings.append(Finding(check_id, "Network Security Group", name, group, "CRITICAL", title, common, port_text, "Trusted administration network", recommendation, "FAIL"))
                for port, service in SENSITIVE_PORTS.items():
                    if port in ports:
                        findings.append(Finding("NSG-003", "Network Security Group", name, group, "HIGH", f"{service} exposed to the Internet", common, port_text, "Trusted source addresses", f"Restrict Internet access to {service} or place it behind approved network controls.", "FAIL"))
        return findings
