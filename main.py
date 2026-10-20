"""Command-line entry point for Azure Security Scanner Lite."""

import argparse
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from auth import AzureAuthenticator
from discovery import ResourceDiscovery
from models import Finding
from reporting import ReportGenerator
from scanners.keyvault import KeyVaultSecurityScanner
from scanners.network import NetworkSecurityScanner
from scanners.storage import StorageSecurityScanner
from scoring import SecurityScoringEngine

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Azure security posture assessment")
    parser.add_argument("--scope", choices=["subscription"], default="subscription", help="Assessment scope (default: subscription)")
    parser.add_argument("--resource-group", help="Limit the assessment to one resource group")
    parser.add_argument("--subscription-id", help="Use a specific subscription ID")
    return parser.parse_args()


def run_scanner(label: str, scanner: Callable[[], list[Finding]]) -> list[Finding]:
    try:
        return scanner()
    except Exception as exc:
        console.print(f"[red]Could not scan {label}: {exc}[/red]")
        return []


def main() -> int:
    args = parse_args()
    console.print(Panel("AZURE SECURITY SCANNER LITE", style="bold blue"))
    console.print("[yellow][+] Authenticating...[/yellow]")
    try:
        authenticator = AzureAuthenticator(args.subscription_id)
        credential = authenticator.get_credential()
        subscription_id, subscription_name = authenticator.get_subscription()
    except RuntimeError as exc:
        console.print(f"[red][!] {exc}[/red]")
        return 1
    console.print("[green][+] Authentication successful[/green]")
    console.print(f"Subscription: [bold]{subscription_name}[/bold]")

    try:
        console.print("\n[cyan]Discovering resources...[/cyan]")
        resources = ResourceDiscovery(credential, subscription_id).discover(args.resource_group)
    except RuntimeError as exc:
        console.print(f"[red][!] {exc}[/red]")
        return 1
    table = Table(title="Resources Discovered")
    table.add_column("Resource Type")
    table.add_column("Count", justify="right")
    for label, key in (("Storage Accounts", "storage"), ("Key Vaults", "keyvault"), ("NSGs", "network")):
        table.add_row(label, str(len(resources[key])))
    console.print(table)

    console.print("\n[cyan]Running assessment...[/cyan]")
    findings: list[Finding] = []
    findings.extend(run_scanner("Storage", lambda: StorageSecurityScanner(resources["storage"]).scan()))
    findings.extend(run_scanner("Key Vault", lambda: KeyVaultSecurityScanner(resources["keyvault"]).scan()))
    findings.extend(run_scanner("Network", lambda: NetworkSecurityScanner(resources["network"]).scan()))
    for finding in findings:
        color = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue"}.get(finding.severity, "white")
        console.print(f"[{color}][{finding.severity}] {finding.check_id}  {finding.title}[/{color}]")

    score = SecurityScoringEngine().calculate(findings)
    console.print(Panel(f"Security Score: {score['score']} / 100\nRisk Level: {score['risk_level']}", title="Assessment Result", style="bold green"))
    console.print(f"Critical: {score['critical']}   High: {score['high']}   Medium: {score['medium']}   Low: {score['low']}")
    reporter = ReportGenerator()
    try:
        json_path = reporter.write_json(subscription_id, subscription_name, args.resource_group, findings, score, sum(len(items) for items in resources.values()))
        assessment = {"subscription_id": subscription_id, "subscription_name": subscription_name, "resource_group": args.resource_group or "subscription", "security_score": score["score"], "risk_level": score["risk_level"]}
        summary = {"resources_scanned": sum(len(items) for items in resources.values()), **score}
        html_path = reporter.write_html(assessment, summary, findings)
        console.print(f"[green]HTML report generated: {html_path}[/green]")
        console.print(f"[green]JSON report generated: {json_path}[/green]")
    except Exception as exc:
        console.print(f"[red][!] Report generation failed: {exc}[/red]")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
