"""
air-trust CLI - Verify, inspect, and export audit chains.

Usage:
    python3 -m air_trust verify              # Verify the default chain
    python3 -m air_trust verify --db path    # Verify a specific database
    python3 -m air_trust stats               # Show chain statistics
    python3 -m air_trust export              # Export chain as JSON
    python3 -m air_trust export --format csv # Export as CSV
    python3 -m air_trust badge               # Print compliance badge markdown
    python3 -m air_trust register            # Register project for tracking (opt-in)
    python3 -m air_trust atf                 # CSA Agentic Trust Framework conformance
"""

import argparse
import json
import csv
import sys
import os
import time
import subprocess
from pathlib import Path
from typing import Optional
import sqlite3

from air_trust.chain import AuditChain
from air_trust.events import AgentIdentity
from air_trust import atf as atf_module


# ANSI color codes
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def print_header(title: str):
    """Print a styled header."""
    print(f"\n{YELLOW}{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}{RESET}\n")


def cmd_verify(args):
    """Verify the integrity and completeness of the audit chain."""
    db_path = args.db
    if not db_path:
        db_path = str(Path.home() / ".air-trust" / "events.db")

    if not Path(db_path).exists():
        if args.json_output:
            print(json.dumps({"error": f"Database not found at {db_path}"}))
        else:
            print_header("AIR Trust - Chain Verification")
            print(f"{RED}✗ FAIL{RESET}: Database not found at {db_path}")
        return 1

    try:
        chain = AuditChain(db_path=db_path, signing_key=args.key)
        result = chain.verify()

        # JSON output mode for CI/CD
        if args.json_output:
            output = {
                "integrity": result["integrity"],
                "completeness": result["completeness"],
            }
            if "handoffs" in result:
                output["handoffs"] = result["handoffs"]
            print(json.dumps(output, indent=2))
            if not result["integrity"]["valid"]:
                return 1
            # Check for handoff signature failures (FAIL severity)
            handoff_fails = [i for i in result.get("handoffs", {}).get("issues", [])
                             if i.get("severity") == "fail"]
            if handoff_fails:
                return 1
            if result["completeness"]["sessions_incomplete"] > 0:
                return 2  # warn exit code
            return 0

        # Human-readable output
        print_header("AIR Trust - Chain Verification (v1.2)")

        integrity = result["integrity"]
        completeness = result["completeness"]

        print(f"Database: {db_path}")
        print(f"Records:  {integrity['records']}")
        print()

        # ── Integrity ──
        if integrity["valid"]:
            print(f"{GREEN}✓ PASS{RESET}: Integrity - chain is intact (HMAC-SHA256)")
        else:
            print(f"{RED}✗ FAIL{RESET}: Integrity - chain is broken")
            if integrity["broken_at"] is not None:
                print(f"  Tampered at record index: {integrity['broken_at']}")
            return 1

        # ── Completeness ──
        if completeness["sessions_checked"] == 0:
            print(f"  INFO: No sessions found (v1.0 records only, completeness not checked)")
            return 0

        print(f"\n  Sessions checked:    {completeness['sessions_checked']}")
        print(f"  Sessions complete:   {completeness['sessions_complete']}")
        print(f"  Sessions incomplete: {completeness['sessions_incomplete']}")

        if completeness["sessions_incomplete"] == 0:
            print(f"\n{GREEN}✓ PASS{RESET}: Completeness - all sessions are complete")
        else:
            print(f"\n{YELLOW}⚠ WARN{RESET}: Completeness - issues detected:")
            for issue in completeness["issues"]:
                sid_short = issue["session_id"][:12] + "..."
                itype = issue["issue"]
                if itype == "gap":
                    print(f"  Session {sid_short}: gap at seq {issue.get('expected_seq')} (got {issue.get('actual_seq')})")
                elif itype == "duplicate":
                    print(f"  Session {sid_short}: duplicate seq {issue.get('session_seq')}")
                elif itype == "rewind":
                    print(f"  Session {sid_short}: rewind at seq {issue.get('expected_seq')} (got {issue.get('actual_seq')})")
                elif itype == "missing_session_end":
                    print(f"  Session {sid_short}: missing session_end (last seq: {issue.get('last_seq')})")
                elif itype == "missing_session_start":
                    print(f"  Session {sid_short}: missing session_start")

        # ── Handoffs (v1.2) ──
        handoffs = result.get("handoffs", {})
        if handoffs.get("interactions_checked", 0) > 0:
            print(f"\n  Handoffs checked:    {handoffs['interactions_checked']}")
            print(f"  Handoffs complete:   {handoffs['interactions_complete']}")
            print(f"  Handoffs incomplete: {handoffs['interactions_incomplete']}")

            # Check for FAIL-severity issues (signature failures)
            fail_issues = [i for i in handoffs.get("issues", []) if i.get("severity") == "fail"]
            warn_issues = [i for i in handoffs.get("issues", []) if i.get("severity") == "warn"]
            info_issues = [i for i in handoffs.get("issues", []) if i.get("severity") == "info"]

            if fail_issues:
                print(f"\n{RED}✗ FAIL{RESET}: Handoffs - signature verification failed:")
                for issue in fail_issues:
                    iid_short = issue.get("interaction_id", "?")[:12] + "..."
                    print(f"  Handoff {iid_short}: {issue['issue']} ({issue.get('record_type', '')})")
                return 1

            if warn_issues:
                print(f"\n{YELLOW}⚠ WARN{RESET}: Handoffs - issues detected:")
                for issue in warn_issues:
                    iid_short = issue.get("interaction_id", "?")[:12] + "..."
                    itype = issue["issue"]
                    if itype == "missing_ack":
                        print(f"  Handoff {iid_short}: request sent but never acknowledged")
                    elif itype == "payload_mismatch":
                        print(f"  Handoff {iid_short}: payload hash mismatch (request vs ack)")
                    elif itype == "counterparty_mismatch":
                        print(f"  Handoff {iid_short}: wrong agent acknowledged")
                    elif itype == "duplicate_nonce":
                        print(f"  Handoff {iid_short}: duplicate nonce (possible replay)")
                    elif itype == "orphaned_response":
                        print(f"  Handoff {iid_short}: ack/result without matching request")
                    else:
                        print(f"  Handoff {iid_short}: {itype}")

            if info_issues:
                for issue in info_issues:
                    iid_short = issue.get("interaction_id", "?")[:12] + "..."
                    if issue["issue"] == "missing_result":
                        print(f"  {YELLOW}INFO{RESET}: Handoff {iid_short}: acknowledged but no result yet")

            if not fail_issues and not warn_issues:
                print(f"\n{GREEN}✓ PASS{RESET}: Handoffs - all handoffs verified (Ed25519)")
        else:
            print(f"\n  INFO: No handoff records found (v1.2 handoff verification not applicable)")

        return 0

    except Exception as e:
        if args.json_output:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"{RED}✗ ERROR{RESET}: {e}")
        return 1


def cmd_stats(args):
    """Show chain statistics."""
    db_path = args.db
    if not db_path:
        db_path = str(Path.home() / ".air-trust" / "events.db")

    print_header("AIR Trust - Chain Statistics")

    if not Path(db_path).exists():
        print(f"{RED}No chain found at {db_path}{RESET}")
        return 1

    try:
        chain = AuditChain(db_path=db_path)
        result = chain.verify()

        # Query the database for detailed stats
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total events
        total = cursor.execute("SELECT COUNT(*) as cnt FROM events").fetchone()["cnt"]

        # Unique frameworks
        frameworks = cursor.execute(
            "SELECT DISTINCT framework FROM events WHERE framework IS NOT NULL"
        ).fetchall()
        framework_list = [row["framework"] for row in frameworks]

        # Unique agents
        agents = cursor.execute(
            "SELECT DISTINCT agent FROM events WHERE agent IS NOT NULL"
        ).fetchall()
        agent_list = [row["agent"] for row in agents]

        # Unique owners (from identity)
        owners = cursor.execute(
            "SELECT DISTINCT owner FROM events WHERE owner IS NOT NULL"
        ).fetchall()
        owner_list = [row["owner"] for row in owners]

        # Date range
        dates = cursor.execute(
            "SELECT MIN(timestamp) as first, MAX(timestamp) as last FROM events"
        ).fetchone()
        first_date = dates["first"] if dates["first"] else "N/A"
        last_date = dates["last"] if dates["last"] else "N/A"

        conn.close()

        # Print stats
        print(f"Total Events: {total}")
        print(f"Unique Frameworks: {len(framework_list)}")
        if framework_list:
            print(f"  {', '.join(framework_list)}")
        print(f"Unique Agents: {len(agent_list)}")
        if agent_list:
            print(f"  {', '.join(agent_list)}")
        print(f"Unique Owners: {len(owner_list)}")
        if owner_list:
            print(f"  {', '.join(owner_list)}")
        print()
        print(f"Date Range:")
        print(f"  First: {first_date}")
        print(f"  Last: {last_date}")
        print()
        is_valid = result["integrity"]["valid"]
        print(f"Chain Validity: {GREEN if is_valid else RED}{'VALID' if is_valid else 'BROKEN'}{RESET}")
        if result["completeness"]["sessions_checked"] > 0:
            c = result["completeness"]
            print(f"Sessions: {c['sessions_complete']}/{c['sessions_checked']} complete")

        return 0

    except Exception as e:
        print(f"{RED}ERROR: {e}{RESET}")
        return 1


def cmd_export(args):
    """Export the chain as JSON or CSV."""
    db_path = args.db
    if not db_path:
        db_path = str(Path.home() / ".air-trust" / "events.db")

    export_format = args.format.lower()

    if not Path(db_path).exists():
        print(f"{RED}Error: Database not found at {db_path}{RESET}", file=sys.stderr)
        return 1

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        rows = cursor.execute(
            "SELECT * FROM events ORDER BY id ASC"
        ).fetchall()

        records = []
        for row in rows:
            record = dict(row)
            # Parse JSON data back
            if record["data"]:
                try:
                    record["data"] = json.loads(record["data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            records.append(record)

        conn.close()

        if export_format == "json":
            # Export as JSON
            output = json.dumps(records, indent=2, default=str)
            print(output)
        elif export_format == "csv":
            # Export as CSV
            if not records:
                print("")
                return 0

            # Flatten records for CSV
            fieldnames = set()
            for record in records:
                fieldnames.update(record.keys())
                if isinstance(record.get("data"), dict):
                    fieldnames.update(f"data.{k}" for k in record["data"].keys())

            fieldnames = sorted(fieldnames)

            writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
            writer.writeheader()

            for record in records:
                row = {}
                for key in fieldnames:
                    if key.startswith("data."):
                        sub_key = key[5:]
                        if isinstance(record.get("data"), dict):
                            row[key] = record["data"].get(sub_key, "")
                    else:
                        val = record.get(key, "")
                        if isinstance(val, (dict, list)):
                            row[key] = json.dumps(val)
                        else:
                            row[key] = val
                writer.writerow(row)
        else:
            print(f"{RED}Error: Unknown format '{export_format}'. Use 'json' or 'csv'.{RESET}", file=sys.stderr)
            return 1

        return 0

    except Exception as e:
        print(f"{RED}Error: {e}{RESET}", file=sys.stderr)
        return 1


def _score_to_color(score: float) -> str:
    """Convert compliance score to shields.io color."""
    if score >= 90:
        return "brightgreen"
    elif score >= 70:
        return "yellow"
    elif score >= 50:
        return "orange"
    else:
        return "red"


def _generate_badge_url(
    label: str, message: str, color: str, style: str = "for-the-badge"
) -> str:
    """Generate a shields.io badge URL."""
    # URL encode the label and message
    safe_label = label.replace(" ", "_")
    safe_message = message.replace(" ", "_").replace("%", "%25")
    return f"https://img.shields.io/badge/{safe_label}-{safe_message}-{color}?style={style}"


def cmd_badge(args):
    """Generate compliance and audit chain badges."""
    badge_format = args.format.lower()
    badge_style = args.style.lower()

    # Try to get compliance score from air-compliance
    compliance_score = None
    try:
        result = subprocess.run(
            ["air-compliance", ".", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                if isinstance(data, dict) and "score" in data:
                    compliance_score = data["score"]
            except (json.JSONDecodeError, ValueError):
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check audit chain validity
    db_path = str(Path.home() / ".air-trust" / "events.db")
    chain_valid = False
    try:
        if Path(db_path).exists():
            chain = AuditChain(db_path=db_path)
            result = chain.verify()
            chain_valid = result.get("integrity", {}).get("valid", False)
    except Exception:
        pass

    badges = []

    # Compliance Score Badge
    if compliance_score is not None:
        score_int = int(compliance_score)
        color = _score_to_color(compliance_score)
        url = _generate_badge_url(
            "EU_AI_Act", f"{score_int}%_compliant", color, badge_style
        )
        alt_text = "EU AI Act"
        if badge_format == "html":
            badges.append(f'<img src="{url}" alt="{alt_text}" />')
        else:
            badges.append(f"![{alt_text}]({url})")

    # Audit Chain Badge
    chain_color = "brightgreen" if chain_valid else "red"
    chain_message = "verified" if chain_valid else "not_verified"
    chain_url = _generate_badge_url(
        "Audit_Chain", chain_message, chain_color, badge_style
    )
    chain_alt = "Audit Chain"
    if badge_format == "html":
        badges.append(f'<img src="{chain_url}" alt="{chain_alt}" />')
    else:
        badges.append(f"![{chain_alt}]({chain_url})")

    # Print badges
    for badge in badges:
        print(badge)

    return 0


def cmd_register(args):
    """Register this project for usage tracking (opt-in only)."""
    reg_path = os.path.expanduser("~/.air-trust/registration.json")

    print("\033[33m" + "=" * 50)
    print("  AIR Trust - Project Registration")
    print("=" * 50 + "\033[0m")
    print()
    print("Registration is optional and helps us understand")
    print("who's using air-trust in production.")
    print("No data is sent anywhere - stored locally only.")
    print()

    project = input("Project name: ").strip()
    email = input("Email (optional): ").strip()
    org = input("Organization (optional): ").strip()
    use_case = input("Use case [compliance/audit/security/other]: ").strip()

    if not project:
        print("\n\033[31mProject name is required.\033[0m")
        sys.exit(1)

    reg_data = {
        "project": project,
        "email": email or None,
        "org": org or None,
        "use_case": use_case or None,
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "air_trust_version": "0.6.1",
    }

    os.makedirs(os.path.dirname(reg_path), exist_ok=True)
    with open(reg_path, "w") as f:
        json.dump(reg_data, f, indent=2)

    print(f"\n\033[32m✓ Registered: {project}\033[0m")
    print(f"  Saved to: {reg_path}")
    print(f"\n  To update: python3 -m air_trust register")
    print(f"  To remove: rm {reg_path}")

    return 0


def cmd_atf(args):
    """Check CSA Agentic Trust Framework (ATF) conformance for an agent identity."""
    # Build identity from CLI args or load from config file
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"{RED}Error: Config file not found: {args.config}{RESET}", file=sys.stderr)
            return 1
        try:
            with open(config_path) as f:
                data = json.load(f)
        except Exception as e:
            print(f"{RED}Error reading config: {e}{RESET}", file=sys.stderr)
            return 1

        identity = AgentIdentity(
            agent_name=data.get("agent_name", ""),
            owner=data.get("owner", ""),
            agent_version=data.get("agent_version", "0.0.0"),
            org=data.get("org", ""),
            purpose=data.get("purpose", ""),
            capabilities=data.get("capabilities", []) or [],
            permissions=data.get("permissions", []) or [],
            description=data.get("description", ""),
            external_id=data.get("external_id", ""),
            atf_level=data.get("atf_level", "intern"),
            urn=data.get("urn", ""),
        )
    else:
        if not args.name or not args.owner:
            print(
                f"{RED}Error: --name and --owner are required (or use --config).{RESET}",
                file=sys.stderr,
            )
            print(
                "\nExample:\n"
                "  python3 -m air_trust atf --name my-agent --owner jason@example.com \\\n"
                "      --purpose 'Summarize tickets' --capabilities read:tickets,generate:summary",
                file=sys.stderr,
            )
            return 1

        capabilities = []
        if args.capabilities:
            capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]

        permissions = []
        if args.permissions:
            permissions = [p.strip() for p in args.permissions.split(",") if p.strip()]

        identity = AgentIdentity(
            agent_name=args.name,
            owner=args.owner,
            agent_version=args.version or "0.0.0",
            org=args.org or "",
            purpose=args.purpose or "",
            capabilities=capabilities,
            permissions=permissions,
            external_id=args.external_id or "",
            atf_level=args.level,
        )

    # Output
    if args.format == "json":
        result = atf_module.conformance_dict(identity)
        print(json.dumps(result, indent=2))
    else:
        print(atf_module.conformance_statement(identity))

    # Exit code: 0 if identity meets its target level, 1 otherwise
    if atf_module.level_compliant(identity, identity.atf_level):
        return 0
    return 1


def cmd_agent_identity(args):
    """Verify agent identity continuity across the audit chain."""
    from air_trust.agent_identity import verify_identity, format_report

    db_path = args.db
    if not db_path:
        db_path = str(Path.home() / ".air-trust" / "events.db")

    if not Path(db_path).exists():
        if args.json_output:
            print(json.dumps({"error": f"Database not found at {db_path}"}))
        else:
            print(f"{RED}No chain database found at {db_path}{RESET}")
        return 1

    report = verify_identity(
        db_path=db_path,
        agent_name=args.agent,
        max_gap_seconds=args.max_gap,
    )

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(format_report(report))

    if report.verdict == "fail":
        return 1
    if report.verdict == "warn":
        return 2
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="air-trust",
        description="AIR Trust - Verify, inspect, and export audit chains",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify chain integrity and completeness")
    verify_parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to events database (default: ~/.air-trust/events.db)",
    )
    verify_parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Output as JSON (for CI/CD pipelines)",
    )
    verify_parser.add_argument(
        "--key",
        type=str,
        default=None,
        help="Signing key (default: from AIR_TRUST_KEY env or ~/.air-trust/signing.key)",
    )
    verify_parser.set_defaults(func=cmd_verify)

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show chain statistics")
    stats_parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to events database (default: ~/.air-trust/events.db)",
    )
    stats_parser.set_defaults(func=cmd_stats)

    # export command
    export_parser = subparsers.add_parser("export", help="Export chain data")
    export_parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv"],
        default="json",
        help="Export format (default: json)",
    )
    export_parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to events database (default: ~/.air-trust/events.db)",
    )
    export_parser.set_defaults(func=cmd_export)

    # badge command
    badge_parser = subparsers.add_parser(
        "badge", help="Generate compliance and audit chain badges"
    )
    badge_parser.add_argument(
        "--format",
        type=str,
        choices=["markdown", "html"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    badge_parser.add_argument(
        "--style",
        type=str,
        choices=["flat", "flat-square", "plastic", "for-the-badge"],
        default="for-the-badge",
        help="Badge style from shields.io (default: for-the-badge)",
    )
    badge_parser.set_defaults(func=cmd_badge)

    # register command
    register_parser = subparsers.add_parser(
        "register", help="Register project for tracking (opt-in only)"
    )
    register_parser.set_defaults(func=cmd_register)

    # atf command - CSA Agentic Trust Framework conformance
    atf_parser = subparsers.add_parser(
        "atf",
        help="Check CSA Agentic Trust Framework (ATF) conformance for an agent identity",
    )
    atf_parser.add_argument(
        "--name", type=str, default=None, help="Agent name (required unless --config)"
    )
    atf_parser.add_argument(
        "--owner",
        type=str,
        default=None,
        help="Owner (email or identifier) - required unless --config",
    )
    atf_parser.add_argument(
        "--version", type=str, default=None, help="Agent version (default: 0.0.0)"
    )
    atf_parser.add_argument(
        "--org", type=str, default=None, help="Organization / team"
    )
    atf_parser.add_argument(
        "--purpose",
        type=str,
        default=None,
        help="I-4 Purpose Declaration: what this agent is for",
    )
    atf_parser.add_argument(
        "--capabilities",
        type=str,
        default=None,
        help="I-5 Capability Manifest: comma-separated list (e.g. 'read:tickets,llm:respond')",
    )
    atf_parser.add_argument(
        "--permissions",
        type=str,
        default=None,
        help="Comma-separated list of allowed actions",
    )
    atf_parser.add_argument(
        "--external-id",
        dest="external_id",
        type=str,
        default=None,
        help="External identity binding (e.g. 'pico@agentlair.dev', 'did:web:...')",
    )
    atf_parser.add_argument(
        "--level",
        type=str,
        choices=["intern", "junior", "senior", "principal"],
        default="intern",
        help="ATF maturity level target (default: intern)",
    )
    atf_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to JSON file with agent identity fields",
    )
    atf_parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    atf_parser.set_defaults(func=cmd_atf)

    # agent-identity command (v1.11+) - verify continuity across sessions
    agent_id_parser = subparsers.add_parser(
        "agent-identity",
        help="Verify cryptographic identity continuity for an agent across the chain",
    )
    agent_id_parser.add_argument(
        "--agent", type=str, default=None,
        help="Restrict check to this agent_name (default: all agents in chain)",
    )
    agent_id_parser.add_argument(
        "--db", type=str, default=None,
        help="Path to events database (default: ~/.air-trust/events.db)",
    )
    agent_id_parser.add_argument(
        "--max-gap", type=int, default=3600,
        help="Timestamp gap (in seconds) above which a new session is inferred (default: 3600)",
    )
    agent_id_parser.add_argument(
        "--json", dest="json_output", action="store_true", default=False,
        help="Output as JSON (for CI/CD pipelines)",
    )
    agent_id_parser.set_defaults(func=cmd_agent_identity)

    # Parse arguments
    args = parser.parse_args()

    # Run command
    if hasattr(args, "func"):
        try:
            exit_code = args.func(args)
            sys.exit(exit_code if exit_code is not None else 0)
        except KeyboardInterrupt:
            print("\nInterrupted.")
            sys.exit(130)
        except Exception as e:
            print(f"{RED}Fatal error: {e}{RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
