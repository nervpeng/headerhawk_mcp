#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HeaderHawk MCP Server
Email security analysis with IoC extraction and threat intelligence.
"""

import asyncio
import json
import os
import sys
import logging
from typing import Optional

from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

# Import HeaderHawk analyzers
from analyzers.header_analyzer import HeaderAnalyzer
from analyzers.ioc_extractor import IoCExtractor
from analyzers.virustotal_scanner import VirusTotalScanner

# Initialize server
app = Server("headerhawk")

# Setup logging
LOG_LEVEL = os.getenv("HEADERHAWK_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("headerhawk")

# Initialize analyzers
header_analyzer = HeaderAnalyzer()
ioc_extractor = IoCExtractor()

# Initialize threat intel scanners
vt_api_key = os.getenv('VT_API_KEY')
vt_scanner: Optional[VirusTotalScanner] = VirusTotalScanner(vt_api_key) if vt_api_key else None


@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    HeaderHawk tool catalog.
    """
    tools = [
        Tool(
            name="say_hello",
            description="Test the status of HeaderHawk",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Your Name"
                    }
                },
                "required": ["name"]
            }
        ),
        Tool(
            name="analyze_email",
            description="Analyze email headers for phishing indicators",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to .eml file"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="extract_iocs",
            description="Extract Indicators of Compromise (URLs, IPs, domains, hashes) from email",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to .eml file"
                    }
                },
                "required": ["file_path"]
            }
        )
    ]
    
    # Add VirusTotal scan if API key is available
    if vt_scanner:
        tools.append(Tool(
            name="scan_with_virustotal",
            description="Scan extracted IoCs against VirusTotal threat intelligence database",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to .eml file"
                    }
                },
                "required": ["file_path"]
            }
        ))
    
    return tools


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """
    Execute HeaderHawk tools.
    """
    
    if name == "analyze_email":
        file_path = arguments.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return [TextContent(type="text", text=f"Error: file_path is missing or does not exist: {file_path}" )]

        results = header_analyzer.analyze(file_path)

        if 'error' in results:
            return [TextContent(type="text", text=f"Error: {results['error']}")]

        report = format_header_analysis(results)
        return [TextContent(type="text", text=report)]
    
    elif name == "extract_iocs":
        file_path = arguments.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return [TextContent(type="text", text=f"Error: file_path is missing or does not exist: {file_path}" )]

        results = ioc_extractor.extract_from_file(file_path)

        if 'error' in results:
            return [TextContent(type="text", text=f"Error: {results['error']}")]

        report = format_ioc_report(results)
        return [TextContent(type="text", text=report)]
    
    elif name == "scan_with_virustotal":
        if not vt_scanner:
            return [TextContent(type="text", text="Error: VirusTotal scanner not configured (VT_API_KEY missing)")]

        file_path = arguments.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return [TextContent(type="text", text=f"Error: file_path is missing or does not exist: {file_path}" )]

        # First extract IoCs
        ioc_results = ioc_extractor.extract_from_file(file_path)

        if 'error' in ioc_results:
            return [TextContent(type="text", text=f"Error: {ioc_results['error']}")]

        # Then scan with VirusTotal
        vt_results = vt_scanner.scan_iocs(ioc_results.get('iocs', {}))

        if not vt_results:
            return [TextContent(type="text", text="Error: VirusTotal returned no results")]

        if 'error' in vt_results:
            return [TextContent(type="text", text=f"Error: {vt_results['error']}")]

        report = format_vt_report(vt_results)
        return [TextContent(type="text", text=report)]
    
    elif name == "say_hello":
        return [TextContent(type="text", text=f"Hello, {arguments['name']}!")]
    
    return [TextContent(type="text", text=f"Unknown tool: {name}")]


def format_header_analysis(results: dict) -> str:
    """Format header analysis results."""
    report = "HEADERHAWK HEADER ANALYSIS\n"
    report += "=" * 60 + "\n\n"
    from_hdr = results.get('from', 'N/A')
    return_path = results.get('return_path', 'N/A')
    subject = results.get('subject', 'N/A')
    risk = results.get('risk_level', 'N/A')
    red_flags = results.get('red_flags', []) or []

    report += f"FROM: {from_hdr}\n"
    report += f"RETURN-PATH: {return_path}\n"
    report += f"SUBJECT: {subject}\n\n"

    report += f"RISK LEVEL: {risk}\n\n"

    report += f"RED FLAGS ({len(red_flags)}):\n"
    for flag in red_flags:
        report += f"  {flag}\n"

    if not red_flags:
        report += "  [OK] No red flags detected\n"
    
    return report


def format_ioc_report(results: dict) -> str:
    """Format IoC extraction results."""
    report = "HEADERHAWK IOC EXTRACTION REPORT\n"
    report += "=" * 60 + "\n\n"
    summary = results.get('summary', 'No summary available')
    total_iocs = results.get('total_iocs', 0)
    attachment_count = results.get('attachment_count', 0)
    iocs = results.get('iocs', {}) or {}

    report += f"{summary}\n\n"
    report += f"Total IoCs: {total_iocs}\n"
    report += f"Attachments: {attachment_count}\n\n"

    # URLs
    urls = iocs.get('urls', [])
    if urls:
        report += "URLs:\n"
        for ioc in urls:
            report += f"  * {ioc.get('value')}\n"
        report += "\n"

    # Domains
    domains = iocs.get('domains', [])
    if domains:
        report += "Domains:\n"
        for ioc in domains[:10]:  # Limit to 10
            report += f"  * {ioc.get('value')}\n"
        if len(domains) > 10:
            report += f"  ... and {len(domains) - 10} more\n"
        report += "\n"

    # IPs
    ips = iocs.get('ips', [])
    if ips:
        report += "IP Addresses:\n"
        for ioc in ips:
            report += f"  * {ioc.get('value')}\n"
        report += "\n"

    # Emails
    emails = iocs.get('emails', [])
    if emails:
        report += "Email Addresses:\n"
        for ioc in emails[:10]:
            report += f"  * {ioc.get('value')}\n"
        if len(emails) > 10:
            report += f"  ... and {len(emails) - 10} more\n"
        report += "\n"

    # Attachments
    attachments = iocs.get('attachments', [])
    if attachments:
        report += "Attachments:\n"
        for att in attachments:
            status = "[SUSPICIOUS]" if att.get('suspicious') else "[OK]"
            report += f"  * {att.get('filename')} {status}\n"
            report += f"    Size: {att.get('size')} bytes\n"
            report += f"    SHA256: {att.get('sha256')}\n"
        report += "\n"
    
    return report


def format_vt_report(results: dict) -> str:
    """Format VirusTotal scan results."""
    report = "HEADERHAWK VIRUSTOTAL SCAN REPORT\n"
    report += "=" * 60 + "\n\n"
    summary = results.get('summary', {})
    report += "SCAN SUMMARY:\n"
    report += f"  Total scanned: {summary.get('total_scanned', 0)}\n"
    report += f"  Malicious: {summary.get('malicious_count', 0)}\n"
    report += f"  Suspicious: {summary.get('suspicious_count', 0)}\n"
    report += f"  Clean: {summary.get('clean_count', 0)}\n\n"

    # Show malicious/suspicious items
    has_threats = False

    for url_result in results.get('urls', []):
        result = url_result.get('result', {})
        malicious = result.get('malicious', 0)
        suspicious = result.get('suspicious', 0)
        harmless = result.get('harmless', 0)
        if malicious > 0 or suspicious > 0:
            has_threats = True
            total = malicious + harmless if (malicious + harmless) > 0 else 'N/A'
            report += f"URL: {url_result.get('ioc')}\n"
            report += f"  Verdict: {result.get('verdict', 'Unknown')}\n"
            report += f"  Detections: {malicious}/{total}\n\n"

    for domain_result in results.get('domains', []):
        result = domain_result.get('result', {})
        malicious = result.get('malicious', 0)
        suspicious = result.get('suspicious', 0)
        harmless = result.get('harmless', 0)
        if malicious > 0 or suspicious > 0:
            has_threats = True
            total = malicious + harmless if (malicious + harmless) > 0 else 'N/A'
            report += f"Domain: {domain_result.get('ioc')}\n"
            report += f"  Verdict: {result.get('verdict', 'Unknown')}\n"
            report += f"  Detections: {malicious}/{total}\n\n"

    for hash_result in results.get('hashes', []):
        result = hash_result.get('result', {})
        malicious = result.get('malicious', 0)
        harmless = result.get('harmless', 0)
        total = malicious + harmless if (malicious + harmless) > 0 else 'N/A'
        if malicious > 0 or result.get('suspicious', 0) > 0:
            has_threats = True
        report += f"File: {hash_result.get('filename')}\n"
        report += f"  Verdict: {result.get('verdict', 'Unknown')}\n"
        report += f"  Detections: {malicious}/{total}\n\n"

    if not has_threats:
        report += "[OK] No threats detected in scanned IoCs\n"
    
    return report


async def main():
    """Start HeaderHawk server."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        try:
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
        except Exception as e:
            logger.exception("Fatal error while running server: %s", e)


if __name__ == "__main__":
    logger.info("%s", "=" * 60)
    logger.info("HEADERHAWK MCP SERVER")
    logger.info("Email Security Analysis & Threat Intelligence")
    logger.info("%s", "=" * 60)

    if vt_scanner:
        logger.info("[OK] VirusTotal scanner enabled")
    else:
        logger.warning("[!] VirusTotal scanner disabled (no API key)")

    logger.info("Server starting...")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutdown requested (KeyboardInterrupt). Exiting.")
    except Exception as e:
        logger.exception("Unhandled exception in main: %s", e)