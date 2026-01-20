#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import hashlib
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, List
import os


class IoC:
    """
    Represents a single Indicator of Compromise.
    """
    def __init__(self, ioc_type: str, value: str, context: str = ""):
        self.type = ioc_type  # 'url', 'ip', 'domain', 'email', 'hash'
        self.value = value
        self.context = context  # Where it was found (body, header, attachment)
    
    def to_dict(self):
        """Convert to dictionary for easy JSON serialization."""
        return {
            'type': self.type,
            'value': self.value,
            'context': self.context
        }


class IoCExtractor:
    """
    Extracts Indicators of Compromise from email files.
    """
    
    def __init__(self):
        # Regex patterns for different IoC types
        # These patterns match common formats
        
        # URL pattern: http(s)://domain.com/path
        self.url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        # IP address pattern: xxx.xxx.xxx.xxx
        self.ip_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # Email pattern: user@domain.com
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        # Domain pattern: domain.com (extracted from URLs and emails)
        self.domain_pattern = re.compile(
            r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)',
            re.IGNORECASE
        )
        
        # Hash patterns (MD5, SHA1, SHA256)
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    def extract_from_file(self, file_path: str) -> Dict:
        """
        Extract all IoCs from an email file.
        
        Args:
            file_path: Path to .eml file
            
        Returns:
            Dictionary containing categorized IoCs and attachments
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        try:
            # Parse the email
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            # Initialize results
            iocs = {
                'urls': [],
                'ips': [],
                'domains': [],
                'emails': [],
                'hashes': [],
                'attachments': []
            }
            
            # Extract from headers
            header_text = self._get_all_headers(msg)
            self._extract_from_text(header_text, iocs, context="headers")
            
            # Extract from body
            body_text = self._get_email_body(msg)
            self._extract_from_text(body_text, iocs, context="body")
            
            # Extract attachments
            attachments = self._extract_attachments(msg)
            iocs['attachments'] = attachments
            
            # Deduplicate IoCs
            iocs = self._deduplicate_iocs(iocs)
            
            # Generate summary
            summary = self._generate_summary(iocs)
            
            return {
                'iocs': iocs,
                'summary': summary,
                'total_iocs': sum(len(v) for k, v in iocs.items() if k != 'attachments'),
                'attachment_count': len(iocs['attachments'])
            }
            
        except Exception as e:
            return {"error": f"Failed to extract IoCs: {str(e)}"}
    
    def _get_all_headers(self, msg) -> str:
        """Extract all headers as text."""
        headers = []
        for key, value in msg.items():
            headers.append(f"{key}: {value}")
        return "\n".join(headers)
    
    def _get_email_body(self, msg) -> str:
        """Extract email body text."""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                
                if content_type == "text/plain":
                    try:
                        body += part.get_content()
                    except:
                        pass
                elif content_type == "text/html":
                    try:
                        # For HTML, we still extract it as text
                        # URLs in HTML are valuable IoCs
                        body += part.get_content()
                    except:
                        pass
        else:
            try:
                body = msg.get_content()
            except:
                pass
        
        return body
    
    def _extract_from_text(self, text: str, iocs: dict, context: str):
        """
        Extract IoCs from text using regex patterns.
        
        Args:
            text: Text to search
            iocs: Dictionary to store found IoCs
            context: Where the text came from (headers/body)
        """
        # Extract URLs
        urls = self.url_pattern.findall(text)
        for url in urls:
            iocs['urls'].append(IoC('url', url, context).to_dict())
            
            # Also extract domain from URL
            domain_match = self.domain_pattern.search(url)
            if domain_match:
                domain = domain_match.group(1)
                iocs['domains'].append(IoC('domain', domain, f"{context} (from URL)").to_dict())
        
        # Extract IP addresses
        ips = self.ip_pattern.findall(text)
        for ip in ips:
            # Filter out private IPs for external threat intel
            if not self._is_private_ip(ip):
                iocs['ips'].append(IoC('ip', ip, context).to_dict())
        
        # Extract email addresses
        emails = self.email_pattern.findall(text)
        for email_addr in emails:
            iocs['emails'].append(IoC('email', email_addr, context).to_dict())
            
            # Extract domain from email
            domain = email_addr.split('@')[1]
            iocs['domains'].append(IoC('domain', domain, f"{context} (from email)").to_dict())
        
        # Extract hashes (useful if email contains IOCs in body)
        md5s = self.md5_pattern.findall(text)
        for hash_val in md5s:
            iocs['hashes'].append(IoC('hash', f"MD5:{hash_val}", context).to_dict())
        
        sha256s = self.sha256_pattern.findall(text)
        for hash_val in sha256s:
            iocs['hashes'].append(IoC('hash', f"SHA256:{hash_val}", context).to_dict())
    
    def _extract_attachments(self, msg) -> List[Dict]:
        """
        Extract attachment metadata and calculate hashes.
        """
        attachments = []
        
        for part in msg.walk():
            # Skip non-attachment parts
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                # Get attachment data
                data = part.get_payload(decode=True)
                
                if data:
                    # Calculate hashes
                    md5_hash = hashlib.md5(data).hexdigest()
                    sha256_hash = hashlib.sha256(data).hexdigest()
                    
                    attachment_info = {
                        'filename': filename,
                        'size': len(data),
                        'content_type': part.get_content_type(),
                        'md5': md5_hash,
                        'sha256': sha256_hash,
                        'suspicious': self._is_suspicious_attachment(filename)
                    }
                    
                    attachments.append(attachment_info)
        
        return attachments
    
    def _is_suspicious_attachment(self, filename: str) -> bool:
        """
        Check if attachment has suspicious extension.
        """
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.msi', '.dll', '.ps1',
            '.hta', '.wsf', '.lnk', '.iso', '.img', '.ico', '.zip'
        ]
        
        filename_lower = filename.lower()
        return any(filename_lower.endswith(ext) for ext in suspicious_extensions)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (RFC 1918)."""
        try:
            octets = list(map(int, ip.split('.')))
            return (
                octets[0] == 10 or
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168) or
                octets[0] == 127
            )
        except:
            return False
    
    def _deduplicate_iocs(self, iocs: dict) -> dict:
        """
        Remove duplicate IoCs while preserving context.
        """
        for key in ['urls', 'ips', 'domains', 'emails', 'hashes']:
            if key in iocs:
                # Create set of unique values
                seen = set()
                unique = []
                
                for ioc in iocs[key]:
                    if ioc['value'] not in seen:
                        seen.add(ioc['value'])
                        unique.append(ioc)
                
                iocs[key] = unique
        
        return iocs
    
    def _generate_summary(self, iocs: dict) -> str:
        """Generate a human-readable summary."""
        summary = []
        
        if iocs['urls']:
            summary.append(f"🔗 Found {len(iocs['urls'])} URL(s)")
        if iocs['ips']:
            summary.append(f"🌐 Found {len(iocs['ips'])} public IP(s)")
        if iocs['domains']:
            summary.append(f"🏠 Found {len(iocs['domains'])} unique domain(s)")
        if iocs['emails']:
            summary.append(f"📧 Found {len(iocs['emails'])} email address(es)")
        if iocs['hashes']:
            summary.append(f"#️⃣ Found {len(iocs['hashes'])} hash(es)")
        if iocs['attachments']:
            suspicious_count = sum(1 for att in iocs['attachments'] if att['suspicious'])
            summary.append(f"📎 Found {len(iocs['attachments'])} attachment(s)")
            if suspicious_count > 0:
                summary.append(f"⚠️  {suspicious_count} suspicious attachment(s)!")
        
        return "\n".join(summary) if summary else "No IoCs found"


# Test code
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ioc_extractor.py <path_to_eml>")
        sys.exit(1)
    
    extractor = IoCExtractor()
    results = extractor.extract_from_file(sys.argv[1])
    
    if 'error' in results:
        print(f"Error: {results['error']}")
    else:
        print("=" * 60)
        print("🦅 HEADERHAWK IOC EXTRACTION REPORT")
        print("=" * 60)
        print(f"\n{results['summary']}\n")
        
        print(f"Total IoCs: {results['total_iocs']}")
        print(f"Attachments: {results['attachment_count']}\n")
        
        # Display URLs
        if results['iocs']['urls']:
            print("🔗 URLs:")
            for ioc in results['iocs']['urls']:
                print(f"  • {ioc['value']} [{ioc['context']}]")
        
        # Display domains
        if results['iocs']['domains']:
            print("\n🏠 Domains:")
            for ioc in results['iocs']['domains']:
                print(f"  • {ioc['value']} [{ioc['context']}]")
        
        # Display attachments
        if results['iocs']['attachments']:
            print("\n📎 Attachments:")
            for att in results['iocs']['attachments']:
                suspicious = "⚠️ SUSPICIOUS" if att['suspicious'] else "✓"
                print(f"  • {att['filename']} [{suspicious}]")
                print(f"    Size: {att['size']} bytes")
                print(f"    SHA256: {att['sha256']}")