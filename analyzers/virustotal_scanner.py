#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
from typing import Dict, List, Optional


class VirusTotalScanner:
    """
    VirusTotal API v3 integration for IoC scanning.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal scanner.
        
        Args:
            api_key: VirusTotal API key (get free key at virustotal.com)
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Rate limiting (free tier: 4 requests/minute)
        self.requests_per_minute = 4
        self.request_interval = 60.0 / self.requests_per_minute
        self.last_request_time = 0
    
    def scan_iocs(self, iocs: dict) -> Dict:
        """
        Scan all extracted IoCs against VirusTotal.
        
        Args:
            iocs: Dictionary of IoCs from IoCExtractor
            
        Returns:
            Dictionary with scan results
        """
        if not self.api_key:
            return {
                'error': 'VirusTotal API key not provided',
                'message': 'Get a free API key at https://www.virustotal.com/gui/join-us'
            }
        
        results = {
            'urls': [],
            'domains': [],
            'ips': [],
            'hashes': [],
            'summary': {
                'total_scanned': 0,
                'malicious_count': 0,
                'suspicious_count': 0,
                'clean_count': 0
            }
        }
        
        # Scan URLs
        for ioc in iocs.get('urls', []):
            result = self._scan_url(ioc['value'])
            if result:
                results['urls'].append({
                    'ioc': ioc['value'],
                    'result': result
                })
                self._update_summary(results['summary'], result)
        
        # Scan domains
        for ioc in iocs.get('domains', []):
            result = self._scan_domain(ioc['value'])
            if result:
                results['domains'].append({
                    'ioc': ioc['value'],
                    'result': result
                })
                self._update_summary(results['summary'], result)
        
        # Scan IPs
        for ioc in iocs.get('ips', []):
            result = self._scan_ip(ioc['value'])
            if result:
                results['ips'].append({
                    'ioc': ioc['value'],
                    'result': result
                })
                self._update_summary(results['summary'], result)
        
        # Scan file hashes (from attachments)
        for attachment in iocs.get('attachments', []):
            sha256 = attachment.get('sha256')
            if sha256:
                result = self._scan_hash(sha256)
                if result:
                    results['hashes'].append({
                        'filename': attachment['filename'],
                        'sha256': sha256,
                        'result': result
                    })
                    self._update_summary(results['summary'], result)
        
        return results
    
    def _rate_limit(self):
        """
        Implement rate limiting to stay within API limits.
        Free tier: 4 requests per minute
        """
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.request_interval:
            sleep_time = self.request_interval - time_since_last
            print(f"⏱️  Rate limiting: waiting {sleep_time:.1f}s...")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, endpoint: str) -> Optional[Dict]:
        """
        Make authenticated request to VirusTotal API.
        """
        self._rate_limit()
        
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/{endpoint}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'error': 'Not found in VirusTotal database'}
            else:
                return {'error': f'API error: {response.status_code}'}
        
        except Exception as e:
            return {'error': f'Request failed: {str(e)}'}
    
    def _scan_url(self, url: str) -> Optional[Dict]:
        """Scan a URL."""
        print(f"🔍 Scanning URL: {url}")
        
        # VirusTotal requires URL to be base64-encoded without padding
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        
        data = self._make_request(f"urls/{url_id}")
        
        if data and 'data' in data:
            stats = data['data']['attributes']['last_analysis_stats']
            return self._parse_stats(stats)
        
        return data
    
    def _scan_domain(self, domain: str) -> Optional[Dict]:
        """Scan a domain."""
        print(f"🔍 Scanning domain: {domain}")
        
        data = self._make_request(f"domains/{domain}")
        
        if data and 'data' in data:
            stats = data['data']['attributes']['last_analysis_stats']
            reputation = data['data']['attributes'].get('reputation', 0)
            
            result = self._parse_stats(stats)
            result['reputation'] = reputation
            return result
        
        return data
    
    def _scan_ip(self, ip: str) -> Optional[Dict]:
        """Scan an IP address."""
        print(f"🔍 Scanning IP: {ip}")
        
        data = self._make_request(f"ip_addresses/{ip}")
        
        if data and 'data' in data:
            stats = data['data']['attributes']['last_analysis_stats']
            return self._parse_stats(stats)
        
        return data
    
    def _scan_hash(self, file_hash: str) -> Optional[Dict]:
        """Scan a file hash."""
        print(f"🔍 Scanning hash: {file_hash[:16]}...")
        
        data = self._make_request(f"files/{file_hash}")
        
        if data and 'data' in data:
            stats = data['data']['attributes']['last_analysis_stats']
            return self._parse_stats(stats)
        
        return data
    
    def _parse_stats(self, stats: dict) -> dict:
        """
        Parse VirusTotal analysis statistics.
        
        Stats format:
        {
            'harmless': 70,
            'malicious': 5,
            'suspicious': 2,
            'undetected': 10,
            'timeout': 0
        }
        """
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'verdict': self._get_verdict(stats)
        }
    
    def _get_verdict(self, stats: dict) -> str:
        """
        Determine verdict based on detection stats.
        """
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        if malicious > 5:
            return '🔴 MALICIOUS'
        elif malicious > 0:
            return '🟠 LIKELY MALICIOUS'
        elif suspicious > 3:
            return '🟡 SUSPICIOUS'
        elif suspicious > 0:
            return '⚪ POSSIBLY SUSPICIOUS'
        else:
            return '🟢 CLEAN'
    
    def _update_summary(self, summary: dict, result: dict):
        """Update running summary of scan results."""
        summary['total_scanned'] += 1
        
        if 'malicious' in result:
            if result['malicious'] > 0:
                summary['malicious_count'] += 1
            elif result['suspicious'] > 0:
                summary['suspicious_count'] += 1
            else:
                summary['clean_count'] += 1


# Test code
if __name__ == "__main__":
    import os
    
    api_key = os.getenv('VT_API_KEY')
    
    if not api_key:
        print("Error: Set VT_API_KEY environment variable")
        print("Get a free API key at: https://www.virustotal.com/gui/join-us")
    else:
        scanner = VirusTotalScanner(api_key)
        
        # Test with a known malicious domain
        test_iocs = {
            'domains': [
                {'value': 'google.com', 'context': 'test'},  # Clean
                {'value': 'testsafebrowsing.appspot.com', 'context': 'test'}  # Test malware site
            ]
        }
        
        results = scanner.scan_iocs(test_iocs)
        
        print("\n" + "=" * 60)
        print("🦅 HEADERHAWK VIRUSTOTAL SCAN RESULTS")
        print("=" * 60)
        print(f"\nTotal scanned: {results['summary']['total_scanned']}")
        print(f"Malicious: {results['summary']['malicious_count']}")
        print(f"Suspicious: {results['summary']['suspicious_count']}")
        print(f"Clean: {results['summary']['clean_count']}\n")
        
        for domain_result in results['domains']:
            print(f"Domain: {domain_result['ioc']}")
            print(f"  Verdict: {domain_result['result']['verdict']}")
            print(f"  Malicious: {domain_result['result']['malicious']}")
            print(f"  Suspicious: {domain_result['result']['suspicious']}")
            print()