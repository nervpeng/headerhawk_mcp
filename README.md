# HeaderHawk 🦅

An advanced email security analysis MCP (Model Context Protocol) server that provides real-time phishing detection, threat intelligence integration, and comprehensive email header analysis.

## Overview

HeaderHawk is a specialized MCP server designed to help security analysts, cybersecurity professionals, and organizations detect and analyze phishing attempts, malicious emails, and security threats through deep email header analysis and threat intelligence integration.

**Key Features:**
- 📧 Comprehensive email header parsing and analysis
- 🎯 Phishing indicator detection with confidence scoring
- 🔍 Indicators of Compromise (IoCs) extraction
- 🛡️ VirusTotal threat intelligence integration
- 🔐 DKIM/SPF/DMARC authentication validation
- 🌐 Domain reputation analysis
- ⚡ Real-time threat assessment
- 🦠 Malware detection and payload analysis
- 📊 Business Email Compromise (BEC) pattern detection
- 🔬 Social engineering tactic identification

<img width="772" height="993" alt="image" src="https://github.com/user-attachments/assets/a51373b7-4f6e-46dd-b919-33d1dce93c2d" />

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- VirusTotal API key (for threat scanning features)

### From PyPI (Recommended)
```bash
pip install headerhawk
```

### From Source
```bash
git clone https://github.com/nervpeng/headerhawk.git
cd headerhawk
pip install -e .
```

## Quick Start

### Basic Usage with Claude Desktop

1. **Install HeaderHawk:**
   ```bash
   pip install headerhawk
   ```

2. **Configure Claude Desktop** (`claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "headerhawk": {
         "command": "headerhawk-mcp",
         "env": {
           "VIRUSTOTAL_API_KEY": "your_virustotal_api_key_here"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop** and start analyzing emails!

### Command Line Usage
```bash
# Analyze an email for phishing indicators
headerhawk analyze /path/to/email.eml

# Extract IoCs from an email
headerhawk extract-iocs /path/to/email.eml

# Scan extracted indicators with VirusTotal
headerhawk scan-virustotal /path/to/email.eml
```

## Available Functions

### 1. `analyze_email(file_path: str)`
Performs comprehensive phishing analysis on an email file.

**Input:**
- `file_path`: Path to .eml file

**Returns:**
- Email header metadata (From, To, Date, Message-ID)
- Authentication results (DKIM, SPF, DMARC status)
- Phishing indicators with confidence scores
- Risk assessment summary
- Detailed analysis recommendations
- Malware/payload detection results

**Example:**
```python
from headerhawk import analyze_email

result = analyze_email("suspicious_email.eml")
print(f"Risk Level: {result['risk_level']}")
print(f"Indicators Found: {result['phishing_indicators']}")
print(f"Malware Detected: {result.get('malware_indicators', [])}")
```

**Real-World Example Output:**
```
Risk Level: CRITICAL
Verdict: MALICIOUS - Business Email Compromise with Malware

Phishing Indicators Found:
1. Spoofed Domain Authority (morecft.shop) - CRITICAL
2. Generic Business Greeting ("Good day") - HIGH
3. Urgency Pattern (RFQ Request) - MEDIUM
4. Suspicious Attachment Format (.7z archive) - CRITICAL
5. Base64-Encoded Payload - CRITICAL

Authentication:
- DKIM: PASS (but domain is malicious)
- SPF: PASS (but sender is spoofed)
- DMARC: PASS (policy bypass)

Malware Indicators:
- .7z compressed archive containing VBS script
- File: Invoice.vbs
- Payload: Base64-encoded executable
- Likely Attack: Ransomware/Trojan deployment

Recommended Action: QUARANTINE & DELETE
```

### 2. `extract_iocs(file_path: str)`
Extracts Indicators of Compromise from email content and headers.

**Input:**
- `file_path`: Path to .eml file

**Returns:**
- URLs found in email
- IP addresses detected
- Domains referenced
- Email addresses extracted
- File hashes (if present)
- Attachment metadata
- Classification by type and risk level

**Example:**
```python
from headerhawk import extract_iocs

iocs = extract_iocs("email.eml")
print(f"URLs: {iocs['urls']}")
print(f"Domains: {iocs['domains']}")
print(f"IPs: {iocs['ips']}")
print(f"Attachments: {iocs.get('attachments', [])}")
```

**Real-World Example Output:**
```json
{
  "domains": ["[redacted].shop"],
  "ips": ["[redacted]"],
  "emails": ["postmaster@[redacted].shop", "Mr. Andy <postmaster@[redacted].shop>"],
  "attachments": [
    {
      "filename": "Request for Quotation (RFQ) - 3949483.7z",
      "type": ".7z",
      "risk": "CRITICAL",
      "encoding": "base64",
      "size_kb": "~100"
    }
  ],
  "mail_server": "[redacted].[redacted].shop",
  "sender_ip": "[redacted]"
}
```

### 3. `scan_with_virustotal(file_path: str)`
Scans extracted IoCs against VirusTotal threat intelligence database.

**Input:**
- `file_path`: Path to .eml file
- Environment variable: `VIRUSTOTAL_API_KEY`

**Returns:**
- VirusTotal scan results for each IoC
- Detection ratios (e.g., "5/72")
- Last analysis dates
- Verdict summary
- Detailed threat classifications
- Campaign correlation (if available)

**Example:**
```python
from headerhawk import scan_with_virustotal

results = scan_with_virustotal("email.eml")
for ioc, verdict in results.items():
    print(f"{ioc}: {verdict['detection_ratio']}")
    print(f"  Verdict: {verdict['verdict']}")
    print(f"  Categories: {verdict.get('categories', [])}")
```

## Phishing Indicators Detected

HeaderHawk analyzes emails for 25+ phishing and malware indicators including:

- **Authentication Failures**
  - DKIM signature failures
  - SPF policy misalignment
  - DMARC failures
  - Missing authentication headers
  - Deprecated signing algorithms (RSA-SHA1)
  - Authentication bypass attempts

- **Header Anomalies**
  - Spoofed sender domains
  - Mismatched Reply-To addresses
  - Suspicious X-headers
  - Mail forwarding inconsistencies
  - X-Recommended-Action flags
  - Spoofed corporate identity headers

- **Content Analysis**
  - Urgency language patterns
  - Authority impersonation attempts
  - Suspicious URL patterns
  - Known phishing keywords
  - Business Email Compromise (BEC) patterns
  - Social engineering tactics
  - Generic greetings ("Good day", "Dear Sir/Madam")
  - Fake business requests

- **Infrastructure Indicators**
  - Suspicious mail servers
  - Blacklisted IP addresses
  - Generic/free email providers for business
  - Impossible travel patterns
  - Bulletproof hosting providers
  - Newly registered malicious domains
  - Domain registration age analysis

- **Technical Indicators**
  - Return-Path misalignment
  - Multiple forwarding hops
  - Encoding anomalies
  - Obfuscated content
  - Suspicious attachment formats (.7z, .scr, .vbs, .exe)
  - Base64-encoded executable payloads
  - Archive bombs or compressed payloads

- **Malware Detection**
  - Archive files (.7z, .rar, .zip) containing executables
  - Visual Basic Script (.vbs) payloads
  - Executable masquerading as documents
  - Ransomware/trojan attack chains
  - Known malware signatures
  - Payload obfuscation techniques

## Real-World Usage Examples

### Example 1: Legitimate Marketing Email
```
✅ Risk Level: LOW
Verdict: LEGITIMATE

Indicators:
- Valid DKIM/SPF/DMARC: ✓
- Known sender domain: [redacted].com
- Legitimate business (Music Festival)
- Clear unsubscribe mechanism
- Standard Mailchimp template
- No suspicious attachments
```

### Example 2: Malicious RFQ Phishing Email
```
🚨 Risk Level: CRITICAL
Verdict: MALICIOUS - BEC with Malware

Indicators:
- Spoofed domain: [redacted].shop (newly registered)
- Generic greeting: "Good day"
- Business request (RFQ) for credibility
- Urgent tone: "awaiting your esteemed offer"
- .7z attachment with VBS payload
- Base64-encoded malware
- Bulletproof hosting IP: [redacted]
- Deprecated DKIM algorithm (RSA-SHA1)

Recommended Action: QUARANTINE & DELETE
```

## MCP Integration

### With Claude (claude.ai or Claude Desktop)

```
User: "Analyze this suspicious email for me"
Claude: Uses HeaderHawk to extract IoCs and phishing indicators
Claude: "I found X phishing indicators including: [list]"
Claude: "Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]"
Claude: "Recommended Action: [QUARANTINE/DELETE/REVIEW/SAFE]"
```

### Available MCP Tools

When used with Claude or other MCP-compatible clients:

1. **say_hello** - Test connection status
2. **analyze_email** - Full phishing analysis with malware detection
3. **extract_iocs** - Extract indicators of compromise
4. **scan_with_virustotal** - Threat intelligence lookup

## Configuration

### Environment Variables

```bash
# VirusTotal API Key (required for threat scanning)
export VIRUSTOTAL_API_KEY="your_api_key_here"

# Optional: API rate limiting
export VIRUSTOTAL_RATE_LIMIT="4"  # requests per minute

# Optional: Output format
export OUTPUT_FORMAT="json"  # or "text" (default)

# Optional: Threat level thresholds
export CRITICAL_THRESHOLD="0.8"
export HIGH_THRESHOLD="0.6"
```

### Configuration File

Create `~/.headerhawk/config.json`:
```json
{
  "virustotal": {
    "api_key": "your_api_key",
    "rate_limit": 4,
    "timeout": 30
  },
  "analysis": {
    "check_authentication": true,
    "extract_urls": true,
    "check_phishing_keywords": true,
    "detect_malware": true,
    "check_attachment_types": true
  },
  "threat_levels": {
    "critical_threshold": 0.8,
    "high_threshold": 0.6,
    "medium_threshold": 0.4
  }
}
```

## Output Format

### Email Analysis Output
```json
{
  "email_metadata": {
    "from": "sender@example.com",
    "to": ["recipient@company.com"],
    "date": "2026-01-08T13:30:49Z",
    "subject": "[Important] Invoice (Due: TODAY at 10pm ET)"
  },
  "authentication": {
    "dkim": "PASS",
    "spf": "PASS",
    "dmarc": "PASS",
    "dkim_algorithm": "rsa-sha256"
  },
  "phishing_indicators": [
    {
      "indicator": "valid_dkim",
      "severity": "low",
      "description": "DKIM signature verified successfully",
      "confidence": 0.95
    }
  ],
  "malware_indicators": [
    {
      "type": "suspicious_attachment",
      "description": ".7z archive with VBS payload",
      "severity": "critical",
      "filename": "Document_Invoice.7z",
      "payload_type": "VBS script"
    }
  ],
  "risk_level": "CRITICAL",
  "verdict": "MALICIOUS"
}
```

### IoCs Extraction Output
```json
{
  "urls": [
    "https://www.[target1].com/...",
    "https://www.[target2].net/..."
  ],
  "domains": [
    "[target1].com",
    "[target2].com"
  ],
  "ips": [
    "[redacted]"
  ],
  "emails": [
    "info@[target1].com"
  ],
  "attachments": [
    {
      "filename": "document.7z",
      "type": "archive",
      "risk_level": "high",
      "encoding": "base64"
    }
  ]
}
```

## Use Cases

### 1. **Security Analysts**
Quickly triage and analyze suspicious emails in bulk with confidence scoring and automated threat intelligence lookup. Identify malware campaigns and BEC attempts in seconds.

### 2. **IT Security Teams**
Integrate HeaderHawk into security information and event management (SIEM) systems for automated email threat detection and alerting.

### 3. **Cybersecurity Researchers**
Extract and analyze phishing campaigns with comprehensive IoC extraction, malware payload detection, and threat intelligence correlation.

### 4. **Email Gateway Administrators**
Deploy HeaderHawk as part of email gateway solutions for real-time phishing detection, malware scanning, and automated quarantine.

### 5. **Incident Response Teams**
Rapidly analyze emails during security incidents with detailed forensic information, malware analysis, and threat assessment for faster response.

### 6. **Managed Security Service Providers (MSSPs)**
Offer HeaderHawk as part of email security services for clients, with automated reports and threat summaries.

## Deployment Strategies

### PyPI Package Distribution
```bash
# Package and upload to PyPI
python -m pip install --upgrade build twine
python -m build
twine upload dist/*
```

### MCP Registry Submission
HeaderHawk is available for submission to the official MCP Registry at [mcp-registry.anthropic.com](https://mcp-registry.anthropic.com).

To register:
1. Format project following MCP standards
2. Submit to registry with documentation
3. Enable discovery for Claude users globally

### Docker Deployment
```dockerfile
FROM python:3.11-slim
RUN pip install headerhawk
ENV VIRUSTOTAL_API_KEY=your_key
CMD ["headerhawk-mcp"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: headerhawk-mcp
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: headerhawk
        image: headerhawk:latest
        env:
        - name: VIRUSTOTAL_API_KEY
          valueFrom:
            secretKeyRef:
              name: headerhawk-secrets
              key: api-key
```

## API Reference

### analyze_email()
```python
def analyze_email(file_path: str) -> Dict[str, Any]:
    """
    Analyze email for phishing indicators and malware.
    
    Args:
        file_path: Path to .eml file
        
    Returns:
        Dictionary with analysis results including:
        - email_metadata
        - authentication (DKIM/SPF/DMARC)
        - phishing_indicators
        - malware_indicators
        - risk_level
        - verdict
    """
```

### extract_iocs()
```python
def extract_iocs(file_path: str) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise from email.
    
    Args:
        file_path: Path to .eml file
        
    Returns:
        Dictionary containing:
        - urls: List of URLs
        - domains: List of domains
        - ips: List of IP addresses
        - emails: List of email addresses
        - attachments: List of attachment metadata
        - hashes: List of file hashes
    """
```

### scan_with_virustotal()
```python
def scan_with_virustotal(file_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Scan IoCs against VirusTotal threat intelligence.
    
    Args:
        file_path: Path to .eml file
        
    Returns:
        Dictionary with VirusTotal results for each IoC:
        - detection_ratio: e.g., "5/72"
        - last_analysis_date
        - verdict
        - categories
        - malware_type
    """
```

## Performance Characteristics

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| Email Analysis | 50-200ms | Local processing only |
| IoCs Extraction | 30-100ms | Includes regex parsing + attachment analysis |
| VirusTotal Scan | 1-5s per IoC | Depends on API rate limits |
| Malware Detection | 100-300ms | Payload analysis and pattern matching |
| Full Pipeline | 2-10s | Complete analysis with threats + VT lookup |

## Limitations & Considerations

- **File Size**: Works best with emails < 50MB
- **Encoding**: Handles UTF-8, ASCII, and common encodings
- **VirusTotal API**: Requires API key for threat scanning (free tier: 4 requests/minute)
- **False Positives**: Machine learning-based detection may have edge cases
- **Zero-Days**: Cannot detect previously unknown threat patterns
- **Language**: Phishing keyword detection optimized for English
- **Payload Analysis**: Limited to email-embedded payloads; does not execute malware

## Troubleshooting

### VirusTotal API Issues
```
Error: "API key invalid or rate limit exceeded"
Solution: Check VIRUSTOTAL_API_KEY environment variable and request limits
```

### File Not Found
```
Error: "File not found at path"
Solution: Ensure .eml file exists and path is absolute or relative from current directory
```

### Encoding Issues
```
Error: "Unable to parse email"
Solution: Verify file is valid .eml format (SMTP mail with CRLF line terminators)
```

### Malware Detection Not Working
```
Error: "Payload analysis incomplete"
Solution: Ensure email includes attachments and they are properly encoded (base64/quoted-printable)
```

## Contributing

Contributions are welcome! Areas for improvement:

- Additional phishing detection heuristics
- Support for more email formats (.msg, .pst)
- Enhanced machine learning models
- Additional threat intelligence integrations
- Payload detonation sandbox integration
- Performance optimizations
- Multi-language support

## Development

### Setup Development Environment
```bash
git clone https://github.com/nervpeng/headerhawk.git
cd headerhawk
pip install -e ".[dev]"
pytest  # Run tests
```

### Running Tests
```bash
pytest tests/ -v
pytest tests/ --cov=headerhawk  # With coverage
pytest tests/test_malware_detection.py -v  # Malware detection tests
```

## Security Considerations

- **API Keys**: Never commit API keys to version control
- **Email Data**: Use in compliance with your organization's data retention policies
- **Rate Limiting**: Respect VirusTotal API rate limits to avoid blocking
- **Threat Intelligence**: VirusTotal results reflect community detections, not absolute truth
- **Payload Safety**: Extracted payloads are not executed; analysis is performed on file metadata
- **Data Privacy**: Emails are analyzed locally unless using VirusTotal scanning

## License

MIT License - See LICENSE file for details

## Support & Community

- **GitHub Issues**: [Report bugs and request features](https://github.com/nervpeng/headerhawk/issues)
- **MCP Specification**: [Model Context Protocol Documentation](https://modelcontextprotocol.io)
- **VirusTotal API**: [VirusTotal Developers](https://developers.virustotal.com)

## Acknowledgments

- Built on the Model Context Protocol (MCP) specification
- Threat intelligence powered by VirusTotal
- Email parsing utilizing industry-standard libraries
- Inspired by security research in phishing detection and malware analysis

## Changelog

### v0.0.1 (Initial)
- Core email analysis functionality
- IoC extraction
- VirusTotal integration
- MCP server implementation

### Roadmap
- v0.1.0: Spam/Ham scoring and detection logic improvements
- v0.2.0: Sandbox payload detonation integration
- v0.3.0: Additional threat intelligence integrations (AlienVault OTX, URLhaus)
- v0.4.0: Multi-language phishing keyword support
- v1.0.0: Production-ready with comprehensive documentation

---

**Made with 🦅 for cybersecurity professionals**


For questions or support, reach out through GitHub Issues or community channels.
