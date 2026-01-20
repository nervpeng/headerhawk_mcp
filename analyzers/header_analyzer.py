#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import email
import re
import os
from email.parser import BytesParser
from email.policy import default
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================================================
# SPAM KEYWORD DETECTOR 
# ============================================================================

class SpamKeywordDetector:
    
    UNIVERSAL_URGENCY_PATTERNS = [
        r'(?i)\burgent\b',
        r'(?i)\bimmediate\b',
        r'(?i)\bact\s*now\b',
        r'(?i)\bverify\b',
        r'(?i)\bconfirm\b',
        r'(?i)\bclick.*link\b',
        r'(?i)\bupdate.*password\b',
        r'(?i)\breset.*password\b',
        r'(?i)\bsuspended\b',
        r'(?i)\blocked\b',
        r'(?i)\bdisabled\b',
        r'(?i)\bunusual\s*activity\b',
    ]
    
    SPAM_KEYWORDS = {
        "en": [
            'urgent', 'verify', 'suspended', 'important', 'click here', 'confirm',
            'invoice', 'password', 'update', 'locked', 'disabled', 'act now',
            'immediate', 'validate', 'unauthorized', 'unusual activity', 'congratulations',
            'won', 'claim', 'prize', 'reward', 'refund', 'quotation', 'quote'
        ],
        "es": [
            'urgente', 'verificar', 'suspendido', 'importante', 'haz clic', 'confirmar',
            'factura', 'contraseña', 'actualizar', 'bloqueado', 'desactivado', 'actúa ahora',
            'inmediato', 'validar', 'no autorizado', 'actividad inusual', 'felicidades',
            'ganaste', 'reclama', 'premio', 'recompensa', 'reembolso'
        ],
        "fr": [
            'urgent', 'vérifier', 'suspendu', 'important', 'cliquez ici', 'confirmer',
            'facture', 'mot de passe', 'mettre à jour', 'verrouillé', 'désactivé', 'agir maintenant',
            'immédiat', 'valider', 'non autorisé', 'activité inhabituelle', 'félicitations',
            'gagné', 'réclamez', 'prix', 'récompense', 'remboursement'
        ],
    }
    
    @staticmethod
    def detect_universal_patterns(text: str) -> List[str]:
        matches = []
        for pattern in SpamKeywordDetector.UNIVERSAL_URGENCY_PATTERNS:
            if re.search(pattern, text):
                pattern_name = pattern.replace(r'\b', '').replace(r'(?i)', '').replace('\\', '')
                matches.append(pattern_name)
        return matches
    
    @staticmethod
    def detect_language_keywords(text: str, language: str = "en") -> List[str]:
        if language not in SpamKeywordDetector.SPAM_KEYWORDS:
            return []
        
        keywords = SpamKeywordDetector.SPAM_KEYWORDS[language]
        text_lower = text.lower()
        matched = [kw for kw in keywords if kw in text_lower]
        return matched
    
    @staticmethod
    def add_language_keywords(language: str, keywords: List[str]) -> None:
        if language not in SpamKeywordDetector.SPAM_KEYWORDS:
            SpamKeywordDetector.SPAM_KEYWORDS[language] = []
        
        SpamKeywordDetector.SPAM_KEYWORDS[language].extend(keywords)


# ============================================================================
# VIRUSTOTAL ANALYZER
# ============================================================================

class VirusTotalAnalyzer:
    """VirusTotal threat intelligence integration"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        import os
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.available = REQUESTS_AVAILABLE and bool(self.api_key)
    
    def check_domain(self, domain: str) -> Optional[Dict]:
        """Check domain with VirusTotal"""
        if not self.available:
            return None
        
        try:
            headers = {"x-apikey": self.api_key}
            url = f"{self.BASE_URL}/domains/{domain}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            last_analysis_date = attributes.get("last_analysis_date")
            
            return {
                "domain": domain,
                "checked": True,
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "last_analysis_date": datetime.fromtimestamp(last_analysis_date) if last_analysis_date else None,
            }
        except:
            return None


# ============================================================================
# ENHANCED WHOIS ANALYZER
# ============================================================================

class EnhancedWhoisAnalyzer:
    """
    Multi-factor domain reputation analyzer
    
    Reputation Factors:
    1. Domain Age (< 1 year = risky)
    2. Privacy Protection
    3. VirusTotal Intelligence
    """
    
    def __init__(self, virustotal_api_key: Optional[str] = None,
                 check_virustotal_for_young_domains: bool = True):
        self.virustotal = VirusTotalAnalyzer(virustotal_api_key)
        self.check_virustotal_for_young_domains = check_virustotal_for_young_domains
    
    def analyze_domain(self, domain: str) -> Dict:
        """Analyze domain reputation"""
        result = {
            "domain": domain,
            "age_days": None,
            "registrar": None,
            "risk_factors": [],
            "risk_score": 0.0,
            "risk_level": "LOW",
            "virustotal": None,
        }
        
        # Fetch WHOIS data
        if WHOIS_AVAILABLE:
            self._fetch_whois_data(domain, result)
        
        # Assess domain age
        self._assess_domain_age(result)
        
        # Check VirusTotal for young domains
        if self.virustotal.available and result["age_days"] and result["age_days"] < 365:
            self._check_virustotal(domain, result)
        
        # Calculate risk score
        self._calculate_risk_score(result)
        
        return result
    
    @staticmethod
    def _fetch_whois_data(domain: str, result: Dict) -> None:
        try:
            w = whois.whois(domain, timeout=10)
            
            if not w:
                return
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                result["age_days"] = (datetime.now() - creation_date).days
            
            registrar = w.registrar
            if isinstance(registrar, list):
                registrar = registrar[0]
            result["registrar"] = registrar.lower() if registrar else None
            
            # Check privacy
            whois_str = str(w).lower()
            if any(x in whois_str for x in ["privacy", "redacted", "protected", "proxy"]):
                result["risk_factors"].append("privacy_protected")
        except:
            pass
    
    @staticmethod
    def _assess_domain_age(result: Dict) -> None:
        """Assess risk based on domain age"""
        age_days = result["age_days"]
        if not age_days:
            return
        
        if age_days < 7:
            result["risk_factors"].append("very_new_domain")  # < 7 days
            result["risk_factors"].append(f"age:{age_days}days")
        elif age_days < 30:
            result["risk_factors"].append("new_domain")  # 7-30 days
            result["risk_factors"].append(f"age:{age_days}days")
        elif age_days < 365:
            result["risk_factors"].append("young_domain")  # 30-365 days
            result["risk_factors"].append(f"age:{age_days}days")
    
    def _check_virustotal(self, domain: str, result: Dict) -> None:
        """Check VirusTotal for young domains"""
        vt_result = self.virustotal.check_domain(domain)
        
        if not vt_result:
            return
        
        result["virustotal"] = vt_result
        
        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)
        
        if malicious > 0:
            result["risk_factors"].append(f"vt_malicious:{malicious}")
        elif suspicious > 0:
            result["risk_factors"].append(f"vt_suspicious:{suspicious}")
    
    @staticmethod
    def _calculate_risk_score(result: Dict) -> None:
        """Calculate risk score (0.0 - 1.0)"""
        risk_scores = {
            "very_new_domain": 0.4,
            "new_domain": 0.3,
            "young_domain": 0.2,
            "malicious_registrar": 0.2,
            "privacy_protected": 0.1,
        }
        
        total_score = 0.0
        
        for factor in result["risk_factors"]:
            # Direct factor match
            if factor in risk_scores:
                total_score += risk_scores[factor]
            
            # VirusTotal malicious
            elif factor.startswith("vt_malicious:"):
                total_score += 0.3
            
            # VirusTotal suspicious
            elif factor.startswith("vt_suspicious:"):
                total_score += 0.15
        
        result["risk_score"] = min(total_score, 1.0)
        
        # Determine risk level
        if result["risk_score"] >= 0.6:
            result["risk_level"] = "CRITICAL"
        elif result["risk_score"] >= 0.4:
            result["risk_level"] = "HIGH"
        elif result["risk_score"] >= 0.2:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "LOW"


# ============================================================================
# MAIN HEADER ANALYZER
# ============================================================================

class HeaderAnalyzer:
    """
    Email header analyzer with enhanced WHOIS and VirusTotal integration
    
    Features:
    - Domain mismatch detection
    - Multi-language spam keyword detection
    - Multi-factor domain reputation analysis
    - VirusTotal threat intelligence for young domains
    """
    
    def __init__(self, language: str = "en", 
                 check_whois: bool = True,
                 check_virustotal: bool = True,
                 virustotal_api_key: Optional[str] = None):
        """
        Initialize analyzer
        
        Args:
            language: Language for keyword detection
            check_whois: Enable WHOIS analysis
            check_virustotal: Enable VirusTotal checking
            virustotal_api_key: VirusTotal API key (optional)
        """
        self.language = language
        self.check_whois = check_whois and WHOIS_AVAILABLE
        self.check_virustotal = check_virustotal
        self.whois_analyzer = EnhancedWhoisAnalyzer(
            virustotal_api_key=virustotal_api_key,
            check_virustotal_for_young_domains=check_virustotal
        ) if self.check_whois else None
    
    def analyze(self, file_path: str) -> dict:
        """
        Analyze email for phishing and security issues
        
        Args:
            file_path: Path to .eml email file
            
        Returns:
            Dictionary with analysis results
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found at path: {file_path}"}
        
        try:
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=default).parse(f)

            from_header = msg.get('From', 'Not found')
            return_path = msg.get('Return-Path', 'Not found')
            subject = msg.get('Subject', 'Not found')

            red_flags = []

            from_domain = self._extract_domain(from_header)
            return_domain = self._extract_domain(return_path)

            # Domain mismatch check
            if from_domain != return_domain and return_domain != 'Not found':
                red_flags.append(f"⚠️ Domain mismatch: From={from_domain}, Return-Path={return_domain}")
            
            # Subject keyword check
            subject_lower = subject.lower()
            subject_warnings = self._check_subject_keywords(subject_lower)
            red_flags.extend(subject_warnings)

            # Build result
            result = {
                'from': from_header,
                'return_path': return_path,
                'subject': subject,
                'red_flags': red_flags,
                'risk_level': self._calculate_risk_level(len(red_flags))
            }
            
            # Enhanced WHOIS analysis with VirusTotal
            if self.check_whois and from_domain != 'Unknown':
                whois_result = self.whois_analyzer.analyze_domain(from_domain)
                result['whois_analysis'] = whois_result
                
                # Add risk factors to red flags
                for factor in whois_result['risk_factors']:
                    if 'age:' in factor:
                        age = factor.replace('age:', '').replace('days', '')
                        red_flags.append(f"⚠️ Domain age: {age} old")
                    elif factor == "very_new_domain":
                        red_flags.append(f"🚨 Domain VERY NEW (< 7 days) - HIGH RISK")
                    elif factor == "new_domain":
                        red_flags.append(f"⚠️ Domain very new (7-30 days)")
                    elif factor == "young_domain":
                        red_flags.append(f"⚠️ Domain young (< 1 year)")
                    elif factor == "malicious_registrar":
                        red_flags.append(f"⚠️ Suspicious registrar: {whois_result['registrar']}")
                    elif factor == "privacy_protected":
                        red_flags.append(f"⚠️ WHOIS privacy protection enabled")
                    elif 'vt_malicious' in factor:
                        count = factor.split(':')[1]
                        red_flags.append(f"🚨 VirusTotal: {count} engines flagged as MALICIOUS")
                    elif 'vt_suspicious' in factor:
                        count = factor.split(':')[1]
                        red_flags.append(f"⚠️ VirusTotal: {count} engines flagged as suspicious")
                
                # Update risk level based on WHOIS analysis
                if whois_result['risk_level'] == 'CRITICAL':
                    result['risk_level'] = 'HIGH'
                elif whois_result['risk_level'] == 'HIGH' and result['risk_level'] != 'HIGH':
                    result['risk_level'] = 'MEDIUM'
            
            return result
        
        except Exception as e:
            return {"error": f"Failed to parse EML: {str(e)}"}
    
    def _check_subject_keywords(self, subject_lower: str) -> List[str]:
        """Check subject for suspicious keywords"""
        warnings = []
        
        # Universal patterns
        universal_matches = SpamKeywordDetector.detect_universal_patterns(subject_lower)
        if universal_matches:
            matches_str = "', '".join(set(universal_matches))
            warnings.append(f"⚠️ Universal urgency indicators found: '{matches_str}'")
        
        # Language-specific keywords
        language_matches = SpamKeywordDetector.detect_language_keywords(subject_lower, self.language)
        if language_matches:
            matches_str = "', '".join(set(language_matches))
            warnings.append(f"⚠️ Suspicious words ({self.language}): '{matches_str}'")
        
        return warnings
    
    @staticmethod
    def _extract_domain(email_str: str) -> str:
        """Extract domain from email address"""
        match = re.search(r'@([^\s>]+)', email_str)
        return match.group(1).rstrip('.') if match else 'Unknown'
    
    @staticmethod
    def _calculate_risk_level(red_flag_count: int) -> str:
        """Calculate risk level"""
        if red_flag_count > 2:
            return 'HIGH'
        elif red_flag_count > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
