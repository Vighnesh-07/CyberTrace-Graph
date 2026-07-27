from typing import Optional
from datetime import datetime, timezone
from junction_nodes.stream_processor.models.alerts import ThreatIntelMatch

class ThreatIntelService:
    """Threat intelligence feed matching service.
    
    Simulates multiple threat intel feeds with IOC matching.
    In production, would integrate with MISP, OTX, VirusTotal, etc.
    """
    
    def __init__(self):
        self._ip_iocs: dict[str, ThreatIntelMatch] = {}     # Known bad IPs
        self._domain_iocs: dict[str, ThreatIntelMatch] = {}  # Known bad domains
        self._hash_iocs: dict[str, ThreatIntelMatch] = {}    # Known bad file hashes
        self._load_simulated_feeds()
    
    def _load_simulated_feeds(self):
        """Load simulated threat intel data."""
        now = datetime.now(timezone.utc)
        
        # IPs
        ips = {
            "185.153.196.14": ("AlienVault OTX", "c2", 0.95),
            "175.45.176.1": ("EmergingThreats", "malware", 0.99),
            "45.133.192.11": ("Abuse.ch", "botnet", 0.90),
            "192.241.223.111": ("CyberTrace Internal", "scanner", 0.75),
            "203.0.113.55": ("EmergingThreats", "c2", 0.88),
            "198.51.100.12": ("AlienVault OTX", "phishing", 0.85),
            "192.0.2.200": ("Abuse.ch", "malware", 0.92),
            "93.184.216.34": ("CyberTrace Internal", "c2", 0.98),
            "103.22.200.15": ("EmergingThreats", "botnet", 0.80),
            "209.17.96.22": ("Abuse.ch", "scanner", 0.70)
        }
        for ip, (feed, t_type, conf) in ips.items():
            self._ip_iocs[ip] = ThreatIntelMatch(indicator=ip, indicator_type="ip", feed_name=feed, threat_type=t_type, confidence=conf, first_seen=now)

        # Domains
        domains = {
            "evil-c2-server.xyz": ("CyberTrace Internal", "c2", 0.99),
            "c2-tunnel.example.com": ("AlienVault OTX", "c2", 0.95),
            "beacon.c2-server.xyz": ("EmergingThreats", "c2", 0.98),
            "update-windows-service.com": ("AlienVault OTX", "phishing", 0.85),
            "secure-login-portal.net": ("Abuse.ch", "phishing", 0.90),
            "malware-dist-site.org": ("EmergingThreats", "malware", 0.95),
            "dga-xjkwq123.com": ("CyberTrace Internal", "dga", 0.90),
            "crypto-miner-pool.net": ("AlienVault OTX", "crypto_miner", 0.88),
            "banking-auth-secure.com": ("Abuse.ch", "phishing", 0.92),
            "stealth-c2-channel.xyz": ("CyberTrace Internal", "c2", 0.97),
            "download-free-software.com": ("AlienVault OTX", "malware", 0.75),
            "fake-antivirus-update.net": ("EmergingThreats", "malware", 0.89),
            "cmd-control-center.org": ("Abuse.ch", "c2", 0.96),
            "phish-target-bank.com": ("AlienVault OTX", "phishing", 0.94),
            "botnet-coordinator.net": ("EmergingThreats", "botnet", 0.93)
        }
        for dom, (feed, t_type, conf) in domains.items():
            self._domain_iocs[dom] = ThreatIntelMatch(indicator=dom, indicator_type="domain", feed_name=feed, threat_type=t_type, confidence=conf, first_seen=now)

        # Hashes
        hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": ("Abuse.ch", "malware", 0.99), # empty sha256 as example
            "8d14697fbf27fb563910c53835fa9e28f32c256a297e641e7f34c2c5c4e334a1": ("CyberTrace Internal", "ransomware", 0.98),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": ("AlienVault OTX", "trojan", 0.95),
            "0000000000000000000000000000000000000000000000000000000000000000": ("EmergingThreats", "malware", 0.90),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": ("CyberTrace Internal", "c2_payload", 0.97)
        }
        for h, (feed, t_type, conf) in hashes.items():
            self._hash_iocs[h] = ThreatIntelMatch(indicator=h, indicator_type="hash", feed_name=feed, threat_type=t_type, confidence=conf, first_seen=now)

    def check_ip(self, ip: str) -> Optional[ThreatIntelMatch]:
        """Check if an IP matches any threat intel feed."""
        return self._ip_iocs.get(ip)
    
    def check_domain(self, domain: str) -> Optional[ThreatIntelMatch]:
        """Check domain and all parent domains against feeds.
        e.g., for 'sub.evil.com', check 'sub.evil.com' then 'evil.com'
        """
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            sub_domain = '.'.join(parts[i:])
            if sub_domain in self._domain_iocs:
                return self._domain_iocs[sub_domain]
        return None
    
    def check_hash(self, file_hash: str) -> Optional[ThreatIntelMatch]:
        """Check if a file hash matches any threat intel feed."""
        return self._hash_iocs.get(file_hash)
    
    def check_event(self, event_dict: dict) -> list[ThreatIntelMatch]:
        """Check all IOC fields in an event against all feeds.
        Checks: source_ip, destination_ip, query_name (if DNS), file_hash_sha256 (if process).
        Returns list of all matches.
        """
        matches = []
        if 'source_ip' in event_dict and event_dict['source_ip']:
            m = self.check_ip(event_dict['source_ip'])
            if m: matches.append(m)
        if 'destination_ip' in event_dict and event_dict['destination_ip']:
            m = self.check_ip(event_dict['destination_ip'])
            if m: matches.append(m)
        if 'query_name' in event_dict and event_dict['query_name']:
            m = self.check_domain(event_dict['query_name'])
            if m: matches.append(m)
        if 'raw_data' in event_dict and 'file_hash_sha256' in event_dict['raw_data']:
            m = self.check_hash(event_dict['raw_data']['file_hash_sha256'])
            if m: matches.append(m)
            
        return matches
