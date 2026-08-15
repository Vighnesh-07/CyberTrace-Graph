"""
Synthetic Data Generator for CyberTrace-Graph ML Models.

Generates statistically realistic network traffic and domain name data
for training the DGA classifier and Isolation Forest anomaly detector.
All data is procedurally generated — no external datasets required.
"""

import math
import random
import string
from typing import List, Dict, Any


class SyntheticDataGenerator:
    """
    A procedural synthetic data generator for training ML models in a cybersecurity SIEM pipeline.
    """

    def __init__(self, seed: int = 42):
        """
        Initialize the synthetic data generator with a random seed for reproducibility.

        Args:
            seed (int): The random seed. Defaults to 42.
        """
        random.seed(seed)
        self.common_tlds = [".com", ".org", ".net", ".io", ".edu", ".gov", ".co.uk"]
        self.dga_tlds = [".xyz", ".top", ".click", ".info", ".biz", ".pw", ".tk", ".cc"]
        self.words = [
            'cloud', 'tech', 'shop', 'web', 'data', 'app', 'dev', 'net', 'digital', 'smart',
            'fast', 'blue', 'green', 'red', 'star', 'sky', 'hub', 'lab', 'works', 'soft',
            'link', 'flow', 'pro', 'core', 'edge', 'byte', 'code', 'pixel', 'cyber', 'mind',
            'wave', 'spark', 'forge', 'grid'
        ]
        self.subdomains = ["www.", "mail.", "api.", "cdn.", "blog.", "docs.", "auth.", "status.", ""]

    def generate_benign_domains(self, count: int = 5000) -> List[str]:
        """
        Generate realistic benign domains.

        Args:
            count (int): Number of domains to generate.

        Returns:
            List[str]: List of benign domain names.
        """
        domains = []
        for _ in range(count):
            tld = random.choice(self.common_tlds)
            subdomain = random.choice(self.subdomains)
            
            # Combine 1-3 words
            num_words = random.randint(1, 3)
            domain_parts = random.choices(self.words, k=num_words)
            
            # Maybe add a number or hyphen
            if random.random() < 0.2:
                domain_parts.append(str(random.randint(1, 99)))
            
            domain_name = "".join(domain_parts)
            
            if random.random() < 0.1 and len(domain_parts) > 1:
                domain_name = "-".join(domain_parts)
                
            # Ensure typical lengths (roughly 5-25 chars)
            while len(domain_name) < 4:
                domain_name += random.choice(self.words)
                
            domain = f"{subdomain}{domain_name}{tld}"
            domains.append(domain)
        return domains

    def generate_dga_domains(self, count: int = 5000) -> List[str]:
        """
        Generate realistic DGA domains mimicking real malware.

        Args:
            count (int): Number of DGA domains to generate.

        Returns:
            List[str]: List of DGA domain names.
        """
        domains = []
        for _ in range(count):
            dga_type = random.choice(["random", "wordlist", "hex", "consonant-vowel"])
            tld = random.choice(self.dga_tlds)
            
            if dga_type == "random":
                length = random.randint(12, 30)
                domain_name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
                
            elif dga_type == "wordlist":
                num_words = random.randint(2, 4)
                domain_name = "".join(random.choices(self.words, k=num_words))
                
            elif dga_type == "hex":
                length = random.randint(10, 20)
                domain_name = "".join(random.choices(string.hexdigits.lower(), k=length))
                
            elif dga_type == "consonant-vowel":
                consonants = "bcdfghjklmnpqrstvwxyz"
                vowels = "aeiou"
                length = random.randint(6, 15)
                domain_name = ""
                for i in range(length):
                    if i % 2 == 0:
                        domain_name += random.choice(consonants)
                    else:
                        domain_name += random.choice(vowels)
            
            domain = f"{domain_name}{tld}"
            domains.append(domain)
        return domains

    def _lognormal_sample(self, median: float, std_dev: float = 0.5) -> float:
        """Helper to generate a lognormal sample with a target median."""
        mu = math.log(median)
        return random.lognormvariate(mu, std_dev)

    def generate_normal_traffic(self, count: int = 10000) -> List[Dict[str, Any]]:
        """
        Generate realistic normal network traffic feature vectors.

        Args:
            count (int): Number of feature vectors to generate.

        Returns:
            List[Dict[str, Any]]: List of normal traffic feature vectors.
        """
        traffic = []
        for _ in range(count):
            bytes_sent = max(50, min(5000, int(self._lognormal_sample(500, 0.8))))
            bytes_received = max(100, min(50000, int(self._lognormal_sample(2000, 1.0))))
            duration = max(0.1, min(120.0, self._lognormal_sample(5.0, 0.6)))
            
            # Packet count correlated with duration and bytes
            packet_count = max(10, min(500, int((bytes_sent + bytes_received) / 500 + duration * 2)))
            
            unique_dns_queries = random.randint(1, 10)
            avg_payload_size = random.randint(100, 1500)
            
            traffic.append({
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'duration_seconds': duration,
                'packet_count': packet_count,
                'unique_dns_queries': unique_dns_queries,
                'avg_payload_size': avg_payload_size
            })
        return traffic

    def generate_anomalous_traffic(self, count: int = 500) -> List[Dict[str, Any]]:
        """
        Generate anomalous traffic feature vectors.

        Args:
            count (int): Number of anomalous feature vectors to generate.

        Returns:
            List[Dict[str, Any]]: List of anomalous traffic feature vectors.
        """
        traffic = []
        for _ in range(count):
            anomaly_type = random.choice(["exfil", "c2", "scan", "dns"])
            
            if anomaly_type == "exfil":
                bytes_sent = random.randint(50000, 500000)
                bytes_received = random.randint(100, 5000)
                duration = random.uniform(60, 3600)
                packet_count = int(bytes_sent / 1000)
                unique_dns_queries = random.randint(1, 5)
                avg_payload_size = random.randint(1000, 1500)
                
            elif anomaly_type == "c2":
                bytes_sent = random.randint(50, 200)
                bytes_received = random.randint(50, 200)
                duration = random.uniform(0.1, 5.0)
                packet_count = random.randint(2, 10)
                unique_dns_queries = 1
                avg_payload_size = random.randint(10, 50)
                
            elif anomaly_type == "scan":
                bytes_sent = random.randint(1000, 5000)
                bytes_received = random.randint(0, 500)
                duration = random.uniform(0.1, 10.0)
                packet_count = random.randint(1000, 5000)
                unique_dns_queries = random.randint(0, 2)
                avg_payload_size = int(bytes_sent / packet_count) if packet_count > 0 else 0
                
            elif anomaly_type == "dns":
                bytes_sent = random.randint(5000, 20000)
                bytes_received = random.randint(5000, 20000)
                duration = random.uniform(10, 300)
                packet_count = random.randint(100, 500)
                unique_dns_queries = random.randint(50, 500)
                avg_payload_size = random.randint(50, 150)
                
            traffic.append({
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'duration_seconds': duration,
                'packet_count': packet_count,
                'unique_dns_queries': unique_dns_queries,
                'avg_payload_size': avg_payload_size
            })
        return traffic
