import hashlib
from typing import Optional
from junction_nodes.stream_processor.models.alerts import GeoIPInfo

class GeoIPService:
    """GeoIP enrichment using a simulated lookup table.
    
    In production, this would use MaxMind GeoLite2 or ip-api.com.
    For our cyber range, we use a deterministic mapping.
    """
    
    KNOWN_IPS = {
        "8.8.8.8": GeoIPInfo(ip="8.8.8.8", country_code="US", country_name="United States", city="Mountain View", latitude=37.386, longitude=-122.084, asn=15169, as_org="Google LLC"),
        "1.1.1.1": GeoIPInfo(ip="1.1.1.1", country_code="AU", country_name="Australia", city="Sydney", asn=13335, as_org="Cloudflare Inc"),
        "185.153.196.14": GeoIPInfo(ip="185.153.196.14", country_code="RU", country_name="Russia", city="Moscow", asn=44342, as_org="RU-TELECOM"),
        "114.114.114.114": GeoIPInfo(ip="114.114.114.114", country_code="CN", country_name="China", city="Nanjing", asn=58466, as_org="China Telecom"),
        "175.45.176.1": GeoIPInfo(ip="175.45.176.1", country_code="KP", country_name="North Korea", city="Pyongyang", asn=131279, as_org="Ryugyong-dong"),
        "9.9.9.9": GeoIPInfo(ip="9.9.9.9", country_code="US", country_name="United States", city="Berkeley", asn=19281, as_org="Quad9"),
        "208.67.222.222": GeoIPInfo(ip="208.67.222.222", country_code="US", country_name="United States", city="San Francisco", asn=36692, as_org="OpenDNS"),
    }
    
    INTERNAL_RANGES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]
    
    SUSPICIOUS_COUNTRIES = {"RU", "CN", "KP", "IR"}

    def is_internal(self, ip: str) -> bool:
        """Check if IP is in RFC1918 private range."""
        return any(ip.startswith(prefix) for prefix in self.INTERNAL_RANGES)
    
    def lookup(self, ip: str) -> Optional[GeoIPInfo]:
        """Look up GeoIP info for an IP address.
        If unknown, generate deterministic data based on IP octets.
        """
        if not ip:
            return None
        if self.is_internal(ip):
            return None  # Internal IPs don't have GeoIP data
            
        if ip in self.KNOWN_IPS:
            return self.KNOWN_IPS[ip]
            
        # Deterministic generation for unknown IPs
        h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        
        # Simulating random countries
        countries = [
            ("US", "United States", "New York", 39.0, -74.0, 12345, "Generic ISP US"),
            ("GB", "United Kingdom", "London", 51.5, -0.1, 54321, "Generic ISP GB"),
            ("DE", "Germany", "Frankfurt", 50.1, 8.6, 11223, "Generic ISP DE"),
            ("FR", "France", "Paris", 48.8, 2.3, 33445, "Generic ISP FR"),
            ("JP", "Japan", "Tokyo", 35.6, 139.6, 55667, "Generic ISP JP"),
            ("RU", "Russia", "St Petersburg", 59.9, 30.3, 77889, "Unknown RU ISP"),
            ("BR", "Brazil", "Sao Paulo", -23.5, -46.6, 99001, "Generic ISP BR")
        ]
        
        idx = h % len(countries)
        cc, cname, city, lat, lon, asn, as_org = countries[idx]
        
        return GeoIPInfo(
            ip=ip,
            country_code=cc,
            country_name=cname,
            city=city,
            latitude=lat,
            longitude=lon,
            asn=asn,
            as_org=as_org,
            is_vpn=(h % 100 < 5),
            is_tor=(h % 1000 < 2)
        )
    
    def is_suspicious_country(self, geo: GeoIPInfo) -> bool:
        """Check if the country is in our watchlist."""
        if not geo or not geo.country_code:
            return False
        return geo.country_code in self.SUSPICIOUS_COUNTRIES
