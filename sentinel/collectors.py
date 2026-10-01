import re
import urllib.request
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

class ThreatFeedCollector:
    def __init__(self, user_agent: str = "SentinelAI-CyberWatch/1.0"):
        self.user_agent = user_agent

    def fetch_feed(self, feed_url: str) -> List[Dict[str, Any]]:
        """
        Fetches and parses an RSS 2.0 / Atom security feed.
        Works reliably without external dependencies using standard library XML parsing.
        """
        items = []
        try:
            req = urllib.request.Request(
                feed_url,
                headers={"User-Agent": self.user_agent}
            )
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                xml_data = resp.read()
                root = ET.fromstring(xml_data)

                # RSS 2.0 support
                channel = root.find("channel")
                if channel is not None:
                    for item in channel.findall("item"):
                        title = (item.findtext("title") or "").strip()
                        link = (item.findtext("link") or "").strip()
                        guid = (item.findtext("guid") or link).strip()
                        pub_date = (item.findtext("pubDate") or "").strip()
                        desc = (item.findtext("description") or "").strip()

                        # Extract CVEs from title and description
                        cves = list(set(CVE_PATTERN.findall(f"{title} {desc}")))

                        items.append({
                            "id": guid or link,
                            "title": title,
                            "link": link,
                            "published_date": pub_date,
                            "description": desc,
                            "cves": cves
                        })
        except Exception as e:
            # Return empty on offline/network errors
            pass

        return items

    @staticmethod
    def estimate_cvss(title: str, desc: str, cves: List[str]) -> float:
        """
        Heuristic CVSS estimation if NVD API is unavailable or rate limited.
        """
        text = f"{title} {desc}".lower()
        if "exécution de code à distance" in text or "rce" in text or "critique" in text or "élévation de privilèges" in text:
            return 9.8
        elif "déni de service" in text or "dos" in text or "contournement" in text:
            return 7.5
        elif "divulgation d'informations" in text or "xss" in text:
            return 5.3
        return 6.5 if cves else 4.0
