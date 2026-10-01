import json
import urllib.request
from typing import Dict, Any

class Notifier:
    def __init__(self, discord_webhook_url: str = ""):
        self.webhook_url = discord_webhook_url.strip()

    def send_discord(self, advisory: Dict[str, Any]) -> bool:
        if not self.webhook_url:
            return False

        cvss = advisory.get("cvss_score", 0.0)
        # Severity color coding (Hex converted to int)
        if cvss >= 9.0:
            color = 15158332 # Critical - Red
            severity_label = "CRITIQUE"
        elif cvss >= 7.0:
            color = 15105570 # High - Orange
            severity_label = "ELEVEE"
        elif cvss >= 4.0:
            color = 16776960 # Medium - Yellow
            severity_label = "MOYENNE"
        else:
            color = 3447003  # Low / Info - Blue
            severity_label = "INFORMATIF"

        cves_text = ", ".join(advisory.get("cves", [])) or "Aucune CVE déclarée"

        embed = {
            "title": f"?? [{severity_label}] {advisory.get('title')}",
            "url": advisory.get("link"),
            "color": color,
            "fields": [
                {"name": "Score CVSS Estimé", "value": f"**{cvss:.1f} / 10**", "inline": True},
                {"name": "CVEs", "value": f"`{cves_text}`", "inline": True},
                {"name": "Date", "value": advisory.get("published_date", "N/A"), "inline": True},
                {"name": "Synthèse SOC & Remédiation", "value": advisory.get("summary", "N/A")[:1024]}
            ],
            "footer": {"text": "SentinelAI-CyberWatch ? Veille Menaces & Vulnérabilités"}
        }

        payload = json.dumps({"embeds": [embed]}).encode("utf-8")
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "SentinelAI/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status in (200, 204)
        except Exception:
            return False
