"""
SentinelAI-CyberWatch ?" Autonomous CVE & Threat Intelligence Watcher
Orchestrates RSS collection, CVSS scoring, AI synthesis, and Discord alerting.
"""

import sys
import os
import time
import yaml
import argparse
import logging
from typing import Dict, Any

from .db import SentinelDB
from .collectors import ThreatFeedCollector
from .ai import SecurityAnalystAI
from .notifiers import Notifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SentinelAI")

DEFAULT_CONFIG = {
    "discord_webhook_url": "",
    "min_cvss_score": 7.0,
    "poll_interval_minutes": 30,
    "ollama_endpoint": "http://localhost:11434",
    "ollama_model": "mistral",
    "feeds": {
        "cert_fr_alerts": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "cert_fr_avis": "https://www.cert.ssi.gouv.fr/avis/feed/"
    }
}

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data:
                return {**DEFAULT_CONFIG, **data}
    return DEFAULT_CONFIG

def run_watch_cycle(config: Dict[str, Any], db: SentinelDB, collector: ThreatFeedCollector, ai: SecurityAnalystAI, notifier: Notifier):
    logger.info("Starting Threat Intelligence scanning cycle...")
    new_alerts = 0
    min_cvss = config.get("min_cvss_score", 7.0)

    for feed_name, feed_url in config.get("feeds", {}).items():
        logger.info(f"Checking feed [{feed_name}]: {feed_url}")
        items = collector.fetch_feed(feed_url)
        for item in items:
            advisory_id = item["id"]
            if db.is_processed(advisory_id):
                continue

            cvss = collector.estimate_cvss(item["title"], item["description"], item["cves"])
            summary = ai.summarize_advisory(item["title"], item["description"], item["cves"])

            advisory_data = {
                **item,
                "cvss_score": cvss,
                "summary": summary,
                "notified": False
            }

            if cvss >= min_cvss:
                logger.warning(f"[NEW VULNERABILITY] {item['title']} (CVSS: {cvss:.1f})")
                notified = notifier.send_discord(advisory_data)
                advisory_data["notified"] = notified
            else:
                logger.info(f"[LOGGED] {item['title']} (CVSS: {cvss:.1f} < threshold)")

            db.save_advisory(advisory_data)
            new_alerts += 1

    logger.info(f"Scan cycle complete. Discovered {new_alerts} new threat advisories.")

def main():
    parser = argparse.ArgumentParser(description="SentinelAI-CyberWatch Autonomous Threat Intelligence")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--db", default="sentinel_cache.db", help="Path to SQLite cache DB")
    parser.add_argument("--once", action="store_true", help="Run a single scan cycle and exit")
    parser.add_argument("--simulate", action="store_true", help="Simulate a critical 0-day detection")
    args = parser.parse_args()

    config = load_config(args.config)
    db = SentinelDB(db_path=args.db)
    collector = ThreatFeedCollector()
    ai = SecurityAnalystAI(ollama_endpoint=config.get("ollama_endpoint", ""), model=config.get("ollama_model", "mistral"))
    notifier = Notifier(discord_webhook_url=config.get("discord_webhook_url", ""))

    if args.simulate:
        logger.info("[SIMULATION] Generating mock Critical CVE advisory...")
        sim_adv = {
            "id": "SIM-2026-0001",
            "title": "CERTFR-2026-ALE-001 : Vulnérabilité critique d'exécution de code à distance dans OpenSSH",
            "link": "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/",
            "published_date": "2026-10-01 09:00:00",
            "description": "Une vulnérabilité critique permet à un attaquant distant non authentifié d'exécuter du code arbitraire avec les privilèges root.",
            "cves": ["CVE-2026-38407"],
            "cvss_score": 9.8,
            "summary": "1. **Impact :** Prise de contrôle totale du serveur sans authentification requise.\n2. **Vecteur :** Dépassement de tampon lors du traitement initial de la négociation SSH.\n3. **Remédiation :** Mettre à jour immédiatement vers OpenSSH 9.8p1 ou désactiver l'accès SSH public."
        }
        db.save_advisory(sim_adv)
        notifier.send_discord(sim_adv)
        logger.info("[SIMULATION] Simulation successfully stored and dispatched.")
        return

    if args.once:
        run_watch_cycle(config, db, collector, ai, notifier)
        return

    interval_sec = config.get("poll_interval_minutes", 30) * 60
    logger.info(f"SentinelAI monitoring daemon started (Interval: {interval_sec}s). Press Ctrl+C to exit.")
    try:
        while True:
            run_watch_cycle(config, db, collector, ai, notifier)
            time.sleep(interval_sec)
    except KeyboardInterrupt:
        logger.info("SentinelAI shutdown gracefully.")

if __name__ == "__main__":
    main()
