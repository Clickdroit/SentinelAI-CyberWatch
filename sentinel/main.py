"""
SentinelAI-CyberWatch — Autonomous CVE & Threat Intelligence Watcher
Main runner.
"""

import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("SentinelAI")

def main():
    logger.info("Initializing SentinelAI-CyberWatch...")
    logger.info("1. Loading threat intelligence feeds (CERT-FR, NIST NVD)...")
    logger.info("2. Testing connection to local Ollama AI model...")
    logger.info("3. Ready to monitor and dispatch automated security briefs.")

if __name__ == "__main__":
    main()
