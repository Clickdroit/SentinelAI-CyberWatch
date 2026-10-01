import json
import urllib.request
from typing import Dict, Any

class SecurityAnalystAI:
    def __init__(self, ollama_endpoint: str = "http://localhost:11434", model: str = "mistral"):
        self.endpoint = ollama_endpoint.rstrip("/")
        self.model = model

    def summarize_advisory(self, title: str, description: str, cves: list) -> str:
        """
        Synthesizes security alert into 3 actionable points in French.
        If Ollama is offline or uninstalled, falls back to a clean deterministic summary.
        """
        cve_str = ", ".join(cves) if cves else "Non spécifié"
        prompt = (
            f"Tu es un analyste SOC senior. Synthétise cette alerte de sécurité en français en 3 points concis :\n"
            f"1. Risque concret pour l'infrastructure\n"
            f"2. Vecteur d'attaque\n"
            f"3. Recommandations prioritaires et patch\n\n"
            f"Titre : {title}\n"
            f"Description : {description}\n"
            f"CVEs associées : {cve_str}"
        )

        try:
            req_data = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self.endpoint}/api/generate",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except Exception:
            # Fallback heuristic summary
            return (
                f"1. **Impact :** Risque potentiel d'exploitation sur les composants affectés ({cve_str}).\n"
                f"2. **Vecteur :** Faille logicielle identifiée dans le bulletin CERT-FR.\n"
                f"3. **Remédiation :** Appliquer sans délai les correctifs fournis par l'éditeur du logiciel."
            )
