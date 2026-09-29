# 🤖 SentinelAI-CyberWatch — Autonomous CVE & Threat Intelligence Watcher

**SentinelAI-CyberWatch** est un agent autonome de veille en cybersécurité développé en **Python** qui surveille en temps réel les flux officiels de menaces (bulletins de sécurité du **CERT-FR**, alertes critiques du **NIST NVD** et de la **CISA**), analyse leur impact à l'aide d'un grand modèle de langage local (**Ollama / Mistral / Llama 3**) sans aucun coût d'API externe, et diffuse des synthèses exploitables sur **Discord** ou **Telegram**.

---

## 🏗️ Architecture Globale

```
+-------------------------------------------------------------------------+
|                       FLUX OFFICIELS DE MENACES                         |
|   +-----------------------+  +-------------------+  +----------------+  |
|   | Bulletins CERT-FR RSS |  | NIST NVD API (CVE)|  | CISA KEV Feed  |  |
|   +-----------+-----------+  +---------+---------+  +--------+-------+  |
+---------------|------------------------|---------------------|----------+
                |                        |                     |
                +------------------------+---------------------+
                                         | Nouvelles alertes brutes
                                         v
+-------------------------------------------------------------------------+
|                      SENTINEL COLLECTOR ENGINE                          |
|  - Déduplication via base SQLite locale (évite les doublons)            |
|  - Extraction des scores CVSS, vecteurs d'attaque et logiciels affectés |
+----------------------------------------+--------------------------------+
                                         | Données non traitées
                                         v
+-------------------------------------------------------------------------+
|                       LOCAL AI INFERENCE (OLLAMA)                       |
|   +------------------------------------------------------------------+  |
|   | Modèle Local (Mistral-7B / Llama-3) via API Ollama               |  |
|   | Prompt : Synthèse claire de l'impact, gravité réelle,            |  |
|   |          vecteur d'exploitation et mesures de remédiation        |  |
|   +------------------------------------------------------------------+  |
+----------------------------------------+--------------------------------+
                                         | Briefing généré en français
                                         v
+-------------------------------------------------------------------------+
|                        DISPATCHER & NOTIFICATEURS                       |
|  +------------------------------+     +-------------------------------+ |
|  | Discord Rich Embed (Webhooks)|     | Telegram Bot Notifications    | |
|  +------------------------------+     +-------------------------------+ |
+-------------------------------------------------------------------------+
```

---

## ✨ Fonctionnalités clés

- **📡 Collecteurs de Menaces Multi-Sources :**
  - **CERT-FR :** Veille sur les avis et alertes officiels français en continu.
  - **NIST NVD :** Récupération automatique des nouvelles CVE publiées avec score de sévérité CVSS v3/v4.
  - **CISA KEV :** Surveillance du catalogue des vulnérabilités activement exploitées dans la nature (*Known Exploited Vulnerabilities*).

- **🧠 Analyseur IA 100% Local (Zéro fuite de données, Zéro coût) :**
  - Interfaçage avec **Ollama** (`mistral`, `llama3` ou `qwen2.5-coder`).
  - Traduction et vulgarisation des détails techniques complexes en un résumé clair pour les équipes de sécurité.
  - Conseils de remédiation et d'application de patchs prioritaires.

- **📬 Notifications Riches & Webhooks :**
  - Envoi de cartes d'alerte esthétiques sur **Discord** (couleur selon la sévérité : Rouge pour Critique, Orange pour Élevé).
  - Liens directs vers les bulletins officiels et détails des scores CVSS.

- **💾 Persistance & Anti-Spam :**
  - Base SQLite locale enregistrant l'empreinte (`hash`) des bulletins déjà traités pour ne jamais notifier deux fois la même alerte.

---

## 🛠️ Stack Technique

- **Langage :** Python 3.11+
- **Moteur IA :** [Ollama](https://ollama.com/) (Mistral / Llama 3)
- **Collecte Réseau :** `feedparser`, `httpx`
- **Base de données :** SQLite
- **Notifications :** Discord Webhooks API / `requests`

---

## 🚀 Démarrage Rapide

### 1. Prérequis
- Installer [Ollama](https://ollama.com/) et télécharger le modèle de votre choix :
  ```bash
  ollama pull mistral
  ```

### 2. Installation
```bash
git clone https://github.com/Clickdroit/SentinelAI-CyberWatch.git
cd SentinelAI-CyberWatch
python -m venv venv
pip install -r requirements.txt
```

### 3. Configuration
Copiez le fichier de configuration et renseignez votre webhook Discord :
```yaml
# config.yaml
discord_webhook_url: "https://discord.com/api/webhooks/..."
min_cvss_score: 7.0
poll_interval_minutes: 30
ollama_model: "mistral"
```

### 4. Lancement
```bash
python -m sentinel.main
```

---

## 📄 Licence
Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus d'informations.
