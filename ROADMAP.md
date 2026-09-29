# 🗺️ Feuille de Route (Roadmap) — SentinelAI-CyberWatch

Ce document décrit les étapes de développement pour construire **SentinelAI-CyberWatch**, du premier script de parsing RSS jusqu'à un agent de veille autonome conteneurisé.

---

## 📌 Phase 1 : Collecteur de Flux RSS (CERT-FR & CISA)
- [ ] Initialiser la structure du package Python (`sentinel/collectors/`, `sentinel/ai/`, `sentinel/notifiers/`).
- [ ] Créer le collecteur RSS avec `feedparser` pour les flux CERT-FR :
  - `https://www.cert.ssi.gouv.fr/avis/feed/` (Avis de sécurité).
  - `https://www.cert.ssi.gouv.fr/alerte/feed/` (Alertes critiques).
- [ ] Parser les éléments essentiels : Titre, Date de publication, Lien, Contenu résumé, Références CVE.
- [ ] Mettre en place la base de données SQLite pour stocker les IDs des bulletins déjà traités (anti-doublon).

---

## 📌 Phase 2 : Connecteur NIST NVD & Extraction CVSS
- [ ] Créer le client API pour le NIST NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
- [ ] Pour chaque CVE identifiée dans les avis CERT-FR, requêter le NVD pour récupérer :
  - Le score CVSS v3.1 / v4.0 exact.
  - Le vecteur d'attaque (ex: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
  - La liste des configurations logicielles vulnérables (CPE).

---

## 📌 Phase 3 : Intégration IA Locale (Ollama)
- [ ] Mettre en place le client HTTP vers l'API locale d'Ollama (`http://localhost:11434/api/generate`).
- [ ] Concevoir le prompt système (System Prompt) spécialisé en analyse cyber :
  - *"Tu es un analyste SOC senior. Synthétise cette alerte de sécurité en français en 3 points : 1. Risque concret pour l'entreprise, 2. Comment la faille est exploitée, 3. Recommandations de patch prioritaires."*
- [ ] Gérer les erreurs (modèle non disponible, timeout) avec un mécanisme de fallback sans IA en affichant la description brute du bulletin.

---

## 📌 Phase 4 : Notificateur Discord & Telegram
- [ ] Développer le module Discord Webhook avec Rich Embeds :
  - Couleur dynamique du bandeau : Rouge vif (`#E74C3C` pour CVSS $\ge 9.0$), Orange (`#E67E22` pour CVSS $\ge 7.0$), Bleu pour avis informatif.
  - Champs structurés : Score CVSS, Logiciels affectés, Résumé généré par l'IA, Lien vers le patch.
- [ ] Ajouter une option de notification Telegram via Bot API (`sendMessage`).
- [ ] Ajouter un filtre configurable : ne notifier que les failles avec un score CVSS supérieur ou égal à un seuil défini (ex: $\ge 7.5$).

---

## 📌 Phase 5 : Automatisation & Docker
- [ ] Mettre en place une boucle de planification (`schedule` ou `apscheduler`) pour exécuter la collecte toutes les 30 ou 60 minutes.
- [ ] Créer le `Dockerfile` et le `docker-compose.yml` (avec connexion réseau automatique vers l'instance hôte Ollama).
- [ ] Ajouter une commande CLI pour forcer une vérification immédiate (`python -m sentinel --check-now`).
