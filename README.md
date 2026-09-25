# Mboa HoneyPot

Un projet de démonstration pour surveiller et analyser des tentatives de fraude sur des numéros factices, avec un tableau de bord local pour visualiser les événements et exporter les données.

## Objectif

Ce projet sert de prototype de honeypot défensif pour :

- capturer des tentatives simulées de fraude
- enregistrer les métadonnées sans exposer de données personnelles réelles
- analyser la langue, l’IP source, le niveau de risque et le message reçu
- visualiser les résultats dans un dashboard local
- exporter les tentatives au format CSV ou JSON

## Stack technique

- Python 3.11+
- FastAPI
- SQLite
- Uvicorn

## Fonctionnalités

- API REST pour enregistrer des tentatives simulées
- stockage local dans SQLite
- détection de langue à partir du message et des headers HTTP
- analyse de risque basée sur le contenu du message
- dashboard web local
- exports : CSV et JSON

## Installation

1. Cloner le projet

```bash
git clone https://github.com/VOTRE_UTILISATEUR/VOTRE_REPO.git
cd VOTRE_REPO
```

2. Créer un environnement virtuel

```bash
python -m venv .venv
```

3. Activer l’environnement

Windows PowerShell :

```powershell
.\.venv\Scripts\Activate.ps1
```

Windows CMD :

```cmd
.venv\Scripts\activate.bat
```

4. Installer les dépendances

```bash
pip install -r requirements.txt
```

## Lancer l’application

```bash
python main.py
```

Puis ouvrir :

- http://127.0.0.1:8000/dashboard
- http://127.0.0.1:8000/export/csv
- http://127.0.0.1:8000/export/json

## Exemple d’appel API

```bash
curl -X POST http://127.0.0.1:8000/report-scam \
  -H "Content-Type: application/json" \
  -d '{
    "numero": "237600000009",
    "message": "Veuillez confirmer votre code OTP pour le transfert MoMo"
  }'
```

## Structure du projet

```text
mboa-honeypot/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── honeypot.db
└── __pycache__/
```

## Portée du projet

Ce projet est un démonstrateur pédagogique et défensif. Il est conçu pour l’analyse de menace et la démonstration technique dans un contexte éthique, sans collecte de données réelles ni d’informations personnelles sensibles.

## Portfolio / présentation

Ce projet démontre :

- la création d’une API Python moderne
- la gestion de données avec SQLite
- le travail sur la détection de langue et de risque
- la visualisation de données dans un dashboard web
- la structuration propre d’un projet prêt à être publié sur GitHub

## Licence

Ce projet est fourni à titre de démonstration technique. Adjustez les règles selon votre usage avant de le déployer dans un environnement réel.
