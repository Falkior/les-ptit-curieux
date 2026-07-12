# Les P'tits Curieux 🔎

Outil d'audit de sécurité réseau développé dans le cadre d'un projet scolaire en cybersécurité. L'application scanne une cible (IP ou nom d'hôte), détecte les ports et services ouverts, teste les accès anonymes sur certains services d'authentification, puis produit une évaluation du risque.

> ⚠️ **Usage légal uniquement.** N'utilisez cet outil que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite. Le scan de réseaux tiers sans autorisation est illégal.

---

## Fonctionnalités

- **Scan de ports** via `nmap` (mode Rapide ou Complet avec détection de versions `-sV`).
- **Détection de la surface d'authentification** : mappe les ports ouverts vers les services connus (SSH, FTP, SMB, LDAP, RDP, MySQL, PostgreSQL, HTTP/S, etc.).
- **Tests d'accès anonyme** :
  - **SMB** — recherche de partages accessibles sans authentification (`smbclient`).
  - **FTP** — tentative de connexion anonyme (`ftplib`).
  - **LDAP** — test de bind anonyme (`ldapsearch`).
- **Évaluation du risque** : score de 0 à 100, niveau (faible / modéré / élevé) et liste de constats classés par sévérité.
- **Historique des scans** stocké en base et consultable (20 derniers).
- **Exécution conditionnelle** : les tests SMB/FTP/LDAP ne se lancent que si le port correspondant est détecté ouvert.

---

## Architecture

Deux services orchestrés par Docker Compose sur un réseau bridge dédié.

| Service    | Techno            | Port | Rôle |
|------------|-------------------|------|------|
| `backend`  | Flask (Python)    | 5000 | Moteur de scan. Embarque `nmap`, `smbclient`, `ldap-utils`, `ftp` (image Debian slim). Expose l'API `/scan`. |
| `frontend` | Django (Python)   | 8000 | Interface web + API applicative. Reçoit les requêtes, appelle le backend, persiste l'historique (SQLite). |

```
Navigateur ──► Django (8000) ──► Flask (5000) ──► nmap / smbclient / ftp / ldapsearch ──► Cible
                  │
                  └─► SQLite (historique des scans)
```

---

## Installation & lancement

Prérequis : **Docker** et **Docker Compose**.

```bash
cd les-ptit-curieux
docker compose up --build
```

Puis ouvrir l'interface : **http://localhost:8000**

Le backend est disponible sur `http://localhost:5000` (endpoint santé : `/health`).

---

## API

### Backend Flask

`POST /scan`

```json
{
  "target": "192.168.1.10",
  "ports": "22,445",
  "mode": "Complet",
  "modules": { "nmap": true, "smb": true, "ftp": true, "ldap": true }
}
```

- `target` — IP ou hostname (validé côté serveur).
- `ports` — liste optionnelle ; vide = ports par défaut selon le mode.
- `mode` — `Rapide` (`-Pn -T4 -F`) ou `Complet` (`-Pn -T4 -sV -p-`).
- `modules` — activation/désactivation des tests.

Réponse : ports ouverts, surface d'authentification, résultats SMB/FTP/LDAP, résumé et `risk_assessment`.

`GET /health` — état du service.

### Frontend Django

| Méthode | Route                       | Rôle |
|---------|-----------------------------|------|
| POST    | `/api/scan/`                | Lance un scan et l'enregistre. |
| GET     | `/api/history/`             | 20 derniers scans. |
| GET     | `/api/history/<id>/`        | Détail d'un scan. |

---

## Modes de scan

| Mode      | Arguments nmap (sans ports)     | Arguments nmap (avec ports)   |
|-----------|---------------------------------|-------------------------------|
| Rapide    | `-Pn -T4 -F`                    | `-Pn -T4 -p <ports>`          |
| Complet   | `-Pn -T4 -sV -p-`               | `-Pn -T4 -sV -p <ports>`      |

---

## Calcul du risque

Chaque constat ajoute au score :

| Constat                         | Sévérité | Points |
|---------------------------------|----------|--------|
| Accès SMB invité autorisé       | haute    | +35    |
| FTP anonyme autorisé            | haute    | +35    |
| RDP exposé (3389)               | haute    | +25    |
| Bind LDAP anonyme               | modérée  | +20    |
| SSH exposé (22)                 | modérée  | +15    |
| HTTP sans HTTPS                 | faible   | +10    |

Niveau : **faible** < 25 ≤ **modéré** < 60 ≤ **élevé** (score plafonné à 100).

---

## Structure du projet

```
les-ptit-curieux/
├── docker-compose.yml
├── backend/            # API Flask (moteur de scan)
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
└── frontend/           # Interface Django
    ├── manage.py
    ├── ptitcurieux/    # Config projet Django
    └── scanner/        # App : vues, modèles, routes
```

---

## Stack technique

- **Backend** : Flask 3, flask-cors, python-nmap ; outils système `nmap`, `smbclient`, `ldap-utils`, `ftp`.
- **Frontend** : Django 4.2, requests, SQLite.
- **Infra** : Docker, Docker Compose.

---

*Projet scolaire — cybersécurité.*
