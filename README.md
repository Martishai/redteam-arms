# Red Team agentique - ARMS

Atelier « Conformité et Finance Agentique » (EPITA). Une Red Team de 5 agents IA (framework **Agno**, modèle local **Ollama**) teste ARMS, un système **fictif** de surveillance des risques soumis à DORA, MiCA et à l'AI Act. Aucune attaque réelle : ARMS est simulé en Python.

## Architecture

```
            data/arms_architecture.json
                       │
              [1] Reconnaissance ──► carte des surfaces d'attaque
                       │
        arms_simulator.py (réaction d'ARMS : scores, règles LCB-FT, détection)
                 ┌─────┴─────┐
         [2] Attaquant   [3] IA Adversaire
                 └─────┬─────┘
             [4] Compliance Breaker ──► écarts DORA / MiCA / AI Act / RGPD
                       │
          [5] Impact & Risk Scoring ──► score 0-1, priorités, recommandations
```

- Le **simulateur** est déterministe : il fournit les faits (transactions détectées ou non, montants, score de risque). Les agents raisonnent dessus, ce qui évite les chiffres inventés par le LLM.
- Chaque agent reçoit des **skills GRC du repo epitalab** (ex. `ict-third-party-register`, `ai-act-risk-classification`, `business-impact-analysis`).

## Scénarios

| # | Type | Attaque | Point de rupture |
|---|------|---------|------------------|
| cyber | Cyber conventionnelle | Vol de la clé API du dépositaire crypto, réécriture des adresses de retrait | Réponses fournisseur non signées, flux crypto hors LCB-FT |
| ia | IA / données | Prompt injection dans les mémos → fausses étiquettes → réentraînement empoisonné → structuration 8 × 9 500 € | Étiquettes d'entraînement écrites par un agent sans contrôle humain |

## Installation (Windows)

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
ollama pull qwen3:8b
```

Optionnel : les skills GRC du repo `epitalab` enrichissent les instructions des agents. Clone-le à côté de ce projet (`..\epitalab`) ou indique son chemin : `$env:EPITALAB_SKILLS="C:\EPITA\epitalab\Skills"`. Sans lui, les agents fonctionnent avec leur seul rôle. Autre modèle : `$env:OLLAMA_MODEL="llama3.1:8b"`.

## Lancer

```powershell
streamlit run app.py                         # interface de démo
python redteam.py --scenario cyber           # en ligne de commande
python redteam.py --scenario ia --dry-run    # test de la chaîne sans LLM
```

Les rapports sont écrits dans `reports/`.

## Fichiers

- `data/arms_architecture.json` : composants, flux, fournisseurs d'ARMS
- `arms_simulator.py` : scénarios, réaction d'ARMS, score de risque
- `agents.py` : définition des 5 agents et chargement des skills
- `redteam.py` : orchestration et rapport
- `app.py` : interface Streamlit

## Score de risque

Score 0-1 calculé dans `arms_simulator.py` (pas par le LLM) : financier 40 % (montant détourné / 100 000 €), réglementaire 35 % (gravité 0-3 par texte, divisée par 9), réputation 25 % (1.0 si l'attaque est restée silencieuse). Cyber : **0.74 (Élevé)**, IA : **0.79 (Élevé)**.

Note AI Act : le moteur de détection de fraude n'est pas un système à haut risque (la détection de fraude financière est exclue de l'annexe III). Les écarts AI Act relevés sont donc des bonnes pratiques de supervision et de traçabilité, pas des obligations.

## Livrables

- Vidéo de démo : LIEN_VIDEO
- Slides : LIEN_SLIDES