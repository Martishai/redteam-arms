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

Le repo `epitalab` doit être cloné à côté de ce projet (`..\epitalab`), ou indiquer son chemin : `$env:EPITALAB_SKILLS="C:\EPITA\epitalab\Skills"`. Autre modèle : `$env:OLLAMA_MODEL="llama3.1:8b"`.

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
