# Red Team agentique - ARMS

Atelier « Conformité et Finance Agentique » (EPITA). Une Red Team de 5 agents IA (framework **Agno**, modèle local **Ollama**) teste ARMS, un système **fictif** de surveillance des risques soumis à DORA, MiCA et à l'AI Act. Aucune attaque réelle : ARMS est simulé en Python.

## Architecture

```
            data/arms_architecture.json
                       │
              [1] Reconnaissance ──► carte des surfaces d'attaque + dépendances critiques
                       │
        arms_simulator.py (réaction d'ARMS : modèle IA, règles LCB-FT, détection, gravités)
                 ┌─────┴─────┐
         [2] Attaquant   [3] IA Adversaire
                 └─────┬─────┘
             [4] Compliance Breaker ──► tableau des écarts DORA / MiCA / LCB-FT / AI Act
                       │
          [5] Impact & Risk Scoring ──► score 0-1, priorités P1-P3, choix d'un correctif
                       │
        boucle de remédiation : simulateur (correctif appliqué) ──► [2] contre-test ──► nouveau score
                       │
        redteam.py : contrôle de chaque sortie ──► reports/rapport_<scénario>.md
```

**Partage des rôles entre le code et les LLM**

- Le **simulateur** fournit tous les faits : transactions détectées ou non, montants, dérive du modèle, gravités, classification AI Act, registre des tiers, score. Tout est déterministe (graines aléatoires fixes).
- Les **agents** rédigent l'analyse : cartographie, explication des étapes, mécanisme de manipulation du modèle, constats, priorités et recommandations.
- L'**orchestrateur** (`redteam.py`) ajoute les blocs factuels lui-même et contrôle chaque sortie : il nettoie les fuites de consignes (noms de champs, « Step 2 »…) et retire les sections hors du rôle de l'agent. Chaque correction est listée à la fin du rapport (« Contrôles automatiques des sorties »).
- Chaque agent reçoit une grille de lecture tirée des **skills GRC du repo epitalab** (ex. `ict-third-party-register`, `ai-impact-assessment`, `business-impact-analysis`).

## Scénarios

| # | Type | Attaque | Point de rupture |
|---|------|---------|------------------|
| cyber | Cyber conventionnelle | Vol de la clé API du dépositaire crypto, réécriture des adresses de retrait | Réponses fournisseur non signées, flux crypto hors LCB-FT |
| ia | IA / données | Prompt injection dans les mémos → fausses étiquettes → réentraînement empoisonné → structuration 8 × 9 500 € | Étiquettes d'entraînement écrites par un agent sans contrôle humain |
| continuite | Résilience (DORA) | Saturation de l'hébergeur CloudHost EU : FRAUD_AI indisponible 6 h, ARMS continue en « fail-open » | Aucun mode dégradé ni plan de sortie pour un fournisseur critique |

## Moteur IA et empoisonnement

FRAUD_AI est une **régression logistique** (Python pur) entraînée sur 400 transactions historiques étiquetées. Dans le scénario IA, l'orchestrateur agentique, manipulé par les mémos, clôture comme « légitimes » 10 alertes « wallet nouveau » par semaine. Ces étiquettes alimentent 3 réentraînements hebdomadaires :

| Semaine | Fausses étiquettes | Poids « wallet nouveau » | Poids « montant » | Score IA des 8 virements | Détection |
|---|---|---|---|---|---|
| 0 | 0 | 3.53 | 1.97 | 0.801 | 8/8 |
| 1 | 10 | 3.19 | 1.24 | 0.665 | 8/8 |
| 2 | 20 | 3.0 | 0.75 | 0.561 | 0/8 |
| 3 | 30 | 2.88 | 0.43 | 0.486 | 0/8 |

Le modèle apprend que « wallet neuf + montant proche de 9 500 € » est normal : le score passe sous le seuil d'alerte (0,60) dès la semaine 2, sans que le système s'arrête.

**Perturbation des entrées, sans réentraînement.** Le modèle sain est aussi sondé directement :

| Variante d'un virement de l'attaque | Score IA | Détecté |
|---|---|---|
| Référence : 9 500 €, wallet neuf, 2 op/compte | 0.801 | oui |
| Montant réduit de 10 % (8 550 €) | 0.769 | oui |
| 1 seule opération par compte | 0.761 | oui |
| Plus petit montant qui passe : 4 500 € (-53 %) | 0.599 | non |
| Un seul champ falsifié : wallet présenté comme « connu » | 0.105 | non |

Le modèle résiste aux petites variations de montant ou de vélocité, mais un seul champ d'entrée falsifié l'aveugle : c'est exactement ce qu'exploite le scénario cyber (réponse API falsifiée qui garde le libellé « wallet connu »).

## Boucle de remédiation

Après son analyse, l'Agent 5 choisit, dans la liste des correctifs que le simulateur sait appliquer, celui qui traite sa priorité P1. Le simulateur rejoue le scénario avec ce correctif, recalcule la détection et le score, puis l'Agent 2 rejoue l'attaque contre ARMS corrigé (« contre-test ») et décrit ce qu'il tenterait ensuite.

| Scénario | Correctifs simulables (détection et score après correctif) |
|---|---|
| cyber | Signature des réponses API (3/3, 0.40) · Flux crypto routés vers AML_RULES (3/3, 0.44) · Alerte sur IP inconnue (3/3, 0.47) |
| ia | Validation humaine des étiquettes (8/8, 0.36) · Agrégation par réseau de comptes liés (8/8, 0.24) · Surveillance de la dérive (8/8, 0.28) |
| continuite | Mode dégradé « fail-closed » (6/6, 0.28) · Hébergement de secours (6/6, 0.32) |

## Score de risque

Score 0-1 calculé dans `arms_simulator.py` (pas par le LLM) :
- financier 40 % : montant détourné / 100 000 € ;
- réglementaire 35 % : pour chaque texte, la gravité la plus forte de ses écarts (Moyenne 1, Élevée 2, Critique 3), somme divisée par 9 ;
- réputation 25 % : 1.0 si l'attaque est restée silencieuse (argent détourné sans alerte), 0.5 sinon.

La gravité affichée dans le tableau de l'Agent 4 est exactement celle comptée dans le score.

| Scénario | Détection | Montant détourné | Score |
|---|---|---|---|
| cyber | 0/3 | 55 000 € | **0.82 (Élevé)** : DORA 3/3, MiCA 3/3, LCB-FT 3/3, RGPD 2/3 (plafonné à 1) |
| ia | 8/8 → 0/8 | 76 000 € | **0.79 (Élevé)** : LCB-FT 3/3, DORA 2/3, AI Act 1/3 |
| continuite | 1/6 (6/6 si FRAUD_AI disponible) | 40 000 € | **0.60 (Moyen)** : DORA 3/3, LCB-FT 2/3 |

Note RGPD : dans le scénario cyber, les ordres de retrait de 3 clients sont consultés et modifiés sans être détectés. C'est une violation de données personnelles (art. 32) que la banque ne peut pas notifier à la CNIL sous 72 h (art. 33). Dans les deux autres scénarios, aucune donnée personnelle n'est compromise : le RGPD y est déclaré hors périmètre, avec cette justification.

Note AI Act : le moteur de détection de fraude n'est pas un système à haut risque (la détection de fraude financière est exclue de l'annexe III, point 5 b). Les écarts AI Act relevés sont donc des bonnes pratiques de supervision et de traçabilité, pas des obligations : leur gravité est plafonnée à « Moyenne ».

## Installation (Windows)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
ollama pull qwen3:8b
```

Optionnel : les skills GRC du repo [epitalab](https://github.com/scortalabs/epitalab) enrichissent les instructions des agents. Clone-le à côté de ce projet (`..\epitalab` ou `..\..\epitalab`) ou indique son chemin : `$env:EPITALAB_SKILLS="C:\EPITA\epitalab"`. Sans lui, les agents fonctionnent avec leur seul rôle.

Variables utiles : `$env:OLLAMA_MODEL="llama3.1:8b"` (autre modèle), `$env:OLLAMA_NUM_CTX="12288"` (contexte plus grand si la carte graphique le permet), `$env:OLLAMA_HOST` (serveur Ollama distant).

## Lancer

```powershell
streamlit run app.py                         # interface de démo
python redteam.py --scenario cyber           # en ligne de commande (cyber, ia ou continuite)
python redteam.py --scenario ia --dry-run    # test de la chaîne sans LLM (rapport dans reports/dry-run/)
python -m pytest                             # tests (sans Ollama ni agno)
```

Les rapports sont écrits dans `reports/`. Si Ollama est arrêté, si le modèle n'est pas installé ou si agno manque, un message explique quoi faire.

## Fichiers

- `data/arms_architecture.json` : composants, flux, fournisseurs d'ARMS
- `arms_simulator.py` : modèle IA, empoisonnement, perturbation, 3 scénarios, correctifs, gravités, score de risque
- `agents.py` : définition des 5 agents, chargement des skills, vérification d'Ollama
- `redteam.py` : orchestration, boucle de remédiation, contrôle des sorties, rapport
- `app.py` : interface Streamlit
- `tests/` : 48 tests pytest (simulateur, correctifs, contrôle des sorties, dry-run)
- `reports/` : rapports des 3 scénarios, en Markdown et en PDF

## Livrables

- Vidéo de démo : https://youtu.be/lo6Wft4m0Ko
