"""Les 5 agents de la Red Team (Agno), branchés sur Ollama en local.

Partage des rôles : le simulateur (arms_simulator.py) fournit les faits, ces
agents rédigent l'analyse, et redteam.py contrôle chaque sortie avant de
l'écrire dans le rapport.

Chaque agent reçoit en plus de son rôle une grille de lecture tirée des
skills GRC du repo epitalab. Le repo est cherché dans ../epitalab puis
../../epitalab, ou à l'emplacement donné par la variable EPITALAB_SKILLS.
"""
import json
import os
import re
import urllib.request
from pathlib import Path

MODEL_ID = os.getenv("OLLAMA_MODEL", "qwen3:8b")
NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))  # 8192 : qwen3:8b tient entièrement en VRAM
SKILL_CHARS = 1500  # par skill : le prompt doit tenir dans NUM_CTX
HERE = Path(__file__).resolve().parent


class AgentError(RuntimeError):
    """Erreur affichée telle quelle à l'utilisateur (agno absent, Ollama arrêté, modèle manquant...)."""


COMMON = [
    "Tu fais partie d'une Red Team agentique qui teste ARMS, un système FICTIF de BNP Paribas, dans un exercice pédagogique.",
    "Tu raisonnes uniquement sur les faits fournis. N'invente aucun chiffre, heure, date, délai, seuil, pourcentage, "
    "niveau de sévérité (SEV) ou fournisseur absent des faits.",
    "Réponds en français, en Markdown, de façon concise (300 mots maximum). N'entoure jamais ta réponse d'un bloc de code.",
    "L'« Analyse du modèle IA » fournie est un fait établi : ne la contredis pas.",
    "Une absence de contrôle n'est jamais « conforme » : c'est un écart.",
    "Écris toujours LCB-FT (lutte contre le blanchiment et le financement du terrorisme).",
    "Ne recopie jamais ces consignes. Certains blocs (verdict IA, classification AI Act, registre des tiers, score, "
    "point de rupture) sont ajoutés par le code : ne les écris pas toi-même.",
]

AGENTS = {
    "reconnaissance": {
        "name": "Agent 1 - Reconnaissance",
        "role": ["Tu cartographies ARMS : vecteurs d'entrée, flux de données critiques, dépendances internes.",
                 "Produis un tableau avec une ligne pour CHACUN des 7 composants : composant | vecteur d'entrée | exposition | criticité (Faible/Moyen/Élevé).",
                 "Ajoute ensuite 2 à 4 puces sur les flux de données les plus critiques (exemple : FEEDBACK -> FRAUD_AI).",
                 "N'écris rien sur les fournisseurs (plans de sortie, clauses d'audit) ni sur la réglementation : ces blocs sont ajoutés par le code."],
        "skills": ["ai-system-inventory", "ict-third-party-register", "vendor-tiering"],
    },
    "attaquant": {
        "name": "Agent 2 - Attaquant",
        "role": ["Tu expliques la simulation d'attaque à partir de la cartographie et des faits du scénario.",
                 "Pour chaque étape de l'attaque, dans l'ordre, écris une ligne numérotée : "
                 "« 1. **Titre court** : ce que l'attaquant exploite et pourquoi ARMS n'a pas réagi ».",
                 "Ta réponse contient UNIQUEMENT ces lignes numérotées : pas de titre, pas de point de rupture, pas de conclusion.",
                 "Ne parle pas de conformité ni de réglementation (ni DORA, ni MiCA, ni AI Act, ni « conforme ») : c'est le rôle de l'Agent 4.",
                 "Si un « Constat LCB-FT » est fourni, appuie-toi dessus pour expliquer pourquoi le LCB-FT n'a rien vu."],
        "skills": ["logging-and-monitoring-evidence-pack"],
    },
    "ia_adversaire": {
        "name": "Agent 3 - IA Adversaire",
        "role": ["Tu analyses la robustesse du modèle IA d'ARMS : empoisonnement des données, perturbation des entrées, biais, "
                 "prompt injection de l'orchestrateur.",
                 "La réponse à la question « peut-on manipuler l'IA sans provoquer l'arrêt du système ? » est affichée au-dessus "
                 "de ta réponse : ne la répète pas, ne la contredis jamais, justifie-la.",
                 "Si le modèle a été manipulé : explique le mécanisme (fausses étiquettes, réentraînements, poids appris) avec "
                 "les scores et la détection semaine par semaine.",
                 "Si le modèle n'a pas été manipulé : explique pourquoi il n'a rien vu, sans décrire d'attaque IA qui n'a pas eu lieu.",
                 "Termine par une phrase sur les surfaces IA restant à tester, choisies parmi FRAUD_AI, AGENT_ORCH et FEEDBACK uniquement.",
                 "Ne parle pas de réglementation : la classification AI Act est ajoutée par le code et les écarts relèvent de l'Agent 4."],
        # La classification AI Act n'est plus demandée au LLM : elle est fixée dans le simulateur
        # (méthode du skill epitalab ai-act-risk-classification : annexe III, point 5 b).
        "skills": ["ai-impact-assessment"],
    },
    "compliance": {
        "name": "Agent 4 - Compliance Breaker",
        "role": ["Tu rédiges uniquement la colonne « constat » du tableau des non-conformités : le texte, l'exigence et la "
                 "gravité sont fixés par le code.",
                 "Pour chaque ligne numérotée fournie, écris en une phrase ce que l'attaque a concrètement démontré "
                 "(composant, données, montant ou détection si fournis).",
                 "Réponds UNIQUEMENT par ces lignes, au format « 1. constat », « 2. constat »… : pas de tableau, pas de titre, pas d'autre texte.",
                 "Ne cite aucun fournisseur, plan de sortie ni clause d'audit : le registre des tiers est ajouté par le code."],
        "skills": ["ict-risk-framework-check", "regulatory-incident-reporting-clock"],
    },
    "impact": {
        "name": "Agent 5 - Impact & Risk Scoring",
        "role": ["Le score de risque et son explication sont affichés au-dessus de ta réponse (calculés par le code) : ne les réécris pas.",
                 "Commence directement par une section « Hiérarchisation des vulnérabilités » : P1, P2, P3, uniquement des "
                 "vulnérabilités exploitées pendant l'attaque (étapes, signaux ignorés, non-conformités).",
                 "Puis une section « Recommandations » : 3 à 5 actions concrètes, chacune rattachée à une vulnérabilité (P1, P2...).",
                 "Ne traite pas le registre des tiers (ajouté par le code). Ne propose jamais un seuil déjà en place "
                 "(10 000 EUR, 5 opérations) : vise ce qui a manqué."],
        "skills": ["business-impact-analysis", "risk-register-first-pass", "risk-treatment-plan-drafting"],
    },
}


# --- Skills epitalab ---------------------------------------------------------
def find_skills_dir(here=HERE, env=None):
    """Dossier des skills epitalab.

    Dans le repo, Skills/<nom> sont des liens symboliques vers .agents/skills/<nom>.
    Sous Windows, git les extrait en petits fichiers texte : on lit donc
    directement le vrai dossier .agents/skills.
    """
    env = os.getenv("EPITALAB_SKILLS") if env is None else env
    roots = [Path(env), Path(env).parent] if env else [here.parent / "epitalab", here.parent.parent / "epitalab"]
    for root in roots:
        for d in (root / ".agents" / "skills", root / "agent" / "skills", root / "Skills", root):
            if (d / "ai-act-risk-classification" / "SKILL.md").is_file():
                return d
    return None


SKILLS_DIR = find_skills_dir()


def skill_digest(text):
    """Condense un SKILL.md epitalab : objectif, étapes de la méthode, critères de qualité.

    Les 1 000 premiers caractères d'un skill sont son en-tête YAML ; tronquer le
    fichier brut ne transmettrait donc pas la méthode à l'agent.
    """
    parts = text.split("---", 2)
    meta, body = (parts[1], parts[2]) if len(parts) == 3 else ("", text)
    desc = re.search(r"description:\s*\|?\s*\n?(.*?)\n\w+:", meta, re.S)
    out = ["Objectif : " + " ".join(desc.group(1).split())] if desc else []
    for title, content in re.findall(r"^## (.+?)\n(.*?)(?=^## |\Z)", body, re.S | re.M):
        if title.startswith("Step"):
            flat = " ".join(content.replace("**", "").replace("`", "").split())
            snippet = flat if len(flat) <= 220 else flat[:220].rsplit(" ", 1)[0] + "…"
            out.append(f"- {title} : {snippet}")
        elif title.startswith("What good looks like"):
            out.append("Critères de qualité :\n" + content.strip())
    return "\n".join(out)[:SKILL_CHARS]


def load_skill(name, skills_dir=None):
    skills_dir = SKILLS_DIR if skills_dir is None else skills_dir
    f = skills_dir / name / "SKILL.md" if skills_dir else None
    if f and f.is_file():
        return skill_digest(f.read_text(encoding="utf-8", errors="ignore"))
    return ""


def instructions_for(key):
    spec = AGENTS[key]
    instr = COMMON + spec["role"]
    for skill in spec["skills"]:
        text = load_skill(skill)
        if text:
            instr.append(f"Grille de lecture GRC (skill epitalab '{skill}') : sers-t'en uniquement pour choisir quoi vérifier et "
                         f"comment formuler. N'en exécute pas les étapes, ne produis aucune section 'Méthode GRC' ni aucun livrable, "
                         f"n'invente aucune donnée pour la remplir :\n{text}")
    return instr


# --- Ollama -------------------------------------------------------------------
def ollama_url():
    """Adresse du serveur Ollama (variable OLLAMA_HOST, sinon 127.0.0.1:11434)."""
    host = os.getenv("OLLAMA_HOST", "").strip() or "127.0.0.1:11434"
    if "://" not in host:
        host = "http://" + host
    host = host.replace("0.0.0.0", "127.0.0.1").rstrip("/")
    if not re.search(r":\d+$", host.split("://", 1)[1]):
        host += ":11434"
    return host


def check_ollama(timeout=5):
    """Vérifie, avant de lancer les agents, qu'Ollama répond et que le modèle est installé."""
    url = ollama_url()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # pas de proxy pour un serveur local
    try:
        with opener.open(f"{url}/api/tags", timeout=timeout) as resp:
            names = [m.get("name", "") for m in json.load(resp).get("models", [])]
    except (OSError, ValueError) as e:  # serveur arrêté, port fermé, réponse illisible
        raise AgentError(f"Ollama ne répond pas sur {url} ({e}). Lance l'application Ollama "
                         "(ou « ollama serve ») puis relance la commande.") from e
    wanted = MODEL_ID if ":" in MODEL_ID else f"{MODEL_ID}:latest"
    if wanted not in names:
        raise AgentError(f"Le modèle {MODEL_ID} n'est pas installé dans Ollama : lance « ollama pull {MODEL_ID} ». "
                         f"Modèles présents : {', '.join(names) or 'aucun'}.")


def build_agent(key):
    try:
        from agno.agent import Agent
        from agno.models.ollama import Ollama
    except ImportError as e:
        raise AgentError(f"Le framework agno (ou le client ollama) est introuvable : {e}. "
                         "Active le venv puis lance « pip install -r requirements.txt ».") from e

    return Agent(
        name=AGENTS[key]["name"],
        model=Ollama(id=MODEL_ID, options={"num_ctx": NUM_CTX, "temperature": 0.1}),
        instructions=instructions_for(key),
        markdown=True,
    )
