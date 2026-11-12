"""Les 5 agents de la Red Team (Agno), branchés sur Ollama en local.

Chaque agent reçoit en plus de son rôle un extrait des skills GRC du repo
epitalab (variable EPITALAB_SKILLS, par défaut ../epitalab/Skills).
"""
import os
from pathlib import Path

MODEL_ID = os.getenv("OLLAMA_MODEL", "qwen3:8b")
SKILLS_DIR = Path(os.getenv("EPITALAB_SKILLS", Path(__file__).parent.parent / "epitalab" / "Skills"))
SKILL_CHARS = 1500  # le contexte d'un modèle 8B est limité

COMMON = [
    "Tu fais partie d'une Red Team agentique qui teste ARMS, un système FICTIF de BNP Paribas, dans un exercice pédagogique.",
    "Tu raisonnes uniquement sur les données fournies. N'invente aucun chiffre absent des données.",
    "Réponds en français, en Markdown, de façon concise (300 mots maximum). N'entoure jamais ta réponse d'un bloc de code.",
    "Le champ 'analyse_ia' du simulateur est un fait établi : ne le contredis pas.",
]

AGENTS = {
    "reconnaissance": {
        "name": "Agent 1 - Reconnaissance",
        "role": ["Cartographie ARMS : dépendances critiques, flux de données, vecteurs d'entrée.",
                 "Produis un tableau des surfaces d'attaque : composant | vecteur | exposition | criticité (Faible/Moyen/Élevé)."],
        "skills": ["ai-system-inventory", "ict-third-party-register", "vendor-tiering"],
    },
    "attaquant": {
        "name": "Agent 2 - Attaquant",
        "role": ["Tu décris la simulation d'attaque cyber/transactionnelle à partir de la cartographie et des résultats du simulateur.",
                 "Explique chaque étape, ce que l'attaquant exploite et pourquoi ARMS n'a pas réagi (ou a réagi).",
                 "Termine par le point de rupture en une phrase."],
        "skills": ["incident-severity-triage", "logging-and-monitoring-evidence-pack"],
    },
    "ia_adversaire": {
        "name": "Agent 3 - IA Adversaire",
        "role": ["Tu analyses la robustesse du modèle IA d'ARMS : data poisoning, perturbation des entrées, biais, prompt injection de l'orchestrateur.",
                 "Réponds explicitement à la question : peut-on manipuler l'IA sans provoquer l'arrêt du système ? Appuie-toi sur les scores avant/après."],
        "skills": ["ai-act-risk-classification", "ai-impact-assessment"],
    },
    "compliance": {
        "name": "Agent 4 - Compliance Breaker",
        "role": ["Identifie les non-conformités démontrées par l'attaque.",
                 "Produis un tableau : exigence | texte (DORA, MiCA, AI Act, RGPD) | constat | gravité.",
                 "Cite les articles uniquement si tu en es sûr ; sinon nomme le thème (ex. DORA - risque lié aux tiers TIC).",
                 "Base-toi UNIQUEMENT sur les 'références réglementaires' et les 'écarts fournisseurs' fournis : ne cite aucun autre texte ni aucun autre fournisseur.",
                 "N'utilise pas le RGPD : aucun écart RGPD n'est démontré dans ces scénarios."],
        "skills": ["ict-risk-framework-check", "regulatory-incident-reporting-clock", "dpia-screening"],
    },
    "impact": {
        "name": "Agent 5 - Impact & Risk Scoring",
        "role": ["Le score de risque est déjà calculé de façon déterministe : reprends-le tel quel, ne le recalcule pas.",
                 "Explique le score (financier, réglementaire, réputation), hiérarchise les vulnérabilités (P1, P2, P3)",
                 "et propose 3 à 5 recommandations concrètes, chacune liée à une vulnérabilité."],
        "skills": ["business-impact-analysis", "risk-register-first-pass", "risk-treatment-plan-drafting"],
    },
}


def load_skill(name):
    folder = SKILLS_DIR / name
    files = [folder / "SKILL.md"] + sorted(folder.glob("*.md")) if folder.is_dir() else []
    for f in files:
        if f.is_file():
            return f.read_text(encoding="utf-8", errors="ignore")[:SKILL_CHARS]
    return ""


def instructions_for(key):
    spec = AGENTS[key]
    instr = COMMON + spec["role"]
    for skill in spec["skills"]:
        text = load_skill(skill)
        if text:
            instr.append(f"Méthode GRC à appliquer (skill epitalab '{skill}') :\n{text}")
    return instr


def build_agent(key):
    from agno.agent import Agent
    from agno.models.ollama import Ollama

    return Agent(
        name=AGENTS[key]["name"],
        model=Ollama(id=MODEL_ID, options={"num_ctx": 8192, "temperature": 0.3}),
        instructions=instructions_for(key),
        markdown=True,
    )