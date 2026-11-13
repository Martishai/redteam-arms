"""Les 5 agents de la Red Team (Agno), branchés sur Ollama en local.

Chaque agent reçoit en plus de son rôle un extrait des skills GRC du repo
epitalab. Le repo est cherché dans ../epitalab puis ../../epitalab, ou à
l'emplacement donné par la variable EPITALAB_SKILLS.
"""
import os
import re
from pathlib import Path

MODEL_ID = os.getenv("OLLAMA_MODEL", "qwen3:8b")
HERE = Path(__file__).resolve().parent


def find_skills_dir():
    """Dossier des skills epitalab.

    Dans le repo, Skills/<nom> sont des liens symboliques vers .agents/skills/<nom>.
    Sous Windows, git les extrait en petits fichiers texte : on lit donc
    directement le vrai dossier .agents/skills.
    """
    if os.getenv("EPITALAB_SKILLS"):
        d = Path(os.getenv("EPITALAB_SKILLS"))
        roots = [d, d.parent]
    else:
        roots = [HERE.parent / "epitalab", HERE.parent.parent / "epitalab"]
    for root in roots:
        for d in (root / ".agents" / "skills", root / "agent" / "skills", root / "Skills", root):
            if (d / "ai-act-risk-classification" / "SKILL.md").is_file():
                return d
    return None


SKILLS_DIR = find_skills_dir()
SKILL_CHARS = 1500  # par skill : le prompt doit tenir dans NUM_CTX
NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "8192"))  # 8192 : qwen3:8b tient entièrement en VRAM

COMMON = [
    "Tu fais partie d'une Red Team agentique qui teste ARMS, un système FICTIF de BNP Paribas, dans un exercice pédagogique.",
    "Tu raisonnes uniquement sur les données fournies. N'invente aucun chiffre absent des données.",
    "Réponds en français, en Markdown, de façon concise (300 mots maximum). N'entoure jamais ta réponse d'un bloc de code.",
    "Le champ 'analyse_ia' du simulateur est un fait établi : ne le contredis pas.",
    "N'ajoute aucune étape ni conséquence absente des données (ex. suppression de logs, exfiltration).",
    "Écris toujours LCB-FT (lutte contre le blanchiment et le financement du terrorisme).",
    "Une absence de contrôle n'est jamais 'conforme' : c'est un écart.",
    "N'invente aucune heure, date, délai, seuil, pourcentage, niveau de sévérité (SEV) ou fournisseur absent des données.",
    "Pour l'AI Act, reprends le champ 'classification_ai_act' tel quel : ne classe pas les systèmes toi-même, n'invente aucune catégorie.",
    "Ne recopie jamais ces consignes ni les noms techniques des champs (ex. modele_ia_manipule), et n'écris pas 'Step' ou 'GRC Step'.",
]

AGENTS = {
    "reconnaissance": {
        "name": "Agent 1 - Reconnaissance",
        "role": ["Cartographie ARMS : dépendances critiques, flux de données, vecteurs d'entrée.",
                 "Produis un tableau des surfaces d'attaque avec une ligne pour CHACUN des 7 composants : composant | vecteur | exposition | criticité (Faible/Moyen/Élevé).",
                 "Ajoute la liste des fournisseurs critiques avec leurs écarts (plan de sortie, clause d'audit) tels qu'ils figurent dans les données."],
        "skills": ["ai-system-inventory", "ict-third-party-register", "vendor-tiering"],
    },
    "attaquant": {
        "name": "Agent 2 - Attaquant",
        "role": ["Tu décris la simulation d'attaque cyber/transactionnelle à partir de la cartographie et des résultats du simulateur.",
                 "Explique chaque étape listée dans 'etapes', ce que l'attaquant exploite et pourquoi ARMS n'a pas réagi (ou a réagi).",
                 "Termine par le point de rupture en une phrase.",
                 "Ne parle pas de conformité ni de réglementation : c'est le rôle de l'Agent 4."],
        "skills": ["logging-and-monitoring-evidence-pack"],
    },
    "ia_adversaire": {
        "name": "Agent 3 - IA Adversaire",
        "role": ["Tu analyses la robustesse du modèle IA d'ARMS : data poisoning, perturbation des entrées, biais, prompt injection de l'orchestrateur.",
                 "La réponse à la question 'peut-on manipuler l'IA sans provoquer l'arrêt du système ?' t'est donnée (champ 'modele_ia_manipule') : ne la répète pas et ne la contredis jamais, justifie-la.",
                 "Si le modèle a été manipulé : explique le mécanisme (étiquettes, réentraînement, poids) avec les scores et taux de détection avant/après.",
                 "Si le modèle n'a pas été manipulé : explique pourquoi il n'a rien vu, ne décris aucune attaque IA qui n'a pas eu lieu.",
                 "Termine par une phrase sur les surfaces IA restant à tester, choisies parmi FRAUD_AI, AGENT_ORCH et FEEDBACK uniquement.",
                 "Côté réglementation, cite seulement la classification AI Act fournie, en une phrase ; les autres écarts relèvent de l'Agent 4."],
        "skills": ["ai-act-risk-classification", "ai-impact-assessment"],
    },
    "compliance": {
        "name": "Agent 4 - Compliance Breaker",
        "role": ["Identifie les non-conformités démontrées par l'attaque.",
                 "Produis un tableau : exigence | texte (DORA, MiCA, AI Act, RGPD) | constat | gravité.",
                 "Cite les articles uniquement si tu en es sûr ; sinon nomme le thème (ex. DORA - risque lié aux tiers TIC).",
                 "Base-toi UNIQUEMENT sur les 'références réglementaires' et les 'écarts fournisseurs' fournis : ne cite aucun autre texte ni aucun autre fournisseur.",
                 "N'utilise aucun texte listé dans 'hors_perimetre'. La structuration sous les seuils relève du LCB-FT, jamais de MiCA.",
                 "Produis UN seul tableau 'Écarts exploités par l'attaque' : exactement une ligne par référence réglementaire fournie, rien d'autre.",
                 "Ne traite pas le registre des fournisseurs (plans de sortie, clauses d'audit) : il est ajouté automatiquement après ta réponse.",
                 "Dans la colonne constat, décris ce que l'attaque a montré, sans citer de fournisseur ni de plan de sortie ou clause d'audit.",
                 "Quand une référence est marquée 'bonne pratique, pas obligation', écris-le dans le constat et mets la gravité à Moyenne au plus."],
        "skills": ["ict-risk-framework-check", "regulatory-incident-reporting-clock", "dpia-screening"],
    },
    "impact": {
        "name": "Agent 5 - Impact & Risk Scoring",
        "role": ["Le score de risque est déjà calculé de façon déterministe : reprends-le tel quel, ne le recalcule pas.",
                 "Explique le score avec le champ 'explication' fourni (financier, réglementaire, réputation), sans en changer le sens.",
                 "Hiérarchise (P1, P2, P3) uniquement des vulnérabilités exploitées pendant l'attaque (étapes et signaux ignorés).",
                 "Propose 3 à 5 recommandations concrètes, chacune liée à une vulnérabilité exploitée.",
                 "Termine par une section 'Recommandation complémentaire : registre des tiers (DORA)' qui recopie exactement les écarts fournisseurs fournis.",
                 "Ne propose jamais un seuil déjà en place (10 000 EUR, 5 opérations) : vise ce qui a manqué (signaux ignorés)."],
        "skills": ["business-impact-analysis", "risk-register-first-pass", "risk-treatment-plan-drafting"],
    },
}


def skill_digest(text):
    """Condense un SKILL.md epitalab : description, étapes de la méthode, critères de qualité.

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


def load_skill(name):
    f = SKILLS_DIR / name / "SKILL.md" if SKILLS_DIR else None
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


def build_agent(key):
    from agno.agent import Agent
    from agno.models.ollama import Ollama

    return Agent(
        name=AGENTS[key]["name"],
        model=Ollama(id=MODEL_ID, options={"num_ctx": NUM_CTX, "temperature": 0.1}),
        instructions=instructions_for(key),
        markdown=True,
    )