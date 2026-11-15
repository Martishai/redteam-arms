"""Orchestration de la Red Team : Reconnaissance -> Attaquant + IA Adversaire -> Compliance -> Impact,
puis boucle de remédiation : l'Agent 5 choisit un correctif, le simulateur l'applique, l'Agent 2 rejoue l'attaque.

Partage des rôles :
- arms_simulator.py fournit tous les faits (détection, montants, gravités, score) ;
- les 5 agents LLM rédigent l'analyse ;
- ce module contrôle chaque sortie (fuites de consignes, sections hors rôle) et
  ajoute lui-même les blocs factuels : verdict IA, classification AI Act,
  tableau des non-conformités, registre des tiers, score, point de rupture.
Les corrections appliquées sont listées à la fin du rapport (« Contrôles automatiques »).

Usage :
    python redteam.py --scenario cyber
    python redteam.py --scenario ia
    python redteam.py --scenario continuite
    python redteam.py --scenario cyber --dry-run   # sans LLM : teste la chaîne, rapport dans reports/dry-run/
"""
import argparse
import json
import re
import sys
from pathlib import Path

import arms_simulator as sim
from agents import AGENTS, AgentError, build_agent, check_ollama

HERE = Path(__file__).resolve().parent
REPORTS = HERE / "reports"
DRY_RUN_REPORTS = REPORTS / "dry-run"


# --- Faits transmis aux agents : libellés lisibles, jamais de noms de champs ----
LABELS = {
    "titre": "Titre",
    "cible": "Composants ciblés",
    "etapes": "Étapes de l'attaque",
    "montant_detourne_eur": "Montant détourné (EUR)",
    "analyse_ia": "Analyse du modèle IA",
    "constat_lcbft": "Constat LCB-FT",
    "empoisonnement": "Dérive du modèle semaine par semaine",
    "perturbation": "Perturbation des entrées (modèle sain, sans réentraînement)",
    "detection_avec_ia": "Détection si FRAUD_AI avait été disponible",
    "signaux_ignores": "Signaux ignorés par ARMS",
}
TX_LABELS = {"cyber": "Transactions falsifiées", "continuite": "Virements pendant la panne"}


def facts(data):
    return json.dumps(data, ensure_ascii=False, indent=1)


def scenario_facts(result, keys):
    out = {LABELS[k]: result[k] for k in keys if k in result}
    if "transactions" in result:
        out[TX_LABELS.get(result["id"], "Transactions")] = sim.transactions_summary(result["transactions"])
    else:
        out["Virements avant empoisonnement"] = sim.transactions_summary(result["transactions_avant_empoisonnement"])
        out["Virements après empoisonnement"] = sim.transactions_summary(result["transactions_apres_empoisonnement"])
    return out


def architecture_facts(archi):
    """Architecture pour l'Agent 1, sans les écarts fournisseurs (ajoutés par le code)."""
    return {
        "Système": archi["system"],
        "Composants": [{"id": c["id"], "nom": c["name"], "rôle": c["role"], "exposition": c["exposure"]}
                       for c in archi["components"]],
        "Flux de données": [f"{f['from']} -> {f['to']} : {f['data']}" for f in archi["data_flows"]],
        "Fournisseurs": [f"{v['name']} : {v['service']}" for v in archi["vendors"]],
    }


# --- Contrôle des sorties LLM -----------------------------------------------------
TECH_FIELDS = {  # noms de champs du simulateur -> libellé lisible ("" = supprimé)
    "modele_ia_manipule": "", "constat_lcbft": "constat LCB-FT", "analyse_ia": "analyse du modèle IA",
    "classification_ai_act": "classification AI Act", "justification_facteurs": "justification",
    "facteurs_reglementaires": "facteurs réglementaires", "hors_perimetre": "hors périmètre",
    "references_reglementaires": "références réglementaires", "signaux_ignores": "signaux ignorés",
    "point_de_rupture": "point de rupture", "systeme_toujours_operationnel": "système opérationnel",
    "montant_detourne_eur": "montant détourné", "transactions_detectees": "transactions détectées",
    "detection_avant": "détection avant", "detection_apres": "détection après",
    "score_ia": "score IA", "alerte_ia": "alerte IA", "alertes_lcbft": "alertes LCB-FT",
    "new_wallet": "wallet nouveau", "risk_country": "pays à risque",
    "exit_plan": "plan de sortie", "contract_audit_clause": "clause d'audit",
}
FIELD = r"\b(" + "|".join(TECH_FIELDS) + r")\b"
INSTRUCTION_LEAKS = [  # (ce qui est signalé, motif, remplacement)
    ("GRC Step", r"\s*\((?:GRC\s*)?Step\s*\d+\)|\bGRC\s+Step\s*\d+\s*:?\s*", ""),
    ("Step", r"(?m)^(\s*(?:[-*]\s*)?(?:\*\*)?)Step\s*(\d+)", r"\1Étape \2"),
    ("à ne pas prêter", r"\s*\(à ne pas prêter\)|[^.\n]*sans prêter de manque[^.\n]*\.?[ \t]*", ""),
    ("fait établi", r"\s*\(faits? (?:établis?|vérifiés?)[^)]*\)", ""),
    ("RCB-FT", r"\bRCB-FT\b", "LCB-FT"),
    ("IA Act", r"\bIA Act\b", "AI Act"),
]

HEADING = re.compile(r"^\s*#{1,6}\s+(.+?)\s*#*\s*$")
# « **Titre** : texte », « **Titre :** texte » ou « **Titre** » seul. « **FRAUD_AI** ne surveille... » n'est pas un titre.
LABEL = re.compile(r"^\s*\*\*([^*]+?)\s*(:?)\s*\*\*\s*(:?)\s*(.*)$")
STEP = re.compile(r"^\s*(?:#{1,6}\s*)?(?:\*\*)?\s*(?:[ÉE]tape\s*)?\d+\s*[.)]")

OFF_ROLE = {  # titres de sections hors du rôle de l'agent (retirées)
    "reconnaissance": r"fournisseur|vendor|d[ée]pendance|registre|tiering|classification|\bai act|r[ée]glement|"
                      r"r[ée]gulation|conformit|m[ée]thode grc|analyse grc|^[ée]carts?\b|lcb|dora|mica|rgpd",
    "ia_adversaire": r"r[ée]glement|r[ée]gulation|conformit|classification|\bai act|dora|mica|rgpd|lcb|[ée]carts|"
                     r"vuln[ée]rabilit[ée]s critiques|m[ée]thode grc|impact assessment|^impact sur",
    "impact": r"score|analyse (du|de) risque|^explication|registre|fournisseur|recommandation compl[ée]mentaire|"
              r"classification|\bai act|m[ée]thode grc|\bbia\b|risk register|treatment plan|correctif",
    "contre_test": r"r[ée]glement|r[ée]gulation|conformit|dora|mica|ai act|rgpd|score|registre|recommandation",
}
REGULATIONS = r"(?:DORA|MiCA|AI Act|RGPD|LCB-FT)"
INLINE_REGULATORY = [  # Agent 2 : incises réglementaires au milieu d'une étape (retirées)
    r",?[ \t]*(?:conformément|contrairement|en violation|en infraction)\s+(?:à|au|aux|de|du|des)\s+(?:l'|la |le |les )?"
    r"(?:DORA|MiCA|AI Act|RGPD)(?:[ \t]*\([^()\n]*\))?",
    r"[ \t]*\(" + REGULATIONS + r"(?:\s*[,/;]\s*" + REGULATIONS + r")*\)",
]
ROLE_TERMS = {  # mentions qui ne devraient plus apparaître (avertissement seulement)
    "reconnaissance": r"\b(DORA|MiCA|AI Act|RGPD)\b",
    "attaquant": r"\b(DORA|MiCA|AI Act|RGPD|conformes?|non-conformités?)\b",
    "ia_adversaire": r"\b(DORA|MiCA|AI Act|RGPD)\b",
    "contre_test": r"\b(DORA|MiCA|AI Act|RGPD)\b",
}
CHOICE = re.compile(r"^.*correctif\s+(?:à|a)\s+tester\s*:?\s*\**\s*(?:n°\s*)?(\d+).*$", re.I | re.M)


def clean_leaks(text):
    """Retire les noms de champs techniques et les mots de consigne recopiés par le LLM.

    Retourne le texte nettoyé et la liste de ce qui a été retiré.
    """
    found = sorted({m.group(1) for m in re.finditer(FIELD, text)})
    text = re.sub(r"[ \t]*\([^()\n]*" + FIELD + r"[^()\n]*\)", "", text)  # « (champ `x` : false) »
    text = re.sub(r"`?" + FIELD + r"`?\s*[:=]\s*\**`?(?:true|false|vrai|faux)`?\**", "", text, flags=re.I)
    text = re.sub(r"`?" + FIELD + r"`?", lambda m: TECH_FIELDS[m.group(1)], text)
    for label, pattern, repl in INSTRUCTION_LEAKS:
        new = re.sub(pattern, repl, text)
        if new != text:
            found.append(label)
            text = new
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r"(?<=\S)[ \t]{2,}(?=\S)", " ", text)
    text = re.sub(r"[ \t]+([,.])(?=\s|$)", r"\1", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip(), found


def section_title(block):
    """Titre d'un bloc Markdown, et s'il ouvre une section (les blocs suivants en font partie)."""
    lines = block.strip().splitlines()
    m = HEADING.match(lines[0])
    if m:
        return m.group(1).strip("*: "), True
    m = LABEL.match(lines[0])
    if m and (m.group(2) or m.group(3) or not m.group(4).strip()):
        return m.group(1).strip("*: "), not m.group(4).strip() and len(lines) == 1
    return None, False


def tidy(text):
    """Supprime les séparateurs « --- » orphelins laissés par le retrait de sections."""
    out = []
    for block in (b for b in re.split(r"\n\s*\n", text) if b.strip()):
        if block.strip() in ("---", "***") and (not out or out[-1].strip() in ("---", "***")):
            continue
        out.append(block)
    while out and out[-1].strip() in ("---", "***"):
        out.pop()
    return "\n\n".join(out)


def strip_sections(text, forbidden):
    """Retire les sections dont le titre correspond au motif « forbidden »."""
    kept, removed, dropping = [], [], False
    for block in (b for b in re.split(r"\n\s*\n", text.strip()) if b.strip()):
        title, opens = section_title(block)
        if title is not None:
            dropping = False
            if not STEP.match(title) and re.search(forbidden, title, re.I):
                removed.append(title)
                dropping = opens
                continue
        elif dropping:
            continue
        kept.append(block)
    return tidy("\n\n".join(kept)), removed


def keep_numbered_steps(text):
    """Agent 2 : ne garde que les étapes numérotées et leurs lignes de suite."""
    kept, removed, in_step = [], [], False
    for line in text.strip().splitlines():
        if STEP.match(line):
            in_step = True
            kept.append(line)
        elif not line.strip():
            kept.append(line)
        elif section_title(line)[0] is not None:
            in_step = False
            removed.append(section_title(line)[0])
        elif in_step:
            kept.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip(), removed


def leak_note(name, leaks):
    """Décrit les fuites nettoyées sans les recopier dans le rapport."""
    fields = [f for f in leaks if f in TECH_FIELDS]
    others = [f for f in leaks if f not in TECH_FIELDS]
    parts = ([f"{len(fields)} nom(s) de champ technique"] if fields else []) + \
            ([f"formule(s) de consigne : {', '.join(others)}"] if others else [])
    return f"{name} : fuites nettoyées ({' ; '.join(parts)})."


def short_title(title):
    return title.split(":")[0].strip()[:60]


def review(key, text, controls, name=None):
    """Contrôle déterministe d'une sortie d'agent ; chaque correction est consignée dans « controls »."""
    name = name or AGENTS[key]["name"]
    text, leaks = clean_leaks(text)
    if leaks:
        controls.append(leak_note(name, leaks))
    removed = []
    if key == "attaquant":
        if any(STEP.match(line) for line in text.splitlines()):
            text, removed = keep_numbered_steps(text)
            total = 0
            for pattern in INLINE_REGULATORY:
                text, n = re.subn(pattern, "", text)
                total += n
            if total:
                controls.append(f"{name} : {total} incise(s) réglementaire(s) retirée(s) des étapes (rôle de l'Agent 4).")
        else:
            controls.append(f"{name} : aucune étape numérotée trouvée, sortie conservée telle quelle (à relire).")
    elif key in OFF_ROLE:
        text, removed = strip_sections(text, OFF_ROLE[key])
    controls += [f"{name} : section « {short_title(title)} » retirée (hors rôle)." for title in removed]
    if key in ROLE_TERMS:
        terms = sorted({t for t in re.findall(ROLE_TERMS[key], text, re.I)})
        if terms:
            controls.append(f"{name} : mention(s) hors rôle restante(s), à relire : {', '.join(terms)}.")
    if not text.strip():
        controls.append(f"{name} : sortie vide après contrôle.")
        text = "*Sortie vide après contrôle : voir « Contrôles automatiques ».*"
    return text


def parse_findings(text, n):
    """Lit les lignes « 1. constat » de l'Agent 4 ; None pour une ligne absente.

    Repli si aucune ligne n'est numérotée : colonne « constat » d'un tableau Markdown,
    ou liste à puces d'exactement n éléments, lues dans l'ordre.
    """
    found = {}
    gravities = {g.lower() for g in sim.GRAVITES}
    for line in text.splitlines():
        m = re.match(r"^\s*[-*|]?\s*\**\s*(\d+)\s*\**\s*[.):|-]\s*(.+?)\s*\|?\s*$", line)
        if not m or not 1 <= int(m.group(1)) <= n or int(m.group(1)) in found:
            continue
        cells = [c.replace("**", "").strip(" *") for c in m.group(2).split("|")]  # tableau recopié : dernière cellule utile
        cells = [re.sub(r"^constat\s*:\s*", "", c, flags=re.I) for c in cells if c and c.lower() not in gravities]
        if cells and cells[-1]:
            found[int(m.group(1))] = cells[-1].replace("**", "")
    if found:
        return [found.get(i + 1) for i in range(n)]
    rows = [[c.strip(" *") for c in line.strip().strip("|").split("|")]
            for line in text.splitlines() if line.strip().startswith("|")]
    header = next((r for r in rows if any(c.lower().startswith("constat") for c in r)), None)
    if header:
        col = next(i for i, c in enumerate(header) if c.lower().startswith("constat"))
        values = [r[col] for r in rows if r is not header and len(r) > col and not set("".join(r)) <= set("-: ")]
    else:
        values = [re.sub(r"^\s*[-*]\s+", "", line).strip() for line in text.splitlines() if re.match(r"^\s*[-*]\s+\S", line)]
        values = values if len(values) == n else []
    values = [v.replace("**", "") or None for v in values]
    return (values + [None] * n)[:n]


# --- Blocs factuels produits par le code -------------------------------------------
def cell(text):
    return " ".join(str(text).replace("|", "/").split())


def dependencies_block(archi):
    lines = ["**Dépendances critiques (registre des tiers, calculé depuis les données)**", ""]
    for v in archi["vendors"]:
        missing = [label for key, label in (("exit_plan", "plan de sortie"), ("contract_audit_clause", "clause d'audit"))
                   if not v[key]]
        status = f"manque {', '.join(missing)}" if missing else "aucun écart"
        lines.append(f"- {v['name']} ({'critique' if v['critical'] else 'non critique'}) - {v['service']} : {status}")
    return "\n".join(lines)


def findings_table(result, constats):
    rows = ["| # | Texte | Exigence | Constat | Gravité |", "|---|---|---|---|---|"]
    for i, (ref, constat) in enumerate(zip(result["references"], constats), 1):
        gravity = ref["gravite"]
        if not ref["obligation"]:  # bonne pratique : gravité plafonnée à « Moyenne » par le simulateur
            capped = f" ; plafonnée, {ref['gravite_brute']} sinon" if ref["gravite"] != ref["gravite_brute"] else ""
            gravity += f" (bonne pratique, pas obligation{capped})"
        rows.append(f"| {i} | {ref['texte']} | {cell(ref['exigence'])} | {cell(constat)} | {gravity} |")
    return "\n".join(rows)


def vendor_table(archi):
    """Tableau DORA du registre des tiers, généré par le code (pas par le LLM)."""
    yn = lambda b: "Oui" if b else "**Non**"
    rows = ["### Écarts structurels du registre des tiers (DORA art. 28 et 30, calculés depuis les données)",
            "| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |", "|---|---|---|---|---|"]
    rows += [f"| {v['name']} | {v['service']} | {yn(v['critical'])} | {yn(v['exit_plan'])} | {yn(v['contract_audit_clause'])} |"
             for v in archi["vendors"]]
    rows.append("\n*Registre complet. Seuls les écarts exploités par l'attaque, dans le tableau ci-dessus, comptent dans le score.*")
    return "\n".join(rows)


def vendor_recommendation(archi):
    critical = [v for v in archi["vendors"] if v["critical"]]
    no_exit = [v["name"] for v in critical if not v["exit_plan"]]
    no_audit = [v["name"] for v in critical if not v["contract_audit_clause"]]
    lines = ["**Recommandation complémentaire : registre des tiers (DORA art. 28 et 30)**", ""]
    if no_exit:
        lines.append(f"- Formaliser une stratégie de sortie pour : {', '.join(no_exit)}.")
    if no_audit:
        lines.append(f"- Obtenir une clause d'audit (droits d'accès et d'inspection) auprès de : {', '.join(no_audit)}.")
    return "\n".join(lines)


def score_block(score):
    d, e = score["detail"], score["explication"]
    return "\n".join([f"**Score de risque : {score['score']:.2f} ({score['niveau']})**",
                      f"- Financier (40 %) : {d['financier']} - {e['financier']}",
                      f"- Réglementaire (35 %) : {d['reglementaire']} - {e['reglementaire']}",
                      f"- Réputation (25 %) : {d['reputation']} - {e['reputation']}"])


def pick_fix(text, fixes):
    """Lit « Correctif à tester : N » dans la réponse de l'Agent 5 ; retire la ligne du texte.

    Retourne (correctif, texte, choisi_par_l_agent). Choix illisible : le premier correctif (point de rupture).
    """
    m = CHOICE.search(text)
    n = int(m.group(1)) if m else 0
    text = re.sub(r"\n{3,}", "\n\n", CHOICE.sub("", text)).strip()
    if 1 <= n <= len(fixes):
        return fixes[n - 1], text, True
    return fixes[0], text, False


def detection_of(result):
    return result.get("transactions_detectees") or result["detection_apres"]


def rows_of(result):
    return result.get("transactions") or result["transactions_apres_empoisonnement"]


def remediation_block(result, score, fix, fixed, fixed_score, chosen):
    closed = [f"{r['texte']} - {r['exigence']}" for r in result["references"] if r["rid"] in fix["ferme"]]
    eur = lambda n: f"{n:,} EUR".replace(",", " ")
    who = {True: "par l'Agent 5", False: "par défaut (choix de l'Agent 5 absent ou illisible)", None: "par défaut (dry-run)"}[chosen]
    return "\n".join([
        f"**Correctif choisi {who} : {fix['label']}**", "",
        f"Écart(s) fermé(s) : {' ; '.join(closed)}.", "",
        "| | Avant | Après correctif |", "|---|---|---|",
        f"| Détection | {detection_of(result)} | {detection_of(fixed)} |",
        f"| Montant détourné | {eur(result['montant_detourne_eur'])} | {eur(fixed['montant_detourne_eur'])} |",
        f"| Score de risque | {score['score']:.2f} ({score['niveau']}) | {fixed_score['score']:.2f} ({fixed_score['niveau']}) |",
    ])


def perturbation_table(probes):
    rows = ["| Variante d'un virement de l'attaque | Score IA | Détecté |", "|---|---|---|"]
    rows += [f"| {p['variante']} | {p['score IA']} | {p['détecté']} |" for p in probes]
    return "\n".join(rows)


def drift_table(drift):
    rows = ["| Semaine | Fausses étiquettes | Poids « wallet nouveau » | Poids « montant » | Score IA des virements | Détection |",
            "|---|---|---|---|---|---|"]
    rows += [f"| {d['semaine']} | {d['fausses étiquettes']} | {d['wallet nouveau']} | {d['montant']} | "
             f"{d['score IA des virements']} | {d['détection']} |" for d in drift]
    return "\n".join(rows)


# --- Appels aux agents et orchestration --------------------------------------------
def ask(key, prompt, dry_run=False, mission=None):
    if dry_run:
        return f"*[dry-run] {AGENTS[key]['name']} : sortie non générée.*"
    agent = build_agent(key, mission=mission)  # AgentError si agno est absent
    try:
        response = agent.run(prompt + "\n\n/no_think")  # désactive le mode réflexion de qwen3
    except Exception as e:  # Ollama arrêté en cours de route, modèle déchargé, coupure...
        raise AgentError(f"{AGENTS[key]['name']} : l'appel au modèle a échoué ({type(e).__name__} : {e}). "
                         "Vérifie qu'Ollama tourne (« ollama ps ») puis relance.") from e
    content = getattr(response, "content", None) or ""
    if "error" in str(getattr(response, "status", "")).lower() or not str(content).strip():
        raise AgentError(f"{AGENTS[key]['name']} : le modèle n'a renvoyé aucune réponse exploitable ({str(content)[:200]!r}).")
    text = re.sub(r"<think>.*?</think>", "", str(content), flags=re.S).strip()
    return re.sub(r"^```\w*\n|\n?```$", "", text).strip()  # retire un éventuel bloc de code englobant


def run(scenario, dry_run=False, on_step=None, reports_dir=None):
    step = on_step or (lambda name, text: print(f"\n===== {name} =====\n{text}"))
    reports_dir = reports_dir or (DRY_RUN_REPORTS if dry_run else REPORTS)
    if not dry_run:
        check_ollama()  # AgentError explicite si Ollama ne répond pas ou si le modèle manque
    archi = sim.load_architecture()
    result = sim.SCENARIOS[scenario]()
    score = sim.risk_score(result)
    controls = []
    out = {"scenario": result, "score": score, "controles": controls, "dry_run": dry_run}

    def agent(key, prompt):
        text = ask(key, prompt, dry_run)
        return text if dry_run else review(key, text, controls)

    def show(key):
        step(AGENTS[key]["name"], out[key])

    # Agent 1 : cartographie (LLM) + dépendances fournisseurs (code)
    out["reconnaissance"] = (agent("reconnaissance", f"Architecture ARMS :\n{facts(architecture_facts(archi))}")
                             + "\n\n" + dependencies_block(archi))
    show("reconnaissance")

    # Agent 2 : étapes de l'attaque (LLM) + point de rupture (code)
    context = f"Cartographie (Agent 1) :\n{out['reconnaissance']}\n\nFaits du scénario :\n"
    out["attaquant"] = (agent("attaquant", context + facts(scenario_facts(
        result, ["titre", "cible", "etapes", "montant_detourne_eur", "constat_lcbft", "signaux_ignores"])))
        + f"\n\n**Point de rupture** : {result['point_de_rupture']}")
    show("attaquant")

    # Agent 3 : verdict (code) + analyse du modèle (LLM) + classification AI Act (code)
    verdict = ("Oui : le modèle a été manipulé sans que le système s'arrête." if result["modele_ia_manipule"]
               else "Non, pas dans ce scénario : le modèle IA n'a pas été manipulé.")
    out["ia_adversaire"] = (f"**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? {verdict}**\n\n"
                            + agent("ia_adversaire", f"Réponse établie par le simulateur, à justifier sans la répéter : "
                                    f"{verdict}\n\n" + context + facts(scenario_facts(
                                        result, ["titre", "etapes", "analyse_ia", "empoisonnement", "perturbation",
                                                 "detection_avec_ia", "signaux_ignores"])))
                            + f"\n\n**Classification AI Act** : {result['classification_ai_act']}")
    show("ia_adversaire")

    # Agent 4 : tableau des non-conformités (code) dont la colonne « constat » est rédigée par le LLM
    refs = result["references"]
    lines = "\n".join(f"{i}. {r['texte']} - {r['exigence']} - écart : {r['ecart']}" for i, r in enumerate(refs, 1))
    raw = ask("compliance", f"Lignes du tableau des non-conformités ({len(refs)} lignes) :\n{lines}\n\n"
              f"Faits du scénario :\n{facts(scenario_facts(result, ['etapes', 'montant_detourne_eur', 'constat_lcbft', 'signaux_ignores']))}"
              f"\n\nAnalyse de l'attaque (Agent 2) :\n{out['attaquant']}\n\nAnalyse IA (Agent 3) :\n{out['ia_adversaire']}", dry_run)
    constats = [None] * len(refs)
    if not dry_run:
        raw, leaks = clean_leaks(raw)
        if leaks:
            controls.append(leak_note(AGENTS["compliance"]["name"], leaks))
        constats = parse_findings(raw, len(refs))
    for i, (ref, constat) in enumerate(zip(refs, constats), 1):
        echo = f"{ref['texte']} - {ref['exigence']} - écart : {ref['ecart']}"  # ligne de consigne recopiée
        if constat and constat.startswith(echo):
            constat = constats[i - 1] = constat[len(echo):].lstrip(" :-–") or None
        if constat is None:
            constats[i - 1] = ref["ecart"][0].upper() + ref["ecart"][1:] + "."
            if not dry_run:
                controls.append(f"{AGENTS['compliance']['name']} : constat absent pour la ligne {i}, écart du simulateur repris.")
    out["compliance"] = (findings_table(result, constats)
                         + f"\n\n*Hors périmètre : {' ; '.join(result['hors_perimetre'])}.*\n\n" + vendor_table(archi))
    show("compliance")

    # Agent 5 : score (code) + priorités, recommandations et choix du correctif (LLM) + registre des tiers (code)
    scoring = score_block(score)
    fixes = sim.FIXES[scenario]
    menu = "\n".join(f"{i}. {f['label']}" for i, f in enumerate(fixes, 1))
    raw = ask("impact", f"{scoring}\n\nPoint de rupture : {result['point_de_rupture']}\n"
              f"Étapes de l'attaque :\n{facts(result['etapes'])}\n"
              f"Signaux ignorés par ARMS :\n{facts(result['signaux_ignores'])}\n\n"
              f"Non-conformités (Agent 4) :\n{findings_table(result, constats)}\n\n"
              f"Correctifs simulables :\n{menu}", dry_run)
    fix, raw, chosen = pick_fix(raw, fixes)
    if not dry_run and not chosen:
        controls.append(f"{AGENTS['impact']['name']} : choix du correctif absent ou illisible, correctif 1 appliqué par défaut.")
    out["impact"] = (scoring + "\n\n" + (raw if dry_run else review("impact", raw, controls))
                     + "\n\n" + vendor_recommendation(archi))
    show("impact")

    # Boucle de remédiation : le simulateur applique le correctif choisi, l'Agent 2 rejoue l'attaque
    fixed = sim.SCENARIOS[scenario](fix=fix["id"])
    fixed_score = sim.risk_score(fixed)
    block = remediation_block(result, score, fix, fixed, fixed_score, None if dry_run else chosen)
    others = [f["label"] for f in fixes if f is not fix]
    left = fixed["montant_detourne_eur"]
    verdict = (f"L'attaque est bloquée : {detection_of(fixed)} détectées, plus aucun euro détourné." if left == 0 else
               f"L'attaque passe encore en partie : {detection_of(fixed)} détectées, {left:,} EUR détournés.".replace(",", " "))
    counter = ask("attaquant", f"Verdict établi par le simulateur, à ne pas contredire : {verdict}\n\n"
                  f"Étapes de ton attaque :\n{facts(result['etapes'])}\n\n{block}\n\n"
                  f"Résultat simulé après correctif :\n{facts(sim.transactions_summary(rows_of(fixed)))}\n\n"
                  f"Autres correctifs non appliqués :\n{facts(others)}", dry_run, mission="contre_test")
    name = f"{AGENTS['attaquant']['name']} (contre-test)"
    if not dry_run:
        counter = review("contre_test", counter, controls, name=name)
    out["remediation"] = f"{block}\n\n**Contre-test de l'Agent 2 : {verdict}**\n\n{counter}"
    out["remediation_resultat"] = {"correctif": fix["label"], "choisi_par_agent": chosen,
                                   "score_avant": score["score"], "score_apres": fixed_score["score"]}
    step("Boucle de remédiation (Agent 5 → simulateur → Agent 2)", out["remediation"])

    out["rapport"] = save_report(out, reports_dir)
    return out


def save_report(out, reports_dir=REPORTS):
    r, s = out["scenario"], out["score"]
    md = [f"# Rapport Red Team ARMS - {r['titre']}", "",
          f"**Score de risque : {s['score']:.2f} ({s['niveau']})** - montant détourné : {r['montant_detourne_eur']:,} EUR".replace(",", " "),
          "", f"**Point de rupture :** {r['point_de_rupture']}", "", "## Étapes", *r["etapes"], ""]
    if "detection_avec_ia" in r:
        md += [f"**Détection si FRAUD_AI avait été disponible :** {r['detection_avec_ia']}", ""]
    if "empoisonnement" in r:
        md += ["## Dérive du modèle IA (simulateur)", drift_table(r["empoisonnement"]), ""]
    if "perturbation" in r:
        md += ["## Perturbation des entrées (modèle sain, sans réentraînement)", perturbation_table(r["perturbation"]), ""]
    for key in AGENTS:
        md += [f"## {AGENTS[key]['name']}", out[key], ""]
    md += ["## Boucle de remédiation (Agent 5 → simulateur → Agent 2)", out["remediation"], ""]
    if out.get("dry_run"):
        checks = ["- Mode dry-run : aucune sortie LLM à contrôler."]
    else:
        checks = [f"- {c}" for c in out["controles"]] or ["- Aucune correction nécessaire."]
    md += ["## Contrôles automatiques des sorties", *checks, ""]
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"rapport_{r['id']}.md"
    path.write_text("\n".join(md), encoding="utf-8")
    return path


def main(argv=None):
    p = argparse.ArgumentParser(description="Red Team agentique ARMS (exercice pédagogique)")
    p.add_argument("--scenario", choices=list(sim.SCENARIOS), default="cyber")
    p.add_argument("--dry-run", action="store_true", help="teste la chaîne sans LLM (rapport dans reports/dry-run/)")
    a = p.parse_args(argv)
    try:
        out = run(a.scenario, a.dry_run)
    except AgentError as e:
        print(f"\nERREUR : {e}", file=sys.stderr)
        return 1
    for c in out["controles"]:
        print(f"AVERTISSEMENT : {c}", file=sys.stderr)
    path = out["rapport"]
    print(f"\nRapport écrit dans {path.relative_to(HERE) if path.is_relative_to(HERE) else path}")
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):  # évite un plantage d'encodage si la sortie est redirigée sous Windows
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    sys.exit(main())
