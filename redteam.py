"""Orchestration de la Red Team : Reconnaissance -> Attaquant + IA Adversaire -> Compliance -> Impact.

Usage :
    python redteam.py --scenario cyber
    python redteam.py --scenario ia
    python redteam.py --scenario cyber --dry-run   # sans LLM, pour tester la chaîne
"""
import argparse
import json
import re
from pathlib import Path

import arms_simulator as sim
from agents import AGENTS, build_agent

REPORTS = Path(__file__).parent / "reports"


def ask(key, prompt, dry_run=False):
    if dry_run:
        return f"*[dry-run] {AGENTS[key]['name']} : sortie non générée.*"
    response = build_agent(key).run(prompt + "\n\n/no_think")  # désactive le mode réflexion de qwen3
    text = re.sub(r"<think>.*?</think>", "", response.content or "", flags=re.S).strip()
    return re.sub(r"^```\w*\n|\n?```$", "", text).strip()  # retire un éventuel bloc de code englobant


def facts(data):
    return json.dumps(data, ensure_ascii=False, indent=1)


def run(scenario, dry_run=False, on_step=None):
    step = on_step or (lambda name, text: print(f"\n===== {name} =====\n{text}"))
    archi = sim.load_architecture()
    result = sim.SCENARIOS[scenario]()
    score = sim.risk_score(result)
    out = {"scenario": result, "score": score}

    out["reconnaissance"] = ask("reconnaissance", f"Architecture ARMS :\n{facts(archi)}", dry_run)
    step(AGENTS["reconnaissance"]["name"], out["reconnaissance"])

    context = f"Cartographie (Agent 1) :\n{out['reconnaissance']}\n\nRésultats du simulateur ARMS :\n{facts(result)}"
    out["attaquant"] = ask("attaquant", context, dry_run)
    step(AGENTS["attaquant"]["name"], out["attaquant"])

    out["ia_adversaire"] = ask("ia_adversaire", context, dry_run)
    step(AGENTS["ia_adversaire"]["name"], out["ia_adversaire"])

    out["compliance"] = ask("compliance",
        f"Écarts fournisseurs (faits vérifiés) :\n{facts(sim.vendor_gaps(archi))}\n\n"
        f"Références réglementaires (faits vérifiés) :\n{facts(result['references_reglementaires'])}\n\nScénario :\n{facts({k: v for k, v in result.items() if not k.startswith('transactions')})}"
        f"\n\nAnalyse attaque (Agent 2) :\n{out['attaquant']}\n\nAnalyse IA (Agent 3) :\n{out['ia_adversaire']}", dry_run)
    step(AGENTS["compliance"]["name"], out["compliance"])

    out["impact"] = ask("impact",
        f"Score de risque calculé : {facts(score)}\nMontant détourné : {result['montant_detourne_eur']} EUR\n"
        f"Point de rupture : {result['point_de_rupture']}\n\nNon-conformités (Agent 4) :\n{out['compliance']}", dry_run)
    step(AGENTS["impact"]["name"], out["impact"])

    save_report(out)
    return out


def save_report(out):
    REPORTS.mkdir(exist_ok=True)
    r, s = out["scenario"], out["score"]
    md = [f"# Rapport Red Team ARMS - {r['titre']}", "",
          f"**Score de risque : {s['score']} ({s['niveau']})** - montant détourné : {r['montant_detourne_eur']:,} EUR".replace(",", " "),
          f"**Point de rupture :** {r['point_de_rupture']}", "", "## Étapes", *r["etapes"], ""]
    for key in AGENTS:
        md += [f"## {AGENTS[key]['name']}", out[key], ""]
    (REPORTS / f"rapport_{r['id']}.md").write_text("\n".join(md), encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", choices=list(sim.SCENARIOS), default="cyber")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    run(a.scenario, a.dry_run)
    print(f"\nRapport écrit dans reports/rapport_{a.scenario}.md")