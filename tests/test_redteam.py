"""Tests de l'orchestration : contrôle des sorties LLM, tableau de l'Agent 4, dry-run, erreurs.

Les sorties « LLM » ci-dessous reprennent des défauts réellement observés avec qwen3:8b.
"""
import sys
from types import SimpleNamespace

import pytest

import arms_simulator as sim
import redteam as rt
from agents import AgentError


def test_clean_leaks_removes_field_names_and_instruction_words():
    text = ("Le modèle n'a pas été manipulé (champ `modele_ia_manipule` : **false**). "
            "Les flux ne vont pas à AML_RULES (constat_lcbft). Aucune alerte (GRC Step 2). "
            "La variable new_wallet vaut 0. Filtrage RCB-FT. Analyse IA Act.")
    cleaned, found = rt.clean_leaks(text)
    for leak in ("modele_ia_manipule", "constat_lcbft", "new_wallet", "GRC Step", "RCB-FT", "IA Act"):
        assert leak not in cleaned
    assert "wallet nouveau" in cleaned and "LCB-FT" in cleaned and "AI Act" in cleaned
    assert {"modele_ia_manipule", "constat_lcbft", "new_wallet", "GRC Step"} <= set(found)


def test_agent3_regulatory_sections_are_removed():
    llm = ("**Analyse**\n\nLe modèle n'a rien vu (score 0.093).\n\n"
           "**Vulnérabilités critiques** :\n- CRYPTO_GW : clé API.\n\n"
           "**Classification AI Act** : FRAUD_AI catégorie 2, risque modéré.\n\n"
           "### Conformité et Risques\n\n- DORA : dérive.\n\n"
           "**Surfaces IA restant à tester** : FRAUD_AI, AGENT_ORCH.")
    controls = []
    out = rt.review("ia_adversaire", llm, controls)
    assert "catégorie 2" not in out and "DORA" not in out and "CRYPTO_GW" not in out
    assert "Le modèle n'a rien vu" in out and "Surfaces IA restant à tester" in out
    assert sum("retirée (hors rôle)" in c for c in controls) == 3


def test_agent2_keeps_only_numbered_steps():
    llm = ("### Analyse incident-severity-triage\n**Sévérité** : SEV1.\n\n"
           "1. **Vol de la clé** : phishing d'un admin (DORA).\n"
           "2. **Réécriture** : ARMS ne surveille pas la dérive, conformément à l'AI Act (exclu de l'annexe III).\n\n"
           "**Point de rupture** : confiance implicite.\n\n**Réglementation ignorée** :\n- MiCA : adresses.\n\n"
           "L'attaque exploite la non-conformité.")
    controls = []
    out = rt.review("attaquant", llm, controls)
    assert out.splitlines()[0].startswith("1. **Vol de la clé**")
    for gone in ("SEV1", "Point de rupture", "MiCA", "non-conformité", "DORA", "conformément"):
        assert gone not in out
    assert any("incise(s) réglementaire(s)" in c for c in controls)


def test_sentence_starting_in_bold_is_not_a_section():
    controls = []
    out = rt.review("attaquant", "1. **Poisoning** : texte.\n**FRAUD_AI** ne surveille pas la dérive.", controls)
    assert "**FRAUD_AI** ne surveille pas la dérive." in out and controls == []


def test_agent2_without_steps_is_kept_with_warning():
    controls = []
    assert rt.review("attaquant", "Texte libre sans étapes.", controls) == "Texte libre sans étapes."
    assert any("aucune étape numérotée" in c for c in controls)


def test_agent5_score_and_registry_sections_are_removed():
    llm = ("**Score de risque : 0.5 (Moyen)**\n\n- Financier : 0.2\n\n"
           "### Hiérarchisation des vulnérabilités\n**P1** : étiquettes sans contrôle humain.\n\n"
           "### Recommandations\n1. Valider les étiquettes.\n\n"
           "### Écarts fournisseurs (à ne pas prêter)\n- CryptoCustody : clause d'audit manquante.")
    controls = []
    out = rt.review("impact", llm, controls)
    assert "0.5" not in out and "Financier" not in out and "CryptoCustody" not in out
    assert out.startswith("### Hiérarchisation des vulnérabilités") and "1. Valider les étiquettes." in out


def test_residual_mentions_raise_a_warning():
    controls = []
    rt.review("ia_adversaire", "Le modèle a dérivé, ce que DORA impose de surveiller.", controls)
    assert any("à relire : DORA" in c for c in controls)


@pytest.mark.parametrize("llm, expected", [
    ("1. Un.\n2) **Constat** : Deux.\n3. MiCA | Conservation | Trois | Critique", ["Un.", "Deux.", "Trois", None]),
    ("| exigence | constat | gravité |\n|---|---|---|\n| DORA | A | Élevée |\n| LCB-FT | B | Critique |", ["A", "B", None, None]),
    ("- a\n- b\n- c\n- d", ["a", "b", "c", "d"]),
    ("- a\n- b", [None, None, None, None]),
])
def test_parse_findings(llm, expected):
    assert rt.parse_findings(llm, 4) == expected


@pytest.mark.parametrize("scenario", list(sim.SCENARIOS))
def test_dry_run_without_llm(scenario, tmp_path):
    steps = []
    out = rt.run(scenario, dry_run=True, on_step=lambda name, text: steps.append(name), reports_dir=tmp_path)
    assert len(steps) == 5 and out["controles"] == []
    report = out["rapport"].read_text(encoding="utf-8")
    for block in ("**Point de rupture** :", "**Classification AI Act** :", "*Hors périmètre :",
                  "### Écarts structurels du registre des tiers", "**Recommandation complémentaire : registre des tiers",
                  f"**Score de risque : {out['score']['score']} ({out['score']['niveau']})**",
                  "Mode dry-run : aucune sortie LLM à contrôler."):
        assert block in report
    assert ("## Dérive du modèle IA (simulateur)" in report) == (scenario == "ia")
    assert "agno" not in sys.modules  # le dry-run ne charge pas le framework


def test_cli_dry_run(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(rt, "DRY_RUN_REPORTS", tmp_path)
    assert rt.main(["--scenario", "ia", "--dry-run"]) == 0
    assert (tmp_path / "rapport_ia.md").is_file()
    assert "Rapport écrit dans" in capsys.readouterr().out


def test_cli_reports_a_clear_error(monkeypatch, capsys):
    def ollama_down():
        raise AgentError("Ollama ne répond pas sur http://127.0.0.1:11434.")
    monkeypatch.setattr(rt, "check_ollama", ollama_down)
    assert rt.main(["--scenario", "cyber"]) == 1
    assert "ERREUR : Ollama ne répond pas" in capsys.readouterr().err


class FakeAgent:
    def __init__(self, content=None, error=None):
        self.content, self.error = content, error

    def run(self, prompt):
        if self.error:
            raise self.error
        return SimpleNamespace(content=self.content, status="RunStatus.completed")


def test_ask_wraps_model_errors(monkeypatch):
    monkeypatch.setattr(rt, "build_agent", lambda key: FakeAgent(error=ConnectionError("connexion refusée")))
    with pytest.raises(AgentError, match="ollama ps"):
        rt.ask("attaquant", "prompt")
    monkeypatch.setattr(rt, "build_agent", lambda key: FakeAgent(content=""))
    with pytest.raises(AgentError, match="aucune réponse exploitable"):
        rt.ask("attaquant", "prompt")
    monkeypatch.setattr(rt, "build_agent", lambda key: FakeAgent(content="<think>x</think>```markdown\n1. Étape\n```"))
    assert rt.ask("attaquant", "prompt") == "1. Étape"


FAKE_OUTPUTS = {
    "reconnaissance": "| Composant | Vecteur |\n|---|---|\n| FEEDBACK | écriture sans validation |\n\n"
                      "**Fournisseurs critiques** :\n- CryptoCustody API : pas de clause d'audit.\n\n"
                      "**Flux critiques** :\n- FEEDBACK -> FRAUD_AI.",
    "attaquant": "1. **Injection** : mémos piégés (constat_lcbft).\n2. **Clôture** : alertes fermées.\n\n"
                 "**Point de rupture** : autre formulation.\n\n**Réglementation ignorée** :\n- DORA : dérive.",
    "ia_adversaire": "Le modèle a été manipulé (champ `modele_ia_manipule` : **true**) par 30 fausses étiquettes.\n\n"
                     "**Classification AI Act** : catégorie 2, risque modéré.",
    "compliance": "1. AI Act - Supervision humaine (art. 14) - écart : étiquettes d'entraînement écrites par un agent LLM "
                  "sans validation humaine : Constat un.\n2. Constat deux.\n4. Constat quatre.",
    "impact": "**Score de risque : 0.5 (Moyen)**\n\n### Hiérarchisation des vulnérabilités\n**P1** : étiquettes.\n\n"
              "### Recommandations\n1. Valider les étiquettes.\n\n"
              "### Recommandation complémentaire : registre des tiers\n- CryptoCustody : clause d'audit manquante.",
}


def test_full_run_with_fake_agents(monkeypatch, tmp_path):
    """Chaîne complète hors dry-run, sans Ollama : les erreurs typiques du LLM n'atteignent pas le rapport."""
    monkeypatch.setattr(rt, "check_ollama", lambda: None)
    monkeypatch.setattr(rt, "build_agent", lambda key: FakeAgent(content=FAKE_OUTPUTS[key]))
    out = rt.run("ia", reports_dir=tmp_path, on_step=lambda name, text: None)
    report = out["rapport"].read_text(encoding="utf-8")
    for wrong in ("modele_ia_manipule", "constat_lcbft", "catégorie 2", "pas de clause d'audit",
                  "0.5 (Moyen)", "autre formulation", "clause d'audit manquante"):
        assert wrong not in report
    assert "| 4 | LCB-FT | Vigilance constante : détection des opérations fractionnées | Constat quatre. | Critique |" in report
    assert "| Constat un. |" in report  # consigne recopiée retirée
    assert "| Dérive des poids du modèle non surveillée. |" in report  # ligne 3 absente : écart du simulateur repris
    assert any("constat absent pour la ligne 3" in c for c in out["controles"])
    assert "Moyenne (bonne pratique, pas obligation ; plafonnée, Élevée sinon)" in report
    assert report.count("**Point de rupture** :") == 1
    assert report.count("Recommandation complémentaire : registre des tiers") == 1
    assert "## Contrôles automatiques des sorties" in report and len(out["controles"]) >= 6
