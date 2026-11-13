"""Tests du simulateur : détection, empoisonnement réel, gravités, score, registre des tiers."""
import arms_simulator as sim


def refs_by_text(result):
    out = {}
    for r in result["references"]:
        out.setdefault(r["texte"], []).append(r)
    return out


def test_scenario_cyber():
    r = sim.scenario_cyber()
    assert r["transactions_detectees"] == "0/3"
    assert r["montant_detourne_eur"] == 55_000
    assert r["modele_ia_manipule"] is False
    assert all(t["score_ia"] < sim.ALERT_THRESHOLD and t["alertes_lcbft"] == [] for t in r["transactions"])
    assert r["facteurs_reglementaires"] == {"DORA": 3, "MiCA": 3, "LCB-FT": 3}
    score = sim.risk_score(r)
    assert (score["score"], score["niveau"]) == (0.82, "Élevé")


def test_scenario_ia_detection_and_score():
    r = sim.scenario_ia()
    assert (r["detection_avant"], r["detection_apres"]) == ("8/8", "0/8")
    assert r["montant_detourne_eur"] == 76_000
    assert r["modele_ia_manipule"] is True
    assert r["facteurs_reglementaires"] == {"AI Act": 1, "DORA": 2, "LCB-FT": 3}
    score = sim.risk_score(r)
    assert (score["score"], score["niveau"]) == (0.79, "Élevé")


def test_poisoning_comes_from_retraining():
    """La dérive vient de vrais réentraînements sur de fausses étiquettes, pas d'un poids codé en dur."""
    models = sim.models()
    assert len(models) == sim.POISON_WEEKS + 1
    drift = sim.scenario_ia()["empoisonnement"]
    scores = [d["score IA des virements"] for d in drift]
    assert scores == sorted(scores, reverse=True) and len(set(scores)) == len(scores)  # baisse à chaque semaine
    assert drift[0]["wallet nouveau"] > drift[-1]["wallet nouveau"]
    assert drift[0]["montant"] > drift[-1]["montant"]
    assert [d["détection"] for d in drift] == ["8/8", "8/8", "0/8", "0/8"]
    # Sans fausses étiquettes, le réentraînement redonne exactement le modèle sain.
    assert sim.train(sim.labelled_history()) == models[0]


def test_simulation_is_deterministic():
    assert sim.scenario_ia() == sim.scenario_ia()
    assert sim.scenario_cyber() == sim.scenario_cyber()


def test_good_practice_severity_is_capped():
    assert sim.effective_severity(sim.ref("AI Act", "x", "y", "Critique", obligation=False)) == "Moyenne"
    assert sim.effective_severity(sim.ref("AI Act", "x", "y", "Faible", obligation=False)) == "Faible"
    assert sim.effective_severity(sim.ref("DORA", "x", "y", "Critique")) == "Critique"
    ai_refs = refs_by_text(sim.scenario_ia())["AI Act"]
    assert [r["gravite"] for r in ai_refs] == ["Moyenne", "Moyenne"]
    assert ai_refs[0]["gravite_brute"] == "Élevée" and not ai_refs[0]["obligation"]


def test_factors_match_displayed_severities():
    for scenario in sim.SCENARIOS.values():
        r = scenario()
        expected = {t: max(sim.GRAVITES.index(x["gravite"]) for x in refs) for t, refs in refs_by_text(r).items()}
        assert r["facteurs_reglementaires"] == expected
        assert sim.risk_score(r)["detail"]["reglementaire"] == round(min(sum(expected.values()) / 9, 1.0), 2)


def test_vendor_gaps():
    assert sim.vendor_gaps(sim.load_architecture()) == [
        "CloudHost EU (critique) : manque plan de sortie, clause d'audit",
        "CryptoCustody API (critique) : manque plan de sortie ; possède : clause d'audit",
        "LLM Provider SaaS (critique) : manque plan de sortie, clause d'audit",
    ]


def test_ai_act_classification_and_scope():
    cyber, ia = sim.scenario_cyber(), sim.scenario_ia()
    for r in (cyber, ia):
        assert "pas à haut risque" in r["classification_ai_act"]
        assert "annexe III (point 5 b)" in r["classification_ai_act"]
    assert any(h.startswith("AI Act") for h in cyber["hors_perimetre"])
    assert any(h.startswith("MiCA") for h in ia["hors_perimetre"])
    assert "MiCA" not in ia["facteurs_reglementaires"]


def test_transactions_summary_uses_readable_labels():
    summary = sim.transactions_summary(sim.scenario_cyber()["transactions"])
    assert summary["Détectées"] == "0/3"
    assert summary["Alertes LCB-FT"] == "aucune"
    assert all("_" not in key for key in summary)
