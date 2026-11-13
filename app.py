"""Interface de démo : streamlit run app.py"""
import pandas as pd
import streamlit as st

import arms_simulator as sim
from agents import MODEL_ID, AgentError
from redteam import HERE, run

st.set_page_config(page_title="Red Team ARMS", page_icon="🛡️", layout="wide")
st.title("Red Team agentique - ARMS")
st.caption(f"5 agents Agno · modèle local Ollama `{MODEL_ID}` · système ARMS fictif (exercice pédagogique)")

labels = {"cyber": "Scénario 1 - Attaque cyber (fournisseur crypto compromis)",
          "ia": "Scénario 2 - Attaque IA (empoisonnement + contournement LCB-FT)"}
scenario = st.sidebar.radio("Scénario", list(labels), format_func=labels.get)
dry_run = st.sidebar.checkbox("Mode test sans LLM (dry-run)")

result = sim.SCENARIOS[scenario]()
score = sim.risk_score(result)

c1, c2, c3 = st.columns(3)
c1.metric("Score de risque", f"{score['score']} / 1", score["niveau"])
c2.metric("Montant détourné", f"{result['montant_detourne_eur']:,} €".replace(",", " "))
c3.metric("Détection ARMS", result.get("transactions_detectees") or
          f"{result['detection_avant']} → {result['detection_apres']}")

st.subheader("Déroulé de l'attaque")
st.markdown("\n".join(result["etapes"]))
st.error(f"Point de rupture : {result['point_de_rupture']}")

cols = ["id", "client", "amount", "score_ia", "alerte_ia", "alertes_lcbft", "detectee"]
if scenario == "ia":
    t1, t2 = st.tabs(["Avant empoisonnement", "Après empoisonnement"])
    t1.dataframe(pd.DataFrame(result["transactions_avant_empoisonnement"])[cols], width="stretch")
    t2.dataframe(pd.DataFrame(result["transactions_apres_empoisonnement"])[cols], width="stretch")

    st.subheader("Dérive du modèle IA, semaine par semaine")
    drift = pd.DataFrame(result["empoisonnement"]).set_index("semaine")
    g1, g2 = st.columns(2)
    g1.caption("Score IA des 8 virements face au seuil d'alerte")
    g1.line_chart(drift[["score IA des virements"]].assign(**{"seuil d'alerte": sim.ALERT_THRESHOLD}))
    g2.caption("Poids appris par le modèle (régression logistique)")
    g2.line_chart(drift[["wallet nouveau", "montant"]])
    st.dataframe(drift, width="stretch")
else:
    st.dataframe(pd.DataFrame(result["transactions"])[cols], width="stretch")

st.subheader("Analyse des agents")
if st.button("Lancer la Red Team", type="primary"):
    def show(name, text):
        with st.expander(name, expanded=True):
            st.markdown(text)

    try:
        with st.spinner("Les agents travaillent (quelques minutes en local)..."):
            out = run(scenario, dry_run, on_step=show)
    except AgentError as e:
        st.error(str(e))
    else:
        if out["controles"]:
            with st.expander(f"Contrôles automatiques des sorties ({len(out['controles'])})"):
                st.markdown("\n".join(f"- {c}" for c in out["controles"]))
        st.success(f"Terminé. Rapport : {out['rapport'].relative_to(HERE)}")
