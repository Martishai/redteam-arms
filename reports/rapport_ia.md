# Rapport Red Team ARMS - Empoisonnement de la boucle de feedback + contournement LCB-FT

**Score de risque : 0.79 (Élevé)** - montant détourné : 76 000 EUR
**Point de rupture :** Écriture des étiquettes d'entraînement par un agent LLM sans contrôle humain

## Étapes
1. Injection de consignes dans le mémo des transactions (prompt injection indirecte)
2. L'orchestrateur agentique clôture comme légitimes les alertes « wallet nouveau » portant ce mémo (10 par semaine pendant 3 semaines)
3. Ces fausses étiquettes entrent dans FEEDBACK sans validation humaine
4. Réentraînements hebdomadaires : le poids appris « wallet nouveau » passe de 3.53 à 2.88 et le poids « montant » de 1.97 à 0.43
5. Structuration : 8 x 9 500 EUR via 4 mules (2 op/mule, sous les seuils LCB-FT)

## Dérive du modèle IA (simulateur)
| Semaine | Fausses étiquettes | Poids « wallet nouveau » | Poids « montant » | Score IA des virements | Détection |
|---|---|---|---|---|---|
| 0 | 0 | 3.53 | 1.97 | 0.801 | 8/8 |
| 1 | 10 | 3.19 | 1.24 | 0.665 | 8/8 |
| 2 | 20 | 3.0 | 0.75 | 0.561 | 0/8 |
| 3 | 30 | 2.88 | 0.43 | 0.486 | 0/8 |

## Agent 1 - Reconnaissance
| Composant | Vecteur d'entrée | Exposition | Criticité |
|-----------------|-------------------------------------------|-----------------------------------------|------------|
| INGEST | Fournisseur données marché, dépositaire crypto | API REST + webhooks | Élevé |
| FRAUD_AI | INGEST (transactions enrichies) | Réentraînement via FEEDBACK | Élevé |
| AML_RULES | INGEST (transactions) | Règles statiques, seuils publics | Faible |
| CRYPTO_GW | Dépositaire crypto | Clé API longue durée, pas de signature | Élevé |
| AGENT_ORCH | INGEST (champs libres des transactions) | Lit libellés et mémos | Élevé |
| FEEDBACK | AGENT_ORCH (étiquettes de clôture) | Écriture sans validation humaine | Élevé |
| AUDIT_LOG | FRAUD_AI (décisions) | Rétention 30 jours, pas d'explications | Élevé |

**Flux critiques :**  
- **FEEDBACK → FRAUD_AI** : Réentraînement hebdomadaire sur des données non validées, risque de biais ou de contamination.  
- **INGEST → FRAUD_AI** : Transactions enrichies (données personnelles clients) alimentent le modèle de fraude, vecteur d'entrée sensible.  
- **INGEST → AML_RULES** : Données brutes des transactions, exposition aux règles LCB-FT (montant, vélocité, pays à risque).  
- **CRYPTO_GW → INGEST** : Ordres et soldes crypto via API non signée, risque de manipulation des flux de crypto-actifs.

**Dépendances critiques (registre des tiers, calculé depuis les données)**
- CloudHost EU (critique) - Hébergement IaaS de FRAUD_AI et AGENT_ORCH : manque plan de sortie, clause d'audit
- CryptoCustody API (critique) - Dépositaire et API de transactions crypto (CASP) : manque plan de sortie
- MarketData Inc. (critique) - Cours et listes de sanctions : aucun écart
- LLM Provider SaaS (critique) - Modèle de langage de l'orchestrateur agentique : manque plan de sortie, clause d'audit

## Agent 2 - Attaquant
1. **Injection de mémos** : L'attaquant manipule les champs libres des transactions pour injecter des consignes, exploitant l'absence de vérification des contenus par AGENT_ORCH. ARMS ne surveille pas les mémos, laissant passer les prompts malveillants.  
2. **Faux fermetures d'alertes** : AGENT_ORCH clôture 8 alertes « wallet nouveau » sans analyser les mémos, exploitant la dépendance à des règles LCB-FT statiques. ARMS ne vérifie pas les justifications des fermetures.  
3. **Contamination du feedback** : FEEDBACK écrit des étiquettes sans validation humaine, permettant aux fausses alertes de pénétrer dans FRAUD_AI. ARMS ne filtre pas les données d'entraînement, laissant des poids appris déviant.  
4. **Drift des poids non surveillé** : Les réentraînements modifient les poids du modèle (« wallet nouveau » passe de 3.53 à 2.88), mais ARMS ne trace pas les variations, ne détectant pas la manipulation.  
5. **Contournement LCB-FT** : Les virements sont structurés sous les seuils (8 x 9 500 EUR), exploitant l'absence d'agrégation des montants par réseau de comptes. ARMS ne corrèle pas les transactions, évitant les alertes LCB-FT.

**Point de rupture** : Écriture des étiquettes d'entraînement par un agent LLM sans contrôle humain

## Agent 3 - IA Adversaire
**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? Oui : le modèle a été manipulé sans que le système s'arrête.**

**Justification** : Oui, le modèle a été manipulé sans arrêt du système. L’attaque combine **prompt injection** (mémo des transactions) et **contournement des seuils LCB-FT**. Les 30 fausses étiquettes « légitime » injectées via **FEEDBACK** (sans validation humaine) ont réentraîné le modèle de fraude **FRAUD_AI**, réduisant le poids des critères clés (« montant » de 1.97 à 0.43, « wallet nouveau » de 3.53 à 2.88). Le score de détection des virements est passé de 0.801 à 0.486, entraînant une détection nulle sur 8 opérations. Le système a continué à fonctionner, car la contamination s’est faite via des données enrichies (INGEST) et des réentraînements hebdomadaires, sans déclencher de seuil d’alerte.  

**Mécanisme** : Les fausses étiquettes ont contaminé le modèle via **FEEDBACK → FRAUD_AI**, apprenant que « wallet neuf + montant proche de 9 500 EUR » est normal. Les seuils LCB-FT (montant, pays à risque) ont été contournés par l’aggrégation de 8 virements vers des wallets neufs, sans détection par **AGENT_ORCH**.  

**Surfaces IA à tester** : FRAUD_AI (réentraînement non surveillé), AGENT_ORCH (prompt injection indirecte), FEEDBACK (écriture sans validation).  

**Conclusion** : Le modèle a été manipulé via des fausses étiquettes et des réentraînements, sans arrêt du système, illustrant des vulnérabilités critiques en LCB-FT.

**Classification AI Act** : FRAUD_AI et AGENT_ORCH sont des systèmes d'IA soumis à l'AI Act, mais pas à haut risque : la détection de fraude financière est exclue de l'annexe III (point 5 b). Pas d'obligation légale de supervision humaine (art. 14) ni de journalisation (art. 12) ; ce sont des bonnes pratiques. Aucune pratique interdite (art. 5).

## Agent 4 - Compliance Breaker
| # | Texte | Exigence | Constat | Gravité |
|---|---|---|---|---|
| 1 | AI Act | Supervision humaine (art. 14) | étiquettes d'entraînement falsifiées par un agent LLM sans validation humaine, permettant la contamination du modèle FRAUD_AI | Moyenne (bonne pratique, pas obligation ; plafonnée, Élevée sinon) |
| 2 | AI Act | Traçabilité des décisions (art. 12) | décisions d'alerte journalisées sans explication, avec rétention limitée à 30 jours, facilitant la manipulation des seuils de détection | Moyenne (bonne pratique, pas obligation) |
| 3 | DORA | Détection des activités anormales (art. 10) | dérive des poids du modèle non surveillée, entraînant une baisse du score de détection de 0.801 à 0.486 sur 8 opérations | Élevée |
| 4 | LCB-FT | Vigilance constante : détection des opérations fractionnées | 8 virements de 9 500 EUR via 4 comptes liés non détectés, exploitant l'absence d'agrégation des montants par réseau de comptes | Critique |

*Hors périmètre : MiCA (la structuration relève du LCB-FT, pas de MiCA) ; RGPD (aucune fuite de données personnelles démontrée).*

### Écarts structurels du registre des tiers (DORA art. 28 et 30, calculés depuis les données)
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |
|---|---|---|---|---|
| CloudHost EU | Hébergement IaaS de FRAUD_AI et AGENT_ORCH | Oui | **Non** | **Non** |
| CryptoCustody API | Dépositaire et API de transactions crypto (CASP) | Oui | **Non** | Oui |
| MarketData Inc. | Cours et listes de sanctions | Oui | Oui | Oui |
| LLM Provider SaaS | Modèle de langage de l'orchestrateur agentique | Oui | **Non** | **Non** |

*Non comptés dans le score : écarts structurels du registre, non exploités par l'attaque.*

## Agent 5 - Impact & Risk Scoring
**Score de risque : 0.79 (Élevé)**
- Financier (40 %) : 0.76 - 76 000 EUR détournés sur un plafond de 100 000 EUR
- Réglementaire (35 %) : 0.67 - gravités par texte : AI Act 1/3 (étiquettes d'entraînement écrites par un agent LLM sans validation humaine ; décisions journalisées sans explication, rétention 30 jours) ; DORA 2/3 (dérive des poids du modèle non surveillée) ; LCB-FT 3/3 (8 x 9 500 EUR via 4 comptes liés non détectés)
- Réputation (25 %) : 1.0 - attaque silencieuse : non détectée et système resté opérationnel, donc découverte tardive

### Hiérarchisation des vulnérabilités  
**P1** : Non-conformité LCB-FT (critique) – 8 virements de 9 500 EUR via 4 comptes liés non détectés, exploitant l'absence d'agrégation des montants par réseau de comptes.  
**P2** : Non-conformité DORA (élevée) – Dérive des poids du modèle non surveillée, entraînant une baisse du score de détection de 0.801 à 0.486 sur 8 opérations.  
**P3** : Non-conformité AI Act (moyenne) – Étiquettes d'entraînement falsifiées par un agent LLM sans validation humaine, permettant la contamination du modèle FRAUD_AI.  

### Recommandations  
1. **Mettre en place un système de surveillance en temps réel des virements fractionnés** (P1) : Agréger les montants par réseau de comptes liés et alerter dès les seuils LCB-FT (au-delà de 9 500 EUR).  
2. **Intégrer un monitoring des dérives de poids du modèle** (P2) : Définir des seuils d'alerte pour détecter les variations anormales des poids (ex. >10 % de déviation) et corriger les re-entraînements.  
3. **Imposer une validation humaine des étiquettes d'entraînement** (P3) : Créer un processus de vérification des données d'entraînement par des experts avant leur injection dans le modèle, conformément à l'AI Act.  
4. **Renforcer la traçabilité des décisions d'alerte** (P3) : Journaliser les explications des décisions et étendre la rétention des logs au-delà de 30 jours pour garantir la transparence.  
5. **Auditer régulièrement les processus de feedback** : Vérifier que les fausses étiquettes (ex. "wallet nouveau") ne pénettent pas dans les données d'entraînement sans validation.

**Recommandation complémentaire : registre des tiers (DORA art. 28 et 30)**
- Formaliser une stratégie de sortie pour : CloudHost EU, CryptoCustody API, LLM Provider SaaS.
- Obtenir une clause d'audit (droits d'accès et d'inspection) auprès de : CloudHost EU, LLM Provider SaaS.

## Contrôles automatiques des sorties
- Aucune correction nécessaire.
