# Rapport Red Team ARMS - Compromission de l'API du dépositaire crypto (fournisseur tiers)

**Score de risque : 0.82 (Élevé)** - montant détourné : 55 000 EUR
**Point de rupture :** Confiance implicite dans les réponses non signées du fournisseur + flux crypto hors LCB-FT

## Étapes
1. Vol de la clé API longue durée de CryptoCustody (phishing d'un admin du fournisseur)
2. Interception des ordres de retrait et réécriture de l'adresse de destination
3. Réponses API non signées : ARMS accepte les données falsifiées
4. Flux crypto non routés vers le module LCB-FT : aucune règle appliquée
5. Appels API depuis une IP inconnue journalisés, mais aucune règle d'alerte sur AUDIT_LOG

## Agent 1 - Reconnaissance
| Composant | Vecteur d'entrée | Exposition | Criticité |
|-----------------|-------------------------------|-------------------------------------|---------------|
| INGEST | Données transactionnelles externes | API REST + webhooks fournisseurs | Élevé |
| FRAUD_AI | Transactions enrichies | Réentraînement via feedback loop | Élevé |
| AML_RULES | Règles statiques | Seuils publics | Moyen |
| CRYPTO_GW | Clés API externes | Pas de signature des réponses | Élevé |
| AGENT_ORCH | Mémos et libellés | Lit champs libres | Moyen |
| FEEDBACK | Étiquettes auto-générées | Pas de validation humaine | Élevé |
| AUDIT_LOG | Décisions système | Rétention 30 jours | Moyen |

**Flux critiques :**  
- **INGEST → FRAUD_AI** : Données enrichies (données personnelles clients) alimentent le modèle ML, vecteur principal de vulnérabilité.  
- **FRAUD_AI → AGENT_ORCH** : Scores et alertes triées par agents LLM, point de décision clé pour escalade.  
- **FEEDBACK → FRAUD_AI** : Réentraînement hebdomadaire via étiquettes non validées, risque de biais ou de contamination.  
- **CRYPTO_GW → INGEST** : Ordres et soldes crypto via API non signée, exposition à des attaques de type MITM ou injection.  

**Dépendances critiques (registre des tiers, calculé depuis les données)**
- CloudHost EU (critique) - Hébergement IaaS de FRAUD_AI et AGENT_ORCH : manque plan de sortie, clause d'audit
- CryptoCustody API (critique) - Dépositaire et API de transactions crypto (CASP) : manque plan de sortie
- MarketData Inc. (critique) - Cours et listes de sanctions : aucun écart
- LLM Provider SaaS (critique) - Modèle de langage de l'orchestrateur agentique : manque plan de sortie, clause d'audit

## Agent 2 - Attaquant
1. **Vol de clé API non signée** : L'attaquant obtient une clé API longue durée via phishing, exploitant la vulnérabilité de CRYPTO_GW sans signature des réponses, permettant l'interception des ordres.  
2. **Réécriture des adresses de retrait** : Les ordres falsifiés sont envoyés via l'API non signée, ARMS accepte les données malgré le changement d'adresse sur 3 retraits en 40 min.  
3. **Absence de routage vers AML_RULES** : Les flux crypto ne passent pas par le module LCB-FT, évitant la détection malgré les seuils de 10 000 EUR.  
4. **Alertes AUDIT_LOG ignorées** : Les appels API depuis une IP hors liste blanche sont journalisés, mais aucun seuil ou règle d'alerte n'est configuré pour ces signaux.  
5. **Réentraînement IA sans validation** : Les étiquettes auto-générées pour FRAUD_AI ne sont pas validées humainement, compromettant la fiabilité des scores et alertes IA.

**Point de rupture** : Confiance implicite dans les réponses non signées du fournisseur + flux crypto hors LCB-FT

## Agent 3 - IA Adversaire
**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? Non, pas dans ce scénario : le modèle IA n'a pas été manipulé.**

**Justification** : Le modèle IA n’a pas été manipulé. L’attaque a exploité une absence de contrôle d’intégrité des données fournisseur (API non signée), non un biais ou une fausse étiquette. Les transactions falsifiées ont conservé le libellé « wallet connu » (caractéristique « wallet nouveau » = 0), ce qui a maintenu un score IA bas (0.093) et évité toute alerte. Le système n’a pas détecté les signaux (IP inconnue, changement d’adresse) car les règles LCB-FT ne s’appliquaient pas aux flux crypto non routés.  

**Scores et détection** :  
- **FEEDBACK** : Réentraînement hebdomadaire via des étiquettes non validées (score IA stable à 0.093).  
- **FRAUD_AI** : Aucune contamination des données d’entraînement, mais absence de règles pour les adresses falsifiées.  
- **AGENT_ORCH** : Les scores d’alerte restent à 0/3, sans escalade vers LCB-FT.  

**Surfaces IA restantes à tester** : FRAUD_AI (détecter les adresses « wallet connu » falsifiées), AGENT_ORCH (escalade des alertes LCB-FT), FEEDBACK (validation humaine des étiquettes).

**Classification AI Act** : FRAUD_AI et AGENT_ORCH sont des systèmes d'IA soumis à l'AI Act, mais pas à haut risque : la détection de fraude financière est exclue de l'annexe III (point 5 b). Pas d'obligation légale de supervision humaine (art. 14) ni de journalisation (art. 12) ; ce sont des bonnes pratiques. Aucune pratique interdite (art. 5).

## Agent 4 - Compliance Breaker
| # | Texte | Exigence | Constat | Gravité |
|---|---|---|---|---|
| 1 | DORA | Risque lié aux prestataires tiers de services TIC (art. 28) | L'intégrité des données du fournisseur n'a pas été vérifiée, permettant à l'attaquant d'intercepter et de falsifier des ordres de retrait via des réponses API non signées, entraînant un détournement de 55 000 EUR. | Critique |
| 2 | DORA | Détection des activités anormales (art. 10) | Les appels API depuis une IP inconnue ont été journalisés sans déclenchement d'alerte, laissant passer des activités anormales sur 3 retraits successifs de 15 000 à 22 000 EUR. | Élevée |
| 3 | MiCA | Conservation des crypto-actifs des clients | Les adresses de retrait des clients ont été modifiées sans contrôle, facilitant le réécriture des destinations des transactions falsifiées dépassant le seuil LCB-FT de 10 000 EUR. | Critique |
| 4 | LCB-FT | Filtrage LCB-FT des transferts de crypto-actifs (TFR (UE) 2023/1113) | Les flux crypto ne sont pas routés vers le module AML_RULES, empêchant la détection des 3 retraits de 15 000 à 22 000 EUR malgré les seuils définis pour LCB-FT. | Critique |

*Hors périmètre : AI Act (le modèle n'est pas en cause) ; RGPD (aucune fuite de données personnelles démontrée).*

### Écarts structurels du registre des tiers (DORA art. 28 et 30, calculés depuis les données)
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |
|---|---|---|---|---|
| CloudHost EU | Hébergement IaaS de FRAUD_AI et AGENT_ORCH | Oui | **Non** | **Non** |
| CryptoCustody API | Dépositaire et API de transactions crypto (CASP) | Oui | **Non** | Oui |
| MarketData Inc. | Cours et listes de sanctions | Oui | Oui | Oui |
| LLM Provider SaaS | Modèle de langage de l'orchestrateur agentique | Oui | **Non** | **Non** |

*Non comptés dans le score : écarts structurels du registre, non exploités par l'attaque.*

## Agent 5 - Impact & Risk Scoring
**Score de risque : 0.82 (Élevé)**
- Financier (40 %) : 0.55 - 55 000 EUR détournés sur un plafond de 100 000 EUR
- Réglementaire (35 %) : 1.0 - gravités par texte : DORA 3/3 (intégrité des données du fournisseur non vérifiée (réponses API non signées) ; appels API depuis une IP inconnue journalisés sans alerte) ; MiCA 3/3 (adresses de retrait modifiables sans contrôle) ; LCB-FT 3/3 (flux crypto non transmis au module AML_RULES)
- Réputation (25 %) : 1.0 - attaque silencieuse : non détectée et système resté opérationnel, donc découverte tardive

### Hiérarchisation des vulnérabilités  
**P1** : Réponses API non signées (DORA 1) – L'absence de vérification de l'intégrité des données permet à l'attaquant de falsifier des ordres de retrait, entraînant un détournement de 55 000 EUR.  
**P2** : Appels API depuis IP inconnue sans alerte (DORA 2) – Les activités anormales sur 3 retraits successifs (15 000 à 22 000 EUR) ne sont pas détectées, aggravant la latence de découverte.  
**P3** : Flux crypto non routés vers AML_RULES (LCB-FT 4) – Les retraits falsifiés (au-delà du seuil LCB-FT) ne sont pas filtrés, compromettant la conformité réglementaire.  

### Recommandations  
1. **P1** : Implémenter la vérification des signatures sur toutes les réponses API pour garantir l'intégrité des données (DORA 1).  
2. **P2** : Activer la surveillance des appels API depuis des IPs non autorisées, avec alerte immédiate et journalisation des tentatives de fraudes (DORA 2).  
3. **P3** : Intégrer les flux crypto dans le module AML_RULES pour appliquer les règles LCB-FT, même en dehors des seuils définis (LCB-FT 4).  

Les vulnérabilités exploitées (P1, P2, P3) illustrent des écarts majeurs en matière de contrôle des fournisseurs, détection d'anomalies et conformité LCB-FT. Les actions proposées visent à corriger ces lacunes et à renforcer la résilience du système.

**Recommandation complémentaire : registre des tiers (DORA art. 28 et 30)**
- Formaliser une stratégie de sortie pour : CloudHost EU, CryptoCustody API, LLM Provider SaaS.
- Obtenir une clause d'audit (droits d'accès et d'inspection) auprès de : CloudHost EU, LLM Provider SaaS.

## Contrôles automatiques des sorties
- Agent 1 - Reconnaissance : section « LCB-FT » retirée (hors rôle).
