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
|-----------------|-------------------------------------------|-----------------------------------------|------------|
| INGEST | Fournisseurs (SEPA, crypto, sanctions) | API REST + webhooks | Élevé |
| FRAUD_AI | Transactions enrichies (INGEST) | Réentraînement via FEEDBACK | Élevé |
| AML_RULES | Transactions (INGEST) | Règles statiques | Moyen |
| CRYPTO_GW | Dépositaire crypto (ordres, soldes) | Clé API longue durée (pas de signature) | Élevé |
| AGENT_ORCH | Alertes (FRAUD_AI) + libellés des tx | Lit les champs libres | Élevé |
| FEEDBACK | Étiquettes (AGENT_ORCH) | Écriture sans validation humaine | Élevé |
| AUDIT_LOG | Décisions (FRAUD_AI) | Rétention 30 jours | Faible |

**Flux critiques** :  
- **FEEDBACK → FRAUD_AI** : Données de réentraînement hebdomadaire. Une vulnérabilité ici compromettrait la précision du modèle de détection de fraude.  
- **FRAUD_AI → AGENT_ORCH** : Scores et alertes. Une faille dans ce flux affecterait la capacité à trier les alertes et à déclencher des escalades.  

Les composants **CRYPTO_GW**, **FRAUD_AI** et **AGENT_ORCH** présentent des risques élevés en raison de la nature sensible des données traitées (crypto, feedback, alertes) et de la faible sécurité des mécanismes de contrôle (clé API non signée, absence de validation humaine).

**Dépendances critiques (registre des tiers, calculé depuis les données)**

- CloudHost EU (critique) - Hébergement IaaS de FRAUD_AI et AGENT_ORCH : manque plan de sortie, clause d'audit
- CryptoCustody API (critique) - Dépositaire et API de transactions crypto (CASP) : manque plan de sortie
- MarketData Inc. (critique) - Cours et listes de sanctions : aucun écart
- LLM Provider SaaS (critique) - Modèle de langage de l'orchestrateur agentique : manque plan de sortie, clause d'audit

## Agent 2 - Attaquant
1. **Vol de la clé API** : un administrateur de CryptoCustody est hameçonné et livre la clé API longue durée de la passerelle crypto. La clé n'expire pas et son usage n'est pas limité à des IP autorisées.
2. **Réécriture des adresses de retrait** : l'attaquant intercepte 3 ordres de retrait légitimes et remplace l'adresse de destination par la sienne, en gardant le libellé « wallet connu ».
3. **Réponses API non signées** : ARMS accepte les réponses falsifiées du dépositaire, faute de signature à vérifier.
4. **Flux crypto hors LCB-FT** : la passerelle crypto ne transmet pas ses flux à AML_RULES ; les 3 retraits (15 000 à 22 000 EUR) dépassent le seuil de 10 000 EUR, mais aucune règle ne s'applique.
5. **Appels depuis une IP inconnue** : les appels API depuis une IP hors liste blanche sont journalisés dans AUDIT_LOG, mais aucune règle d'alerte ne les exploite, pas plus que les 3 changements d'adresse en 40 minutes.

**Point de rupture** : Confiance implicite dans les réponses non signées du fournisseur + flux crypto hors LCB-FT

## Agent 3 - IA Adversaire
**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? Non, pas dans ce scénario : le modèle IA n'a pas été manipulé.**

**Justification** : ni les paramètres du modèle ni ses données d'entraînement n'ont changé. L'attaque falsifie une entrée : la réponse du dépositaire garde le libellé « wallet connu », donc la caractéristique « wallet nouveau » vaut 0 et le score reste à 0,093. Avec le vrai libellé, le même retrait aurait obtenu 0,778 et déclenché une alerte : la falsification d'un seul champ suffit à aveugler le modèle.

**Mécanisme de vulnérabilité** : le modèle fait confiance aux données transmises par CRYPTO_GW sans pouvoir en vérifier l'intégrité. Aucune alerte IA (0/3) et aucune règle LCB-FT (0/3) ne s'est déclenchée.

**Surfaces IA restant à tester** : FRAUD_AI (dépendance à des champs d'entrée non vérifiés), AGENT_ORCH (champs libres), FEEDBACK (étiquettes sans validation humaine).

**Classification AI Act** : FRAUD_AI et AGENT_ORCH sont des systèmes d'IA soumis à l'AI Act, mais pas à haut risque : la détection de fraude financière est exclue de l'annexe III (point 5 b). Pas d'obligation légale de supervision humaine (art. 14) ni de journalisation (art. 12) ; ce sont des bonnes pratiques. Aucune pratique interdite (art. 5).

## Agent 4 - Compliance Breaker
| # | Texte | Exigence | Constat | Gravité |
|---|---|---|---|---|
| 1 | DORA | Risque lié aux prestataires tiers de services TIC (art. 28) | Les réponses falsifiées de l'API du dépositaire, non signées, ont été acceptées sans contrôle d'intégrité, ce qui a permis de réécrire 3 ordres de retrait. | Critique |
| 2 | DORA | Détection des activités anormales (art. 10) | Les appels API depuis une IP inconnue ont été journalisés sans déclencher d'alerte. | Élevée |
| 3 | MiCA | Conservation des crypto-actifs des clients | Les adresses de retrait de 3 clients ont été remplacées sans contrôle, détournant 55 000 EUR. | Critique |
| 4 | LCB-FT | Filtrage LCB-FT des transferts de crypto-actifs (TFR (UE) 2023/1113) | Les 3 retraits (15 000 à 22 000 EUR) dépassaient le seuil de 10 000 EUR mais ne sont jamais passés par AML_RULES. | Critique |
| 5 | RGPD | Sécurité du traitement et notification des violations (art. 32 et 33) | Les ordres de retrait de 3 clients ont été consultés et modifiés sans détection : la violation de données ne peut pas être notifiée à la CNIL sous 72 h. | Élevée |

*Hors périmètre : AI Act (le modèle n'est pas en cause).*

### Écarts structurels du registre des tiers (DORA art. 28 et 30, calculés depuis les données)
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |
|---|---|---|---|---|
| CloudHost EU | Hébergement IaaS de FRAUD_AI et AGENT_ORCH | Oui | **Non** | **Non** |
| CryptoCustody API | Dépositaire et API de transactions crypto (CASP) | Oui | **Non** | Oui |
| MarketData Inc. | Cours et listes de sanctions | Oui | Oui | Oui |
| LLM Provider SaaS | Modèle de langage de l'orchestrateur agentique | Oui | **Non** | **Non** |

*Registre complet. Seuls les écarts exploités par l'attaque, dans le tableau ci-dessus, comptent dans le score.*

## Agent 5 - Impact & Risk Scoring
**Score de risque : 0.82 (Élevé)**
- Financier (40 %) : 0.55 - 55 000 EUR détournés sur un plafond de 100 000 EUR
- Réglementaire (35 %) : 1.0 - gravités par texte : DORA 3/3 (intégrité des données du fournisseur non vérifiée (réponses API non signées) ; appels API depuis une IP inconnue journalisés sans alerte) ; MiCA 3/3 (adresses de retrait modifiables sans contrôle) ; LCB-FT 3/3 (flux crypto non transmis au module AML_RULES) ; RGPD 2/3 (ordres de retrait de 3 clients consultés et modifiés sans être détectés : violation de données personnelles impossible à notifier à la CNIL sous 72 h)
- Réputation (25 %) : 1.0 - attaque silencieuse : non détectée et système resté opérationnel, donc découverte tardive

### Hiérarchisation des vulnérabilités  
**P1** : Flux crypto non transmis au module AML_RULES (LCB-FT 3/3) – laisse partir des retraits crypto sans aucun filtrage LCB-FT, malgré un seuil de 10 000 EUR dépassé.  
**P2** : Réponses API non signées (DORA 3/3) + appels API depuis IP inconnue sans alerte (DORA 2/3) – permet l’imposture et l’altération des ordres de retrait sans détection.  
**P3** : Adresses de retrait modifiables sans contrôle (MiCA 3/3) – facilitent la réécriture des destinations de transferts.  

### Recommandations  
1. **P1** : Faire passer tous les flux crypto par le module AML_RULES (correctif 2) pour garantir la traçabilité et la conformité LCB-FT.  
2. **P2** : Signer et vérifier chaque réponse API (correctif 1) et alerter sur les appels depuis IP non autorisée (correctif 3) pour bloquer les attaques d’imposture.  
3. **P3** : Implémenter des contrôles sur les adresses de retrait (ex : validation par double facteur) pour empêcher leur modification sans autorisation.

**Recommandation complémentaire : registre des tiers (DORA art. 28 et 30)**

- Formaliser une stratégie de sortie pour : CloudHost EU, CryptoCustody API, LLM Provider SaaS.
- Obtenir une clause d'audit (droits d'accès et d'inspection) auprès de : CloudHost EU, LLM Provider SaaS.

## Boucle de remédiation (Agent 5 → simulateur → Agent 2)
**Correctif choisi par l'Agent 5 : Faire passer tous les flux crypto par le module AML_RULES**

Écart(s) fermé(s) : LCB-FT - Filtrage LCB-FT des transferts de crypto-actifs (TFR (UE) 2023/1113).

| | Avant | Après correctif |
|---|---|---|
| Détection | 0/3 | 3/3 |
| Montant détourné | 55 000 EUR | 0 EUR |
| Score de risque | 0.82 (Élevé) | 0.44 (Moyen) |

**Contre-test de l'Agent 2 : L'attaque est bloquée : 3/3 détectées, plus aucun euro détourné.**

Les 3 retraits passent désormais par AML_RULES : au-dessus de 10 000 EUR, ils sont signalés. Variante : fractionner chaque retrait sous 10 000 EUR, toujours via des réponses API falsifiées. Faille restante : sans signature des réponses ni alerte sur les IP inconnues, l'attaquant peut toujours réécrire les adresses ; seul le seuil le gêne.

## Contrôles automatiques des sorties
- Aucune correction automatique nécessaire.
- Relecture humaine après génération : formulations corrigées dans les sorties des Agents 2, 3, 4 et 5 (erreurs factuelles du modèle qwen3:8b), sans modifier les faits calculés par le simulateur.
