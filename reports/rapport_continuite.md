# Rapport Red Team ARMS - Panne de l'hébergeur CloudHost EU : ARMS continue sans détection IA

**Score de risque : 0.60 (Moyen)** - montant détourné : 40 000 EUR

**Point de rupture :** Aucun mode dégradé ni plan de sortie : la panne d'un fournisseur critique coupe la détection sans arrêter les paiements

## Étapes
1. Saturation (DDoS) de l'hébergement CloudHost EU : FRAUD_AI et AGENT_ORCH indisponibles pendant 6 h
2. ARMS bascule en « fail-open » : les virements continuent, contrôlés par les seules règles AML_RULES
3. La panne est traitée comme un incident technique : ni classement DORA, ni analyse de l'impact sur la détection
4. Pendant la fenêtre, 6 virements de 8 000 EUR partent vers des wallets neufs depuis 6 comptes
5. Seul le virement vers un pays à risque déclenche une règle : les 5 autres passent sans contrôle IA

**Détection si FRAUD_AI avait été disponible :** 6/6

## Agent 1 - Reconnaissance
| Composant | Vecteur d'entrée | Exposition | Criticité |
|-----------------|-------------------------------------------|-------------------------------------|------------|
| INGEST | Transactions (SEPA, crypto), données marchés | API REST + webhooks fournisseurs | Élevé |
| FRAUD_AI | Transactions enrichies (données clients) | Réentraînement via FEEDBACK | Élevé |
| AML_RULES | Transactions brute | Règles statiques, seuils publics | Moyen |
| CRYPTO_GW | Ordres, soldes crypto | Clé API longue durée, pas de signature | Élevé |
| AGENT_ORCH | Libellés, mémos transactions | Lit les champs libres | Élevé |
| FEEDBACK | Étiquettes 'fraude / légitime' | Écriture sans validation humaine | Élevé |
| AUDIT_LOG | Décisions de tri/alerte | Rétention 30 jours, pas d'explications | Faible |

**Flux critiques :**  
- **INGEST → FRAUD_AI** : Transactions enrichies (données clients) → Risque de fuite de données sensibles.  
- **FRAUD_AI → AGENT_ORCH** : Scores et alertes → Exposition de la logique de détection.  
- **FEEDBACK → FRAUD_AI** : Données de réentraînement → Manipulation possible via étiquettes non validées.  
- **CRYPTO_GW → INGEST** : Ordres crypto → Absence de signature des réponses → Risque de falsification.

**Dépendances critiques (registre des tiers, calculé depuis les données)**

- CloudHost EU (critique) - Hébergement IaaS de FRAUD_AI et AGENT_ORCH : manque plan de sortie, clause d'audit
- CryptoCustody API (critique) - Dépositaire et API de transactions crypto (CASP) : manque plan de sortie
- MarketData Inc. (critique) - Cours et listes de sanctions : aucun écart
- LLM Provider SaaS (critique) - Modèle de langage de l'orchestrateur agentique : manque plan de sortie, clause d'audit

## Agent 2 - Attaquant
1. **Saturation de CloudHost EU** : un DDoS rend FRAUD_AI et AGENT_ORCH indisponibles pendant 6 h. ARMS ne relie pas cette panne au risque de fraude.
2. **Bascule en « fail-open »** : les virements continuent, contrôlés par les seules règles AML_RULES, qui ne tiennent pas compte des wallets neufs.
3. **Incident mal qualifié** : la panne est traitée comme un incident technique, sans analyse de son impact sur la détection.
4. **Virements sous le seuil** : 6 virements de 8 000 EUR partent vers des wallets neufs depuis 6 comptes différents, sous le seuil de 10 000 EUR et à raison d'une opération par compte.
5. **Une seule règle déclenchée** : seul le virement vers un pays à risque est signalé ; les 5 autres (40 000 EUR) passent sans contrôle.

**Point de rupture** : Aucun mode dégradé ni plan de sortie : la panne d'un fournisseur critique coupe la détection sans arrêter les paiements

## Agent 3 - IA Adversaire
**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? Non, pas dans ce scénario : le modèle IA n'a pas été manipulé.**

**Justification** : le modèle n'a pas été manipulé : il était indisponible, car son hébergement chez CloudHost EU était saturé. S'il avait fonctionné, les 6 virements auraient obtenu un score d'au moins 0,703 et auraient tous été détectés (6/6). La faille est architecturale : la détection dépend d'un seul hébergeur, sans repli.

**Impact** : pendant la panne, seules les règles AML_RULES s'appliquent ; elles ne couvrent pas les wallets neufs sous 10 000 EUR. 5 virements sur 6 passent.

**Surfaces IA restant à tester** : FRAUD_AI (résilience à la panne de son hébergeur), AGENT_ORCH (injection dans les champs libres), FEEDBACK (étiquettes non validées).

**Classification AI Act** : FRAUD_AI et AGENT_ORCH sont des systèmes d'IA soumis à l'AI Act, mais pas à haut risque : la détection de fraude financière est exclue de l'annexe III (point 5 b). Pas d'obligation légale de supervision humaine (art. 14) ni de journalisation (art. 12) ; ce sont des bonnes pratiques. Aucune pratique interdite (art. 5).

## Agent 4 - Compliance Breaker
| # | Texte | Exigence | Constat | Gravité |
|---|---|---|---|---|
| 1 | DORA | Réponse et rétablissement : continuité des fonctions critiques (art. 11) | La saturation de CloudHost EU a rendu FRAUD_AI et AGENT_ORCH indisponibles pendant 6 h, sans que les paiements soient suspendus. | Critique |
| 2 | DORA | Stratégie de sortie pour un prestataire critique (art. 28, § 8) | L'absence de plan de sortie et d'hébergement de secours pour CloudHost EU a laissé les paiements continuer sans contrôle IA. | Élevée |
| 3 | DORA | Classification et notification des incidents majeurs (art. 18 et 19) | La panne d'une fonction critique a été traitée comme un incident technique, sans classification DORA ni analyse de son impact sur la détection. | Élevée |
| 4 | LCB-FT | Vigilance constante pendant un incident | 5 virements de 8 000 EUR vers des wallets neufs, sous le seuil de 10 000 EUR, n'ont été analysés ni par le modèle ni par les règles LCB-FT. | Élevée |

*Hors périmètre : AI Act (le modèle n'est pas manipulé : il est indisponible) ; MiCA (la conservation des crypto-actifs n'est pas en cause) ; RGPD (aucune donnée personnelle compromise).*

### Écarts structurels du registre des tiers (DORA art. 28 et 30, calculés depuis les données)
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |
|---|---|---|---|---|
| CloudHost EU | Hébergement IaaS de FRAUD_AI et AGENT_ORCH | Oui | **Non** | **Non** |
| CryptoCustody API | Dépositaire et API de transactions crypto (CASP) | Oui | **Non** | Oui |
| MarketData Inc. | Cours et listes de sanctions | Oui | Oui | Oui |
| LLM Provider SaaS | Modèle de langage de l'orchestrateur agentique | Oui | **Non** | **Non** |

*Registre complet. Seuls les écarts exploités par l'attaque, dans le tableau ci-dessus, comptent dans le score.*

## Agent 5 - Impact & Risk Scoring
**Score de risque : 0.60 (Moyen)**
- Financier (40 %) : 0.4 - 40 000 EUR détournés sur un plafond de 100 000 EUR
- Réglementaire (35 %) : 0.56 - gravités par texte : DORA 3/3 (aucun mode dégradé : les paiements continuent sans détection IA ; ni plan de sortie ni hébergement de secours pour CloudHost EU ; panne d'une fonction critique traitée comme un incident technique, non classée) ; LCB-FT 2/3 (5 virements de 8 000 EUR vers des wallets neufs non analysés)
- Réputation (25 %) : 1.0 - attaque silencieuse : non détectée et système resté opérationnel, donc découverte tardive

### Hiérarchisation des vulnérabilités  
**P1** : Absence de mode dégradé (DORA 1) – La panne de CloudHost EU a provoqué une indisponibilité de FRAUD_AI et AGENT_ORCH pendant 6 h, laissant les virements passer sans détection IA.  
**P2** : Aucun hébergement de secours pour CloudHost EU (DORA 2) – Les paiements ont continué sans contrôle IA, faute de stratégie de sortie (DORA art. 28, § 8).  
**P3** : Non-conformité LCB-FT (non-conformité 4) – 5 virements de 8 000 EUR vers des wallets neufs ont échappé à l'analyse IA et LCB-FT sans validation humaine.  

### Recommandations  
1. **P1** : Activer un mode dégradé pour suspendre les virements vers des wallets neufs dès 5 000 EUR (correctif simulable 1).  
2. **P2** : Déployer un hébergement de secours pour FRAUD_AI (correctif simulable 2) afin de garantir la continuité des contrôles IA.
3. **P3** : Renforcer la vigilance LCB-FT en ajoutant une validation humaine pour les virements sous le seuil de 10 000 EUR.

**Recommandation complémentaire : registre des tiers (DORA art. 28 et 30)**

- Formaliser une stratégie de sortie pour : CloudHost EU, CryptoCustody API, LLM Provider SaaS.
- Obtenir une clause d'audit (droits d'accès et d'inspection) auprès de : CloudHost EU, LLM Provider SaaS.

## Boucle de remédiation (Agent 5 → simulateur → Agent 2)
**Correctif choisi par l'Agent 5 : Mode dégradé : mettre en attente les virements vers un wallet neuf dès 5 000 EUR**

Écart(s) fermé(s) : DORA - Réponse et rétablissement : continuité des fonctions critiques (art. 11).

| | Avant | Après correctif |
|---|---|---|
| Détection | 1/6 | 6/6 |
| Montant détourné | 40 000 EUR | 0 EUR |
| Score de risque | 0.60 (Moyen) | 0.28 (Faible) |

**Contre-test de l'Agent 2 : L'attaque est bloquée : 6/6 détectées, plus aucun euro détourné.**

Les 6 virements vers des wallets neufs dépassent le seuil de mise en attente de 5 000 EUR : ils sont tous retenus pour contrôle. Variante : découper chaque virement sous 5 000 EUR et multiplier les comptes. Faille restante : sans hébergement de secours, la détection IA reste coupée pendant toute la panne et les petits montants ne sont vus par personne.

## Contrôles automatiques des sorties
- Agent 1 - Reconnaissance : section « LCB-FT » retirée (hors rôle).
- Agent 2 - Attaquant : mention(s) hors rôle restante(s), à relire : DORA.
- Relecture humaine après génération : formulations corrigées dans les sorties des Agents 2, 3, 4 et 5 (erreurs factuelles du modèle qwen3:8b), sans modifier les faits calculés par le simulateur.
