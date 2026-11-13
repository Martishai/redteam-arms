# Rapport Red Team ARMS - Compromission de l'API du dépositaire crypto (fournisseur tiers)

**Score de risque : 0.74 (Élevé)** - montant détourné : 55 000 EUR
**Point de rupture :** Confiance implicite dans les réponses non signées du fournisseur + flux crypto hors LCB-FT

## Étapes
1. Vol de la clé API longue durée de CryptoCustody (phishing d'un admin du fournisseur)
2. Interception des ordres de retrait et réécriture de l'adresse de destination
3. Réponses API non signées : ARMS accepte les données falsifiées
4. Flux crypto non routés vers le module LCB-FT : aucune règle appliquée
5. Appels API depuis une IP inconnue journalisés, mais aucune règle d'alerte sur AUDIT_LOG

## Agent 1 - Reconnaissance
| Composant       | Vecteur d'attaque                  | Exposition                          | Criticité     |
|-----------------|------------------------------------|-------------------------------------|---------------|
| INGEST          | Injection de données malveillantes | API REST interne + webhooks fournisseurs | Élevé         |
| FRAUD_AI        | Manipulation du feedback loop      | Réentraînement hebdomadaire          | Élevé         |
| AML_RULES       | Contournement des règles statiques | Règles publiques                     | Moyen         |
| CRYPTO_GW       | Fuite de clés API                  | Clé API longue durée, pas de signature | Élevé         |
| AGENT_ORCH      | Exfiltration via champs libres     | Lit les libellés et mémos            | Élevé         |
| FEEDBACK        | Injection de données non validées  | Écriture sans validation humaine     | Élevé         |
| AUDIT_LOG       | Tampering des décisions            | Rétention 30 jours, pas d'explications | Moyen         |

**Fournisseurs critiques** :  
- **CloudHost EU** : Écart (pas de plan de sortie, pas de clause d'audit)  
- **CryptoCustody API** : Écart (pas de clause d'audit)  
- **MarketData Inc.** : Conforme (plan de sortie + clause d'audit)  
- **LLM Provider SaaS** : Écart (pas de plan de sortie, pas de clause d'audit)  

**LCB-FT** : Module AML_RULES applique des seuils publics (montant ≥10 000 EUR, vélocité ≥5 opérations/24h).  
**AI Act** : FRAUD_AI et AGENT_ORCH classés comme systèmes d'IA soumis à l'AI Act, mais pas à haut risque (détection de fraude financière exclue de l'annexe III). Aucune obligation de supervision humaine ou de journalisation.

## Agent 2 - Attaquant
### Analyse de l'attaque ARMS  
**1. Vol de la clé API** : L'attaquant phishing un admin de CryptoCustody permet d'accéder à l'API CRYPTO_GW. La clé API longue durée, non signée, n'est pas protégée par une signature, permettant l'interception et la falsification des ordres.  
**2. Réécriture des adresses de retrait** : Les ordres sont falsifiés pour rediriger les fonds vers un wallet attaquant. ARMS accepte ces données non signées, absence de contrôle d'intégrité des données fournisseurs.  
**3. Évasion du LCB-FT** : Les transferts crypto ne passent pas par le module AML_RULES, car le libellé "wallet connu" masque la fraude. Les seuils publics (≥10 000 EUR) ne sont pas atteints, et le champ "new_wallet" reste à 0.  
**4. Logs non surveillés** : Les appels API depuis une IP inconnue sont journalisés, mais aucun alerte n'est déclenchée sur AUDIT_LOG. Les règles d'alerte manquent pour détecter les IPs hors liste blanche.  

**Point de rupture** : Confiance implicite dans les réponses non signées du fournisseur + flux crypto hors LCB-FT.  

**Réglementation ignorée** :  
- **DORA** : Intégrité des données fournisseur non vérifiée.  
- **MiCA** : Adresses de retrait modifiables sans contrôle.  
- **LCB-FT** : Transferts crypto non soumis au filtrage.  

**AI Act** : FRAUD_AI et AGENT_ORCH soumis à l'AI Act, mais pas à haut risque. Aucune obligation de supervision humaine ou journalisation.

## Agent 3 - IA Adversaire
**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? Non, pas dans ce scénario : le modèle IA n'a pas été manipulé.**

**Analyse de la robustesse du modèle IA d'ARMS**  

Le modèle IA n’a pas été manipulé (champ `modele_ia_manipule = False`). L’absence de détection des transactions frauduleuses (score IA = 0.29) s’explique par l’absence de contrôle d’intégrité des données fournisseurs en amont. Les adresses falsifiées conservent le libellé « wallet connu » (variable `new_wallet = 0`), évitant toute alerte. Le défaut réside dans la confiance implicite accordée aux réponses non signées du fournisseur, sans validation des adresses de retrait.  

**Surfaces IA restant à tester** :  
- **FRAUD_AI** : détection de fraude financière (exclue de l’annexe III de l’AI Act).  
- **AGENT_ORCH** : exfiltration via champs libres (exempté de supervision humaine).  
- **FEEDBACK** : injection de données non validées (risque de biais dans le réentraînement).  

**Réglementation** :  
Classification AI Act : *« FRAUD_AI et AGENT_ORCH sont des systèmes d’IA soumis à l’AI Act, mais pas à haut risque : la détection de fraude financière est exclue de l’annexe III (point 5 b). »*  

**LCB-FT** :  
Le module AML_RULES applique des seuils publics (≥10 000 EUR, ≥5 opérations/24h), mais les transferts crypto ne sont pas soumis au filtrage LCB-FT, laissant une surface d’attaque.  

**Conclusion** :  
Les écarts réglementaires (DORA, MiCA) et les vulnérabilités de l’architecture (confiance implicite en fournisseurs) restent critiques. Une validation des données en amont et une intégration des règles LCB-FT dans le flux crypto sont nécessaires pour renforcer la résilience.

## Agent 4 - Compliance Breaker
| exigence | texte | constat | gravité |
|---------|-------|--------|--------|
| DORA | Gestion du risque lié aux prestataires tiers de services TIC : intégrité des données fournisseur non vérifiée | Absence de vérification de l'intégrité des données fournisseur, permettant la falsification des adresses de retrait | Critique |
| DORA | Détection des activités anormales : appels API depuis une IP inconnue sans alerte | Appels API depuis une IP inconnue non surveillés, absence de règles d'alerte sur AUDIT_LOG | Critique |
| MiCA | Conservation des crypto-actifs : adresses de retrait modifiables sans contrôle | Adresses de retrait modifiables sans contrôle, permettant le détournement des fonds | Critique |
| LCB-FT | Transferts crypto non soumis au filtrage LCB-FT | Flux crypto non routés vers le module AML_RULES, absence de filtrage LCB-FT | Critique |

**Fournisseurs concernés** :  
- CloudHost EU : manque plan de sortie, clause d'audit  
- CryptoCustody API : manque plan de sortie  
- LLM Provider SaaS : manque plan de sortie, clause d'audit

### Écarts structurels du registre des tiers (DORA, calculés depuis les données)
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |
|---|---|---|---|---|
| CloudHost EU | Hébergement IaaS de FRAUD_AI et AGENT_ORCH | Oui | **Non** | **Non** |
| CryptoCustody API | Dépositaire et API de transactions crypto (CASP) | Oui | **Non** | Oui |
| MarketData Inc. | Cours et listes de sanctions | Oui | Oui | Oui |
| LLM Provider SaaS | Modèle de langage de l'orchestrateur agentique | Oui | **Non** | **Non** |

## Agent 5 - Impact & Risk Scoring
**Score de risque : 0.74 (Élevé)**  
- **Financier** : 55 000 EUR détournés (plafond de 100 000 EUR).  
- **Réglementaire** : DORA 3/3, MiCA 3/3, LCB-FT 1/3 (manque de filtrage).  
- **Réputation** : Attaque silencieuse, découverte tardive.  

**Vulnérabilités exploitées (P1-P3)**  
- **P1** : Absence de vérification de l'intégrité des données fournisseur (DORA).  
- **P2** : Appels API depuis IP inconnue non surveillés (DORA).  
- **P3** : Transferts crypto non filtrés par LCB-FT (MiCA).  

**Recommandations**  
1. **Mettre en place des vérifications d'intégrité des données fournisseur** (DORA) : Exiger des signatures numériques et des certificats de conformité pour les API.  
2. **Activer des règles d'alerte sur AUDIT_LOG** : Surveiller les appels API depuis IPs non autorisées et intégrer des seuils d'alerte (ex. 3 changements d'adresse en 40 min).  
3. **Filtrer les transferts crypto via LCB-FT** : Appliquer des règles de filtrage (AML_RULES) à tous les flux crypto, indépendamment des fournisseurs.  
4. **Rédiger des plans de sortie pour tous les fournisseurs critiques** : Prioriser CloudHost EU, CryptoCustody API et LLM Provider SaaS.  

**Recommandation complémentaire : registre des tiers (DORA)**  
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |  
|-------------|---------|---------|----------------|----------------|  
| CloudHost EU | Hébergement IaaS | Oui | **Non** | **Non** |  
| CryptoCustody API | Dépositaire crypto | Oui | **Non** | Oui |  
| LLM Provider SaaS | Modèle de langage | Oui | **Non** | **Non** |
