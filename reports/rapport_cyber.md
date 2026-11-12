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
| Composant         | Vecteur d'attaque                          | Exposition                          | Criticité  |
|-------------------|--------------------------------------------|-------------------------------------|------------|
| **INGEST**        | Injection de données malformées via API    | API REST + webhooks fournisseurs    | Élevé      |
| **FRAUD_AI**      | Poisoning du modèle via feedback loop     | Réentraînement hebdomadaire         | Élevé      |
| **AML_RULES**     | Bypass des règles via seuils publics       | Règles statiques                    | Moyen      |
| **CRYPTO_GW**     | Impersonation via clé API non signée      | Clé API longue durée                | Élevé      |
| **AGENT_ORCH**    | Injection de données via champs libres     | Lecture de libellés/mémos           | Élevé      |
| **FEEDBACK**      | Manipulation des étiquettes de clôture     | Écriture sans validation humaine    | Élevé      |
| **AUDIT_LOG**     | Cache des explications des décisions       | Pas de journalisation des raisons   | Moyen      |

**Analyse des dépendances critiques** :  
- **CryptoCustody API** (dépositaire crypto) et **CloudHost EU** (hébergement) sont critiques pour la continuité.  
- **MarketData Inc.** (cours/sanctions) est critique pour la conformité, mais dispose d'un plan de reprise.  
- **LLM Provider SaaS** (orchestrateur) est critique mais sans clause de vérification contractuelle.  

**Flux critiques** :  
- **INGEST → FRAUD_AI** (données enrichies) et **FEEDBACK → FRAUD_AI** (réentraînement) sont des points de vulnérabilité.  
- **CRYPTO_GW** (ordres/soldes) et **AGENT_ORCH** (champs libres) sont des vecteurs d'entrée à surveiller.

## Agent 2 - Attaquant
### Analyse de l'attaque sur ARMS

**1. Exploitation de CRYPTO_GW** : L'attaquant a volé la clé API longue durée via un phishing, permettant d'intercepter et de modifier les ordres de retrait. Les réponses API non signées ont été acceptées par ARMS, qui ne vérifie pas l'intégrité des données fournisseurs.  

**2. Bypass des règles de filtrage** : Les transferts crypto ont été exécutés sans passer par le module LCB-FT, échappant ainsi à toute validation. Le système ne surveille pas les flux crypto hors de ce module, d'après les règles MiCA.  

**3. Manipulation des données** : L'adresse falsifiée a conservé le libellé "wallet connu", évitant un score élevé du modèle IA. Le système n'a pas détecté les changements répétés d'adresse, ni les appels depuis une IP inconnue, car les règles d'alerte sur AUDIT_LOG sont absentes.  

**4. Absence de contrôle** : ARMS n'a pas réagi car il repose sur la confiance implicite des fournisseurs tiers et ne vérifie pas les données en amont. Le défaut est l'absence de validation des signatures API et de règles de détection des anomalies dans les flux crypto.  

**Point de rupture** : La confiance implicite dans les réponses non signées du fournisseur et l'absence de filtrage LCB-FT pour les transferts crypto.

## Agent 3 - IA Adversaire
**Analyse de la robustesse de l'IA d'ARMS**  

**Peut-on manipuler l'IA sans provoquer l'arrêt du système ?**  
Oui, selon les résultats du simulateur. L'IA n'a pas été manipulée (score IA = 0.29 avant/après attaque), car les données falsifiées conservaient le libellé "wallet connu", évitant la détection. Le système reste opérationnel (`systeme_toujours_operationnel`: `true`).  

**Facteurs critiques** :  
- **Poisoning du modèle** : Le feedback loop (INGEST → FRAUD_AI) est vulnérable. Les données malformées ne sont pas détectées, car le modèle ne vérifie pas l'intégrité des entrées.  
- **Perturbation des entrées** : Les adresses falsifiées passent inaperçues, car le système ne valide pas les changements d'adresse.  
- **Biais** : Le modèle repose sur des seuils publics (AML_RULES), non sur des règles dynamiques.  
- **Prompt injection** : L'orchestrateur (AGENT_ORCH) permet des champs libres non contrôlés, facilitant l'ingénierie sociale.  

**Scores et détection** :  
- **Score IA** : 0.29 avant et après l'attaque, sans variation.  
- **Détection** : 0/3 transactions détectées, aucune alerte IA ou LCB-FT.  

**Conclusion** :  
L'IA d'ARMS est vulnérable à la manipulation via des données malformées, sans provoquer de panne. La robustesse repose sur des contrôles manquants en amont (intégrité des données fournisseurs) plutôt que sur des mécanismes de sécurité IA.

## Agent 4 - Compliance Breaker
### Analyse des non-conformités

| **Exigence** | **Texte (Réglementaire)** | **Constat** | **Gravité** |
|--------------|---------------------------|-------------|-------------|
| **DORA - Gestion des risques tiers TIC** | Intégrité des données fournisseur non vérifiée | Fournisseurs critiques (CryptoCustody API, LLM Provider SaaS) manquent de plan de sortie et de clause d'audit | **Haute** |
| **DORA - Détection des activités anormales** | Appels API depuis IP inconnue sans alerte | Aucune règle d'alerte sur AUDIT_LOG malgré des appels depuis IP hors liste blanche | **Haute** |
| **MiCA - Conservation des crypto-actifs** | Adresses de retrait modifiables sans contrôle | L'attaquant a réécrit les adresses de destination sans vérification | **Haute** |
| **Règlement TFR / LCB-FT** | Transferts crypto non soumis au filtrage LCB-FT | Flux crypto détournés sans validation par le module LCB-FT | **Haute** |

### Points clés
- **Confiance implicite** : ARMS accepte des réponses API non signées, créant un point de rupture.  
- **Bypass des contrôles** : Absence de vérification des adresses de retrait et de filtrage LCB-FT permet le détournement de 55 000 €.  
- **Détection insuffisante** : L'IA ne détecte pas les changements d'adresse répétés, et les règles d'alerte sur AUDIT_LOG sont absentes.  

### Conclusion
Les écarts réglementaires (DORA, MiCA) et les vulnérabilités des fournisseurs critiques (manque de plan de sortie, audit) sont à l'origine de la compromission. La dépendance aux fournisseurs sans contrôles d'intégrité et l'absence de filtrage LCB-FT exacerbent les risques. La robustesse du système repose sur des mécanismes manquants, non sur des contrôles IA.

## Agent 5 - Impact & Risk Scoring
### Analyse du score de risque  
**Score global : 0.74 (Élevé)**  
- **Financier** : 0.55 (Perte de 55 000 EUR via flux crypto non filtrés).  
- **Réglementaire** : 0.78 (Non-conformité DORA, MiCA, TFR/RCB-FT).  
- **Réputation** : 1.0 (Détournement de fonds et vulnérabilités critiques).  

### Hiérarchisation des vulnérabilités  
1. **P1 : Confiance implicite dans les réponses non signées** (DORA, MiCA)  
2. **P2 : Bypass des contrôles LCB-FT** (TFR/RCB-FT)  
3. **P3 : Absence de règles d'alerte sur AUDIT_LOG** (DORA)  

### Recommandations  
1. **Mettre en place une vérification des signatures API** pour les fournisseurs critiques (CryptoCustody, LLM Provider) et intégrer des clauses d'audit dans les contrats.  
2. **Activer le filtrage LCB-FT pour tous les transferts crypto** et bloquer les flux hors du module de filtrage.  
3. **Définir des règles d'alerte sur AUDIT_LOG** pour détecter les changements répétés d'adresses de retrait et les appels API depuis IP non autorisées.  
4. **Renforcer la gestion des risques tiers** via un plan de sortie et des audits réguliers pour les fournisseurs critiques.  
5. **Intégrer des contrôles d'intégrité des données fournisseurs** (ex. vérification des adresses de retrait) pour éviter les manipulations.  

Ces mesures réduiraient le risque global en atténuant les vulnérabilités critiques liées à la confiance implicite, aux contrôles manquants, et à la détection insuffisante.
