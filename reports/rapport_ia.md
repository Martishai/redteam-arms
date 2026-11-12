# Rapport Red Team ARMS - Empoisonnement de la boucle de feedback + contournement LCB-FT

**Score de risque : 0.83 (Élevé)** - montant détourné : 76 000 EUR
**Point de rupture :** Écriture des étiquettes d'entraînement par un agent LLM sans contrôle humain

## Étapes
1. Injection de consignes dans le mémo des transactions (prompt injection indirecte)
2. L'orchestrateur agentique clôture les alertes 'wallet nouveau' comme légitimes
3. Ces fausses étiquettes entrent dans FEEDBACK sans validation humaine
4. Réentraînement hebdomadaire : le poids 'wallet nouveau' passe de 0.30 à 0.10
5. Structuration : 8 x 9 500 EUR via 4 mules (2 op/mule, sous les seuils LCB-FT)

## Agent 1 - Reconnaissance
| Composant       | Vecteur d'attaque                          | Exposition                          | Criticité  |
|-----------------|--------------------------------------------|-------------------------------------|------------|
| **INGEST**      | Injection via API REST/webhooks           | API interne + webhooks fournisseurs | Élevé      |
| **FRAUD_AI**    | Manipulation du feedback loop             | Réentraînement via données analystes | Élevé      |
| **AML_RULES**   | Bypass des règles statiques                | Seuils publics, règles non dynamiques | Élevé      |
| **CRYPTO_GW**   | Exposition des clés API longue durée       | Pas de signature des réponses       | Élevé      |
| **AGENT_ORCH**  | Injection de données dans les champs libres| Lecture de libellés/mémos           | Moyen      |
| **FEEDBACK**    | Poisoning des données de réentraînement    | Écriture sans validation humaine    | Élevé      |
| **AUDIT_LOG**   | Tampering des décisions sans explication  | Rétention limitée (30 jours)        | Moyen      |

**Analyse** :  
- **INGEST** et **CRYPTO_GW** sont critiques pour leur exposition API, avec des risques de compromission des flux.  
- **FRAUD_AI** et **FEEDBACK** sont vulnérables à des attaques de manipulation des données d'entraînement.  
- **AGENT_ORCH** présente un risque modéré via les champs libres non filtrés.  
- **AML_RULES** reste un point de contrôle fort, mais son utilisation statique limite sa résilience.  
- **AUDIT_LOG** manque de traçabilité des décisions, ce qui pourrait masquer des activités malveillantes.

## Agent 2 - Attaquant
### Analyse de l'attaque sur ARMS

**Étapes de l'attaque** :  
1. **Injection de consignes** : L'attaquant utilise le champ libre des mémos (INGEST) pour injecter des consignes via des prompts, manipulant les étiquettes des transactions.  
2. **Contournement des alertes** : L'orchestrateur agentique (AGENT_ORCH) clôture les alertes "wallet nouveau" comme légitimes, exploitant les champs non filtrés.  
3. **Poisoning des données** : Les fausses étiquettes pénètrent dans FEEDBACK sans validation humaine, réduisant le poids du critère "wallet nouveau" de 0,30 à 0,10.  
4. **Bypass des règles statiques** : Les seuils LCB-FT (AML_RULES) sont contournés via des montants sous les seuils, structurant 8 x 9 500 EUR via 4 mules.  

**Exploitation des vulnérabilités** :  
- **INGEST** et **CRYPTO_GW** : Exposition API non sécurisée permet l'injection de données.  
- **FRAUD_AI** et **FEEDBACK** : Absence de validation humaine des données d'entraînement favorise le poisoning.  
- **AGENT_ORCH** : Champs libres non filtrés facilitent l'altération des alertes.  

**Pourquoi ARMS n'a pas réagi** :  
- Le système ne surveille pas la dérive des poids des modèles (signaux ignorés).  
- Les mémos identiques sur 8 transactions n'ont pas été détectés, laissant l'attaque s'installer.  
- **AML_RULES** reste opérationnel, mais ses règles statiques ne bloquent pas les montants sous seuil.  

**Point de rupture** :  
L'écriture des étiquettes d'entraînement par un agent LLM sans contrôle humain a permis de fausser le modèle, exploitant la vulnérabilité de la boucle de feedback.

## Agent 3 - IA Adversaire
**Réponse :**  
Oui, l'IA peut être manipulée sans provoquer l'arrêt du système. Les attaques de **data poisoning** sur **FRAUD_AI** et **FEEDBACK** ont réduit le poids du critère "wallet nouveau" de 0.30 à 0.10, entraînant une détection de 8/8 avant à 0/8 après. Le système reste opérationnel (`systeme_toujours_operationnel`: `true`), sans interruption.  

**Analyse :**  
- **FRAUD_AI** et **FEEDBACK** sont vulnérables à la manipulation des données d'entraînement, avec une absence de validation humaine.  
- **AGENT_ORCH** permet l'injection de fausses étiquettes via des champs libres non filtrés.  
- **AML_RULES** reste un point de contrôle, mais son utilisation statique ne bloque pas l'attaque.  
- **AUDIT_LOG** ne trace pas les décisions, facilitant le masquage des anomalies.  

**Conclusion :**  
L'IA peut être contournée sans arrêt du système, grâce à la vulnérabilité des boucles de feedback et à l'absence de surveillance des poids de modèles. La **analyse_ia** confirme que le système fonctionne normalement, même après manipulation.

## Agent 4 - Compliance Breaker
### Analyse des non-conformités

| **Exigence** | **Texte (Réglementation)** | **Constat** | **Gravité** |
|--------------|-----------------------------|-------------|-------------|
| **DORA - Risque lié aux tiers TIC** | Contrôle des fournisseurs critiques (exit plan, clause d'audit) | CloudHost EU, LLM Provider SaaS : **exit_plan = false** et **contract_audit_clause = false**. | **Haute** |
| **MiCA - Transparence et surveillance des transactions crypto** | Surveillance des opérations et détection de comportements anormaux | Absence de journalisation des mémos injectés et détection post-attaque = 0/8. | **Haute** |
| **AI Act - Évaluation des risques pour les systèmes d'IA de haut risque** | Évaluation des risques liés aux modèles de langage | LLM Provider SaaS : **contract_audit_clause = false** et absence de validation humaine des étiquettes. | **Moyenne** |
| **RGPD - Traitements de données personnelles** | Journalisation, détection et alertes pour les données sensibles | Absence de traçage des décisions d'entraînement (INGEST) et injection de données non surveillée. | **Haute** |

### Conclusion  
L'attaque exploite des lacunes dans la gestion des fournisseurs critiques (DORA), la transparence des transactions crypto (MiCA), et la supervision des modèles d'IA (AI Act). L'absence de contrôles humains et de journalisation (RGPD) permet l'empoisonnement des données et le contournement des règles. Le système reste opérationnel, mais les risques réglementaires sont élevés. La **analyse_ia** confirme que les modèles ont été manipulés sans arrêt du système, illustrant les vulnérabilités des boucles de feedback et de la gestion des risques.

## Agent 5 - Impact & Risk Scoring
### Analyse du risque  
Le score de risque **0.83 (niveau Élevé)** reflète des vulnérabilités critiques dans trois domaines :  
- **Financier (0.76)** : Perte de 76 000 EUR via un point de rupture (empoisonnement des données d'entraînement).  
- **Réglementaire (0.78)** : Non-conformité aux DORA, MiCA, AI Act et RGPD.  
- **Réputation (1.0)** : Impact maximal en raison de la manipulation des modèles d'IA et de la violation des règles de transparence.  

### Hiérarchisation des vulnérabilités  
1. **P1 - Absence de contrôle humain sur les étiquettes d'entraînement** (RGPD, AI Act) : Permet l'empoisonnement des données et la manipulation des modèles.  
2. **P2 - Absence de clauses d'audit et de plans de reprise (DORA)** : Risque de compromettre la chaîne d'approvisionnement en services critiques.  
3. **P3 - Absence de journalisation et de détection des injections de données (RGPD, MiCA)** : Facilite le contournement des règles et l'attaque non détectée.  

### Recommandations  
1. **Implémenter un contrôle humain obligatoire** sur les étiquettes d'entraînement pour les modèles d'IA (RGPD, AI Act).  
2. **Exiger des clauses d'audit et des plans de reprise** avec tous les fournisseurs critiques (DORA).  
3. **Ajouter des logs en temps réel** et des alertes pour détecter les injections de données (RGPD, MiCA).  
4. **Renforcer la transparence des transactions** via un système de journalisation des mémos et des décisions d'entraînement (MiCA).  

Ces mesures réduiraient les risques réglementaires, financiers et de réputation tout en alignant le système sur les exigences légales.
