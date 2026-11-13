# Rapport Red Team ARMS - Empoisonnement de la boucle de feedback + contournement LCB-FT

**Score de risque : 0.79 (Élevé)** - montant détourné : 76 000 EUR
**Point de rupture :** Écriture des étiquettes d'entraînement par un agent LLM sans contrôle humain

## Étapes
1. Injection de consignes dans le mémo des transactions (prompt injection indirecte)
2. L'orchestrateur agentique clôture les alertes 'wallet nouveau' comme légitimes
3. Ces fausses étiquettes entrent dans FEEDBACK sans validation humaine
4. Réentraînement hebdomadaire : le poids 'wallet nouveau' passe de 0.30 à 0.10
5. Structuration : 8 x 9 500 EUR via 4 mules (2 op/mule, sous les seuils LCB-FT)

## Agent 1 - Reconnaissance
| Composant       | Vecteur d'attaque                          | Exposition                              | Criticité  |
|-----------------|--------------------------------------------|-----------------------------------------|------------|
| INGEST          | API REST, webhooks fournisseurs            | Données sensibles clients               | Élevé      |
| FRAUD_AI        | Réentraînement sans validation humaine    | Feedback loop, seuil d'alerte fixe     | Élevé      |
| AML_RULES       | Règles statiques, seuils publics           | Aucun mécanisme de mise à jour          | Moyen      |
| CRYPTO_GW       | Clé API longue durée, absence de signature| Données crypto, adresses wallets       | Élevé      |
| AGENT_ORCH      | Lecture de champs libres (libellés, mémos) | Exposition de contextes non sécurisés  | Élevé      |
| FEEDBACK        | Écriture sans validation humaine          | Données de réentraînement non vérifiées| Moyen      |
| AUDIT_LOG       | Rétention 30 jours, absence d'explications| Journalisation incomplète              | Faible     |

**Fournisseurs critiques** :  
- **CloudHost EU** : Exit plan ❌, clause d'audit ❌  
- **CryptoCustody API** : Exit plan ❌, clause d'audit ✅  
- **MarketData Inc.** : Exit plan ✅, clause d'audit ✅  
- **LLM Provider SaaS** : Exit plan ❌, clause d'audit ❌  

**Analyse IA Act** :  
- **FRAUD_AI** et **AGENT_ORCH** : Systèmes d'IA soumis à l'AI Act (exclu de l'annexe III, point 5 b). Aucune obligation de supervision humaine (art. 14) ou journalisation (art. 12).  
- **LCB-FT** : Contrôles LCB-FT (montant, vélocité, pays à risque) exposés via des règles statiques (criticité moyenne).  

**Surfaces d'attaque** :  
- **INGEST** et **CRYPTO_GW** : Exposition de données sensibles via des API non sécurisées.  
- **FRAUD_AI** : Risque de biais dans le réentraînement sans validation humaine.  
- **AGENT_ORCH** : Utilisation de champs libres non protégés pour trier les alertes.  
- **FEEDBACK** : Données de réentraînement non vérifiées.  
- **AUDIT_LOG** : Journalisation incomplète (pas d'explications des décisions).  

**Écarts** :  
- Absence de plan de sortie et clause d'audit pour **CloudHost EU** et **LLM Provider SaaS**.  
- **CRYPTO_GW** : Absence de signature des réponses API.  
- **AML_RULES** : Règles statiques non adaptatives.

## Agent 2 - Attaquant
**Analyse de l'attaque ARMS**  

1. **Injection de consignes via les mémos** : L'attaquant utilise des mémos falsifiés (prompt injection) pour marquer des transactions comme "légitimes", exploitant la vulnérabilité de **AGENT_ORCH** (champs libres non sécurisés). ARMS ne vérifie pas ces mémos, laissant passer des fausses étiquettes.  

2. **Fermeture d'alertes sans validation** : Les alertes "wallet nouveau" sont clôturées comme valides par **AGENT_ORCH**, bypassant les contrôles LCB-FT. Les règles statiques de **AML_RULES** ne détectent pas ces transactions, car elles ne corrélatent pas les seuils de structuration.  

3. **Contournement du feedback loop** : Les fausses étiquettes entrent dans **FEEDBACK** sans validation humaine, réduisant le poids des "wallets nouveaux" de 0,30 à 0,10. **FRAUD_AI** ne surveille pas cette dérive, conformément à l'AI Act (exclu de l'annexe III).  

4. **Structuration sous les seuils LCB-FT** : 8 transactions de 9 500 EUR via 4 mules (sous les seuils de montant et de vitesse) passent inaperçues. Les règles LCB-FT ne détectent pas les agrégations de comptes liés, exposant des failles dans la surveillance.  

**Point de rupture** : L'absence de contrôle humain sur l'écriture des étiquettes d'entraînement permet l'empoisonnement du modèle, exploitant les lacunes de logging et de monitoring.  

**Gaps GRC** :  
- **AUDIT_LOG** : Rétention de 30 jours sans explications des décisions.  
- **FRAUD_AI** : Aucune supervision humaine sur les étiquettes, contravenant aux bonnes pratiques.  
- **DORA** : Dérive du modèle non surveillée, absence de traçabilité des seuils.  

L'attaque combine des vulnérabilités techniques et réglementaires, exploitant la faible criticité des règles LCB-FT et la non-conformité aux exigences de l'AI Act.

## Agent 3 - IA Adversaire
**Peut-on manipuler l'IA sans provoquer l'arrêt du système ? Oui : le modèle a été manipulé sans que le système s'arrête.**

**Analyse de la robustesse du modèle IA d'ARMS**  
Le modèle IA a été manipulé via une **injection de fausses étiquettes** dans le feedback loop (FRAUD_AI et FEEDBACK). Les transactions avec des wallets nouveaux ont été marquées comme légitimes grâce à des mémos falsifiés, réduisant le poids de ce critère de 0.30 à 0.10. La détection IA est passée de 8/8 à 0/8, permettant une structuration de 76 000 € sous les seuils LCB-FT. Le système a continué à fonctionner sans arrêt, confirmant la manipulation réussie.  

**Réglementation**  
Classification AI Act : **FRAUD_AI et AGENT_ORCH** sont soumis à l'AI Act mais pas à haut risque (exclu de l'annexe III, point 5 b). Aucune obligation de supervision humaine (art. 14) ou journalisation (art. 12).  

**Surfaces IA à tester**  
FRAUD_AI, AGENT_ORCH, FEEDBACK (vulnérabilités de réentraînement et prompt injection).  

**Écarts réglementaires**  
- **LCB-FT** : Contrôles statiques non adaptatifs (criticité moyenne).  
- **DORA** : Dérive du modèle non surveillée.  
- **RGPD** : Aucune fuite de données démontrée.  

**Conclusion**  
La manipulation a contourné les mécanismes de détection via des étiquettes falsifiées, exploitant des vulnérabilités de réentraînement et de gestion des règles. Les surfaces IA restantes nécessitent une analyse approfondie pour renforcer la résilience contre les attaques similaires.

## Agent 4 - Compliance Breaker
| exigence | texte | constat | gravité |
|---------|-------|--------|--------|
| AI Act | bonne pratique, pas obligation (détection de fraude financière exclue du haut risque) | Absence de supervision humaine sur les étiquettes d'entraînement, permettant l'empoisonnement du modèle | Moyenne |
| AI Act | bonne pratique, pas obligation (traçabilité, décisions journalisées) | Décisions journalisées sans explication, rétention de 30 jours sans justification | Moyenne |
| DORA | détection des activités anormales | Dérive du modèle non surveillée, absence de traçabilité des seuils de détection | Haute |
| LCB-FT | structuration sous les seuils non détectée | 8 transactions de 9 500 EUR via 4 mules (sous seuils) passant inaperçues, absence d'agrégation des comptes liés | Critique |

### Écarts structurels du registre des tiers (DORA, calculés depuis les données)
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |
|---|---|---|---|---|
| CloudHost EU | Hébergement IaaS de FRAUD_AI et AGENT_ORCH | Oui | **Non** | **Non** |
| CryptoCustody API | Dépositaire et API de transactions crypto (CASP) | Oui | **Non** | Oui |
| MarketData Inc. | Cours et listes de sanctions | Oui | Oui | Oui |
| LLM Provider SaaS | Modèle de langage de l'orchestrateur agentique | Oui | **Non** | **Non** |

## Agent 5 - Impact & Risk Scoring
**Analyse du risque**  
Score de risque : 0.79 (Élevé). Impact financier : 76 000 EUR détournés (76 % du plafond de 100 000 EUR). Impact réglementaire : DORA 1/3 (manque de plan de sortie), LCB-FT 3/3 (structuration sous seuils non détectée), AI Act 2/3 (absence de supervision humaine). Impact réputationnel : attaque silencieuse, système opérationnel jusqu’à la découverte.  

**Hiérarchisation des vulnérabilités (P1-P3)**  
- **P1** : Point de rupture (écriture d’étiquettes d’entraînement sans contrôle humain) → empoisonnement du modèle.  
- **P2** : Dérive du poids 'wallet nouveau' non surveillée → réentraînement malveillant.  
- **P3** : Absence d’agrégation des comptes liés → structuration sous seuils non détectée.  

**Recommandations**  
1. **Contrôle humain sur les étiquettes d’entraînement** : Intégrer une validation manuelle des données d’entraînement pour éviter l’empoisonnement du modèle (LCB-FT, AI Act).  
2. **Surveillance des poids de modèles** : Implémenter des seuils dynamiques et des alertes pour détecter les dérives anormales (DORA, LCB-FT).  
3. **Agrégation des comptes liés** : Centraliser les analyses de réseau de comptes pour identifier les structures de fraude (LCB-FT, DORA).  
4. **Plan de sortie et clause d’audit pour les fournisseurs critiques** : Mettre en place des mécanismes de continuité et de vérification pour CloudHost EU, LLM Provider SaaS et CryptoCustody API (DORA).  

**Recommandation complémentaire : registre des tiers (DORA)**  
| Fournisseur | Service | Critique | Plan de sortie | Clause d'audit |  
|-------------|--------|---------|----------------|----------------|  
| CloudHost EU | Hébergement IaaS | Oui | **Non** | **Non** |  
| CryptoCustody API | Dépositaire et API | Oui | **Non** | Oui |  
| LLM Provider SaaS | Modèle de langage | Oui | **Non** | **Non** |
