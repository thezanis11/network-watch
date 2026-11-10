# Network Watch — résultats

Modèle choisi en validation : **Random Forest**.

| Méthode | F1 | Rappel | Balanced accuracy | Faux positifs |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.944 | 89.54 % | 87.68 % | 14.19 % |
| Isolation Forest | 0.996 | 100.00 % | 62.73 % | 74.54 % |
| Random Forest | 0.990 | 98.24 % | 91.33 % | 15.57 % |
| Random Forest without history | 0.998 | 99.72 % | 91.91 % | 15.90 % |
| Explainable rules | 0.907 | 83.10 % | 84.34 % | 14.41 % |
| Always benign | 0.000 | 0.00 % | 50.00 % | 0.00 % |
| Always malicious | 0.994 | 100.00 % | 50.00 % | 100.00 % |

Prévalence des attaques parmi les labels de test connus : 98.87%.
Consulter le rapport pour les scores par capture et les limites ; les flux inconnus sont exclus des métriques binaires.
