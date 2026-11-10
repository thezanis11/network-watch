# Comprendre et présenter Network Watch

## Démonstration de cinq minutes

1. Ouvrir le rapport et expliquer la différence entre paquet, flux terminé, alerte et incident.
2. Montrer les prédictions triviales. Le F1 de « tout malveillant » est élevé à cause du déséquilibre : expliquer pourquoi ce n'est pas un bon détecteur.
3. Examiner séparément le malware, le grand scan et le trafic utilisateur connu. Montrer les fausses alertes.
4. Filtrer les incidents, ouvrir le CSV et expliquer le regroupement sans labels.
5. Montrer un test de causalité et la commande de reproduction des modèles.

## Questions d'entretien

- **Pourquoi ne pas utiliser les IP dans le modèle ?** Pour réduire la mémorisation des machines du laboratoire. Elles restent utiles pour les fenêtres et la corrélation.
- **Pourquoi Background n'est-il pas bénin ?** Les auteurs ne connaissent pas sa classe avec certitude. Lui donner un label négatif inventerait de la vérité terrain.
- **Pourquoi début + durée ?** On ne connaît les statistiques finales d'un flux qu'après l'avoir observé. Utiliser ces totaux à son premier paquet donnerait une anticipation artificielle.
- **Pourquoi le F1 ne suffit-il pas ?** La majorité des flux de test connus sont malveillants ; une prédiction constante peut avoir un F1 excellent. Balanced accuracy, MCC et taux de faux positifs apportent d'autres informations.
- **Pourquoi ne pas choisir le meilleur modèle du test ?** Cela utiliserait le test pour la sélection. Ici, le modèle retenu reste celui choisi en validation, même si une ablation est meilleure au test.
- **Le nombre d'incidents est-il une vérité métier ?** Non. C'est le résultat d'une règle de corrélation documentée. Les épisodes de référence sont eux aussi dérivés des labels, pas annotés par un analyste.

## Contributions personnelles utiles

Tester des journaux d'une autre infrastructure ; ajouter une déduplication EVE par flow_id et cycle de vie ; étudier plusieurs politiques de corrélation ; comparer un seuil ajusté à un budget réel d'alertes ; intégrer une source de vérité terrain indépendante.

## Formulation CV après appropriation

« Network Watch — Développement assisté d'une chaîne Python d'analyse Zeek/Suricata : caractéristiques causales, comparaison de détecteurs sur captures CTU réelles, gestion des labels incertains, évaluation du déséquilibre et corrélation d'alertes en incidents. »

Ajouter un score uniquement avec son protocole et son taux de fausses alertes. Décrire les parties personnellement revues ou modifiées, et l'assistance IA utilisée. Ne pas présenter le prototype comme un SOC opérationnel.
