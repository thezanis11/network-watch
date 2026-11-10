# Retrouver et faire évoluer le dépôt

Adresse : https://github.com/thezanis11/network-watch

Le code, les tests, les rapports, les scores de test compressés et les incidents sont publiés. Les journaux bruts, caches de caractéristiques et modèles entraînés restent locaux. Les scripts permettent de les reconstruire.

Pour consulter le rapport sans installation : télécharger le ZIP du dépôt avec **Code → Download ZIP**, extraire les fichiers et ouvrir `reports/index.html`. Pour voir seulement les résultats dans GitHub, ouvrir `reports/RESULTS_FR.md` et les figures.

Pour modifier le projet : enregistrer un commit après les tests puis l'envoyer avec Push. GitHub exécute les tests de logique et de causalité ; le téléchargement des données et le benchmark complet restent des commandes explicites.

Sur cet ordinateur, l'environnement partagé des deux nouveaux projets existe déjà dans le dossier parent `.research-venv`. Depuis le dossier `network-watch`, utiliser `..\.research-venv\Scripts\python.exe` pour reprendre les commandes. Les modèles sont dans `models/` et les données dans `data/`, exclus de Git.

Garder une distinction entre un changement choisi en validation et une amélioration constatée après consultation du test. Une nouvelle évaluation indépendante est nécessaire pour confirmer une généralisation.
