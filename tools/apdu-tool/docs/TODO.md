# Refonte d'APDU Tool

Cette feuille de route transforme progressivement `apdu-tool` en client APDU
brut, client GlobalPlatform de haut niveau et terminateur de Secure Channels.

Les tâches sont classées dans l'ordre recommandé. Chaque étape doit préserver
les tests de transport et T=0 existants.

## 1. Poser les contrats et protéger l'existant

- [x] Capturer dans des tests d'intégration le comportement actuel sur TCP,
  socket Unix et port série simulé.
- [x] Ajouter des tests pour les quatre cas APDU T=0 court : sans entrée ni
  sortie, entrée seule, sortie seule, entrée et sortie.
- [x] Couvrir les octets NULL, `61xx` suivi de `GET RESPONSE`, `6Cxx`, les
  status words immédiats, les réponses tronquées et les délais d'attente.
- [x] Séparer les types représentant le transport, le protocole T=0, une APDU
  logique, une commande CLI et son rendu.
- [x] Définir une taxonomie d'erreurs distinguant connexion, silence du SE,
  désynchronisation, erreur T=0, erreur Secure Channel et status word GP.
- [x] Définir les conventions `stdout`, `stderr` et codes de sortie.
- [x] Ajouter des tests de non-régression pour `-v`, `-vv` et les options de
  liaison existantes.

## 2. Introduire les sous-commandes

- [x] Remplacer le parseur ad hoc par un modèle de CLI structuré pouvant gérer
  les sous-commandes et leurs options mutuellement exclusives.
- [x] Ajouter les sous-commandes `atr` et `raw`.
- [x] Rendre les sous-commandes obligatoires et retirer la syntaxe historique,
  ses options de liaison et la génération implicite de données.
- [x] Accepter en mode `raw` les octets séparés par espaces, les deux-points et
  une chaîne hexadécimale continue.
- [x] Ajouter `raw --file` et `raw --stdin`.
- [x] Valider localement la longueur, `Lc`, `Le` et les contraintes T=0 avant
  d'ouvrir la liaison.
- [x] Ajouter une représentation d'APDU logique dont `Lc` est calculé par
  l'outil, tout en conservant un mode wire strict pour les tests bas niveau.
- [x] Actualiser `--help` et les exemples d'utilisation.

## 3. Séparer ATR et échange APDU

- [x] Faire de `atr` le seul mode qui attend spontanément un ATR.
- [x] En mode `atr`, réessayer la connexion tant que l'endpoint n'est pas
  disponible et que le délai de connexion n'est pas expiré.
- [x] Après connexion, attendre le premier octet puis collecter l'ATR jusqu'à
  la période d'inactivité de fin de trame.
- [x] Ne transmettre aucun octet dans le mode `atr`.
- [x] Faire en sorte que `raw` et toutes les commandes symboliques transmettent
  immédiatement après l'ouverture du lien, sans lecture préalable d'ATR.
- [x] Détecter autant que possible un ATR résiduel reçu à la place d'une
  réponse, signaler la désynchronisation et proposer `apdu-tool atr`.
- [x] Ajouter `--connect-timeout`, `--atr-timeout`, `--response-timeout` et
  `--retry-interval` avec unités explicites et valeurs par défaut documentées.
- [x] Tester le scénario QEMU `server=on,wait=on`, un SE déjà démarré, un SE
  silencieux et un endpoint absent.

## 4. Ajouter la progression interactive

- [x] Créer un composant de progression réutilisable pour les attentes d'ATR
  et de réponse.
- [x] Animer la séquence `-`, `\`, `|`, `/` deux fois par seconde pendant
  l'attente des octets de l'ATR, sans perturber le délai du transport.
- [x] Faire avancer l'animation de réponse uniquement à la réception d'un
  octet de procédure T=0 `NULL` (`60`).
- [x] Écrire exclusivement la progression sur `stderr`, avec `\r` pour
  réécrire la même ligne.
- [x] Effacer proprement l'animation avant un résultat ou une erreur.
- [x] Ne produire aucune progression par défaut et l'activer exclusivement
  avec `--progress`.
- [x] Tester le rendu activé et vérifier qu'aucun octet n'est produit lorsque
  la progression est désactivée.

## 5. Stabiliser la sortie et l'automatisation

- [x] Ajouter `--quiet` pour ne produire sur `stdout` que les octets bruts en
  hexadécimal, sans couleur, commentaire, verbose ni progression.
- [x] Ajouter `--output human|color|json|bin`, avec `human` par défaut.
- [x] En mode `color`, produire uniquement les octets bruts colorés : données
  en bleu, métadonnées TL en rose, succès en vert et échec en rouge.
- [x] En mode `human`, produire un champ coloré par ligne suivi d'un commentaire
  `#` décrivant sa nature.
- [x] Définir et tester les schémas JSON ATR, réponse et erreur structurée.
- [x] En mode `bin`, écrire exclusivement les données binaires utiles sur
  `stdout`, sans NULL T=0, verbose, progression ni status word.
- [x] En mode `bin`, écrire un status word différent de `9000` sur `stderr`.
- [x] Associer un code de sortie non nul aux erreurs de transport, de protocole
  et aux status words d'échec.
- [x] Ajouter un décodeur symbolique des status words pour les commentaires du
  mode `human`, tout en conservant leur valeur hexadécimale.
- [x] Ne pas ajouter de mécanisme `--allow-sw` : tout status word reste visible
  dans les modes textuels et JSON.

## 7. Créer la couche GlobalPlatform commune

- [x] Ajouter l'espace de sous-commandes `gp`.
- [x] Centraliser les constantes CLA, INS, P1, P2 et les encodeurs LV/TLV
  GlobalPlatform déjà reproduits dans le code de test de `xtask`.
- [x] Extraire ou partager les décodeurs GP existants au lieu de maintenir deux
  implémentations divergentes entre `xtask` et `apdu-tool`.
- [x] Définir un type de résultat GP conservant données, status word et champs
  décodés.
- [x] Tester les encodeurs et décodeurs avec les vecteurs APDU déjà employés
  par les campagnes QEMU.

## 8. Implémenter la consultation GP

- [x] Implémenter `gp get-data <TAG>` avec `--format hex|binary|tlv`.
- [x] Ajouter `gp get-data <TAG> --output <fichier>`.
- [x] Décoder les Card Recognition Data et Card Capability Information.
- [x] Implémenter `gp get-status` pour l'Issuer Security Domain, les Security
  Domains, applications, packages et modules pris en charge.
- [x] Ajouter les filtres par AID.
- [x] Gérer automatiquement les occurrences suivantes et la pagination de
  `GET STATUS`.
- [x] Décoder les cycles de vie, privilèges et relations entre objets.
- [x] Proposer une sortie tabulaire humaine et une sortie JSON stable.

## 9. Implémenter les mutations du registry

- [x] Implémenter `gp store-data <TAG> --data <HEX>`.
- [x] Ajouter `--input <fichier>` et `--stdin`, mutuellement exclusifs avec
  `--data`.
- [ ] Segmenter automatiquement les données lorsque la commande ou le Secure
  Channel réduit la taille utile d'une APDU. Bloqué tant que le profil
  Oxide SE ne définit pas de réassemblage transactionnel de `STORE DATA` ;
  l'outil refuse actuellement ces données avant connexion.
- [x] Implémenter `gp delete-data <TAG>` sans exposer l'AID synthétique interne
  du registry Oxide SE.
- [x] Implémenter `gp delete --aid <AID>` pour les packages et instances.
- [x] Implémenter `gp set-status <type> <AID> <état>` avec noms symboliques.
- [x] Valider localement les combinaisons type/état manifestement invalides.
- [ ] Documenter et tester reprise, abandon et absence de publication partielle
  après introduction du protocole de mutation segmentée. Les mutations courtes
  actuelles restent atomiques.

## 10. Ajouter la gestion des clés GP

- [x] Implémenter `gp put-key` avec version, identifiant, usage et fichier de
  clé.
- [x] Prendre en charge plusieurs entrées dans une même commande `PUT KEY`.
- [x] Gérer au minimum les usages SCP03 `ENC` et `MAC`. Ajouter `DEK` seulement
  si le profil
  Oxide SE l'emploie.
- [x] Ajouter les types de clés et identifiants nécessaires à SCP11 :
  `SK.SD.ECKA` et `PK.CA-KLOC.ECDSA`, versionnés et persistés par Security
  Domain, avec repli explicite sur les clés de développement pour l'amorçage.
- [ ] Calculer et vérifier le KCV lorsque le format de clé le prévoit.
- [ ] Ajouter le wrapping des nouvelles clés sous `DEK` lorsqu'il devient
  nécessaire.
- [x] Garantir qu'aucun secret n'apparaît dans les logs, erreurs, sorties
  verbeuses ou fichiers de test produits.
- [x] Accepter `--key` pour le débogage en émettant un avertissement sur
  `stderr`; recommander `--key-file` et avertir lorsque ses permissions Unix
  autorisent l'accès au groupe ou aux autres utilisateurs.
- [ ] Tester création, rotation, sélection de version, suppression et rollback
  sur erreur.

## 11. Définir l'abstraction Secure Channel

- [x] Créer une interface commune pour établir, protéger, déprotéger et fermer
  une session Secure Channel.
- [x] Faire porter à la session la sélection du Security Domain, les clés de
  session, compteurs, chaînes MAC et niveau de sécurité.
- [x] Conserver la même connexion et la même session pendant toute opération
  composée.
- [x] Définir le comportement après MAC invalide, reçu invalide, réponse
  tronquée, timeout et perte de connexion.
- [x] Empêcher toute réutilisation accidentelle d'un compteur ou d'une session
  invalidée.
- [x] Calculer la taille de données APDU disponible après ajout des objets de
  secure messaging.
- [x] Exposer les options communes `--secure-channel`, `--security-domain`,
  `--security-level` et `--credentials`.
- [x] Ajouter des tests unitaires indépendants du transport avec vecteurs
  déterministes.

Les options de contexte réutilisables acceptent une variable d'environnement
`APDU_*`, avec la priorité CLI > environnement > défaut. Les variables déjà
actives et celles réservées aux étapes suivantes sont documentées dans le
README. Aucun secret brut ne doit être lu depuis l'environnement : seules des
références vers des fichiers de credentials, keysets ou trust stores y sont
admises.

## 12. Implémenter SCP03

- [x] Ajouter le chargement sûr d'un keyset SCP03 depuis un fichier de
  configuration.
- [x] Implémenter `INITIALIZE UPDATE` côté hôte.
- [x] Dériver `S-ENC`, `S-MAC` et `S-RMAC` selon le profil sélectionné.
- [x] Vérifier le cryptogramme du SE et produire le cryptogramme de l'hôte.
- [x] Implémenter `EXTERNAL AUTHENTICATE` avec C-MAC.
- [x] Implémenter SCP03 S8.
- [x] Implémenter SCP03 S16.
- [x] Protéger les commandes par C-MAC.
- [x] Ajouter C-ENC et son compteur de chiffrement.
- [x] Vérifier R-MAC et prendre en charge R-ENC lorsque le profil Oxide SE le
  permet.
- [x] Implémenter les débuts et fins de session R-MAC nécessaires : pour les
  profils Oxide SE, la chaîne R-MAC démarre avec le C-MAC de `EXTERNAL
  AUTHENTICATE`; les commandes GP `BEGIN/END R-MAC SESSION` sont explicitement
  hors profil et aucune commande supplémentaire ne doit être émise.
- [x] Vérifier les vecteurs publics déjà reproduits dans les tests Oxide SE.
- [x] Tester sur Pico 1 le Security Domain géré par le noyau en SCP03 S8 et
  S16 : ATR, C-MAC, C-ENC, `STORE DATA`, `GET DATA`, `GET STATUS`, mauvais
  cryptogramme et profil incompatible.
- [x] Tester sur Pico 1 le Security Domain délégué à une Rustlet avec le nouvel
  `apdu-tool`, en SCP03 S16 niveau `33` avec R-MAC et R-ENC.
- [x] Tester les rejets de replay, chaînes MAC périmées, mauvais cryptogrammes,
  mauvais keysets et profils incompatibles.

## 13. Implémenter SCP11

- [x] Définir le format de credentials pour clé privée hôte, certificat,
  chaîne de confiance, identifiants et paramètres de profil.
- [x] Réutiliser les primitives cryptographiques et encodeurs SCP11 déjà
  validés dans les campagnes Oxide SE.
- [x] Implémenter SCP11a et ses modes d'authentification pris en charge.
- [x] Implémenter SCP11b.
- [x] Implémenter SCP11c.
- [x] Vérifier certificats, signatures, clés éphémères et données SharedInfo.
- [x] Dériver les clés de session et vérifier les reçus.
- [x] Implémenter C-MAC, C-ENC, R-MAC et R-ENC selon chaque profil autorisé.
- [x] Refuser localement les opérations de gestion interdites par le profil,
  sans prétendre qu'elles ont été transmises.
- [x] Tester authentification unilatérale ou mutuelle, replay, reçu périmé,
  chaîne de confiance invalide et credential absent.

## 14. Implémenter les primitives de chargement GP

- [x] Implémenter `gp install-for-load` avec package AID, Security Domain,
  hash, paramètres de chargement et token lorsque pris en charge.
- [x] Implémenter `gp load-block --number <n> [--last] <fichier>` pour le
  diagnostic bas niveau.
- [x] Implémenter `gp install-for-install` et `gp install-make-selectable`
  pour `INSTALL [for install]` et `INSTALL [for install and make selectable]`.
- [x] Accepter package AID, module AID, instance AID, privilèges et paramètres
  sous forme symbolique ou depuis des fichiers.
- [x] Décoder et afficher précisément tout échec d'une primitive.
- [x] Tester chaque primitive en clair sur Pico 1 avec `NullSecurityDomain`.
- [ ] Tester chaque primitive sous SCP03 et sous les profils SCP11 qui
  autorisent l'opération.

## 15. Charger ou déployer un FAE en une commande

- [x] Implémenter `gp load <AID> <fichier.fae>` comme opération
  composée `INSTALL [for load]` puis `LOAD`.
- [x] Lire et valider localement l'en-tête, la taille, l'ISA et l'ABI du FAE
  avant de commencer la transaction.
- [x] Déterminer la taille maximale de bloc à partir de T=0, du profil Secure
  Channel, de la longueur de MAC et du chiffrement actifs.
- [x] Découper le fichier, numéroter les blocs et positionner correctement le
  marqueur du dernier bloc.
- [x] Afficher une progression en octets et en blocs sur `stderr` avec
  `--progress`.
- [x] Arrêter au premier status word d'échec et indiquer le numéro de bloc.
- [ ] Tester les tailles limites, plus de 256 blocs, fichier vide, dernier bloc
  plein, interruption réseau et FAE incompatible.
- [x] Tester `gp load` en clair sur Pico 1 et vérifier le package chargé dans
  le registry du `NullSecurityDomain`.
- [x] Implémenter `gp deploy <AID> <fichier.fae> <AID> [--params <payload>]`.
- [x] Enchaîner découverte/sélection du Security Domain, établissement du
  Secure Channel, chargement, installation et mise en état sélectionnable.
- [x] Arrêter le déploiement au premier bloc LOAD incomplet ou refusé, avant
  toute tentative d'installation.
- [x] Tester `gp deploy` en clair sur Pico 1 puis sélectionner l'instance créée.
- [ ] Tester `gp load` et `gp deploy` sous SCP03 S8/S16 et sous chaque profil
  SCP11 qui autorise ces opérations.

## 16. Persister le suivi de session

- [x] Créer `session.json` lors de `atr` afin de conserver le suivi nécessaire
  entre plusieurs invocations normales du terminal.
- [x] Utiliser le chemin indiqué par `APDU_SESSION_FILE` lorsqu'elle est
  définie, sinon le chemin de session par défaut.
- [x] Ajouter `close`, qui supprime le fichier de session et ne dépend pas d'un
  mode interactif `shell` ou `batch`.
- [x] Avertir clairement que le fichier de session est un élément critique de
  sécurité et appliquer des permissions locales restrictives.
- [x] Permettre de sélectionner une application puis de lui envoyer plusieurs
  APDU sans réétablir le Secure Channel entre les invocations.
- [x] Définir `scp03 open`, `scp03 inspect` et `scp03 close`; persister SCP11
  reste à implémenter.
- [x] Invalider immédiatement l'état local après erreur de sécurité ou perte du
  lien.
- [x] Garantir qu'aucun secret ni clé de session n'est enregistré dans
  l'historique interactif.
- [x] Valider sous QEMU la reprise SCP03 entre processus pour une commande GP,
  un `select` protégé et un `raw` protégé; l'APDU applicative de référence
  renvoie `10 11 12 90 00`.
- [x] Rejouer sur Pico 1 le scénario complet SCP03 S16 persistant : `gp
  deploy` en 37 blocs protégés, `select`, réponse fixe `10 11 12` et écho `DE
  AD BE EF` via `raw`, puis inspection et fermeture de session.

## 17. Compléter les opérations GlobalPlatform

- [x] Exposer la découverte des Card Recognition Data et Card Capability
  Information avec décodage symbolique (`card-recognition` et
  `card-capabilities`).
- [x] Ne pas ajouter de commandes séparées `BEGIN/END R-MAC SESSION` : les
  profils Oxide SE amorcent R-MAC avec le C-MAC d'`EXTERNAL AUTHENTICATE` et
  déclarent ces commandes hors profil.
- [x] Évaluer `INSTALL [for make selectable]` et ne pas l'exposer : Oxide SE
  n'implémente que les variantes P1 `02` et `0C`.
- [x] Évaluer `INSTALL [for personalization]` et ne pas l'exposer tant que le
  modèle de personnalisation Oxide SE ne lui donne pas de sémantique.
- [x] Évaluer `INSTALL [for extradition]` et ne pas l'exposer tant que
  Oxide SE ne prend pas en charge le transfert entre Security Domains.
- [x] Refuser localement les noms de commandes GP non pris en charge; `raw`
  reste volontairement disponible pour le diagnostic bas niveau.

## 18. Documentation et validation finale

- [ ] Transformer les exemples cibles du README en tests de documentation ou
  tests CLI lorsque chaque commande devient disponible.
- [ ] Ajouter un guide « première APDU » avec QEMU et `atr`.
- [ ] Ajouter un guide de chargement et de déploiement d'un FAE en clair.
- [ ] Ajouter un guide SCP03 sans inclure de clés réelles dans le dépôt.
- [ ] Ajouter des guides SCP11a, SCP11b et SCP11c.
- [ ] Documenter le format des fichiers de credentials et leurs permissions
  recommandées.
- [ ] Documenter tous les codes de sortie et le schéma JSON.
- [ ] Ajouter une matrice des commandes disponibles selon le Security Domain et
  le profil Secure Channel.
- [ ] Exécuter les tests unitaires du paquet, les campagnes QEMU GP/SCP et les
  tests sur une liaison série physique.
- [ ] Vérifier que les sorties de test et d'erreur ne contiennent aucun secret.
- [x] Retirer la syntaxe historique après documentation de son remplacement par
  `atr`, `raw` et `--serial`.

## 19. Construire en dernier les primitives ISO 7816 de système de fichiers

- [ ] Ajouter un encodeur/décodeur commun des APDU courtes ISO 7816.
- [x] Implémenter `select <AID>` pour `SELECT by DF/application name`, requis
  par le scénario de session persistante; conserver les autres primitives de
  système de fichiers pour cette dernière étape.
- [ ] Ajouter les options d'occurrence et de réponse `FCI`, `FCP`, `FMD` ou
  aucune donnée.
- [ ] Valider et normaliser les AID écrits avec espaces, deux-points ou hex
  continu.
- [ ] Exposer `get-response` pour le diagnostic, sans dupliquer l'enchaînement
  automatique déjà réalisé par le client T=0.
- [ ] Ajouter `get-challenge`, `manage-channel`, `read-binary`,
  `update-binary`, `read-record` et `verify` uniquement si leur sémantique est
  réellement prise en charge et testée dans Oxide SE.

## Définition de terminé

- [ ] `apdu-tool atr` attend et affiche l'ATR sans envoyer d'APDU.
- [ ] `apdu-tool raw ...` envoie immédiatement sans attendre d'ATR.
- [ ] Les erreurs différencient connexion impossible, SE silencieux,
  désynchronisation, erreur T=0, erreur Secure Channel et échec GP.
- [ ] `select`, `gp get-data`, `store-data`, `get-status`, `set-status`,
  `delete` et `put-key` fonctionnent avec sorties humaine et JSON.
- [ ] SCP03 S8/S16 et SCP11a/b/c sont pris en charge conformément aux profils
  réellement implémentés par Oxide SE.
- [ ] `gp load --package-aid <AID> <FAE>` exécute correctement
  `INSTALL [for load]` puis tous les blocs `LOAD`.
- [ ] `gp deploy <FAE>` charge et installe une instance en une invocation.
- [ ] Les opérations composées conservent une seule connexion et une seule
  session Secure Channel.
- [ ] Les tests passent sur TCP, socket Unix, transport simulé et matériel
  série représentatif.
- [ ] Aucun secret n'est exposé dans la ligne de commande recommandée, les
  logs, les sorties verbeuses ou les rapports de test.
