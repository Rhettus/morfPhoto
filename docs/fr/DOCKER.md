# Déployer morfPhoto avec Docker

*Lire dans une autre langue : [English](../en/DOCKER.md) · **Français** (ce document).*

L'image contient tout ce dont morfPhoto a besoin (Qt, le pilote SQLite et ExifTool). Elle fonctionne sur
`linux/amd64` et `linux/arm64`, y compris sur la plupart des NAS.

## Prérequis

- Docker avec le plugin Compose (`docker compose version` doit afficher une version).
- Un dossier de photos sur la machine hôte.

## 1. Récupérer les fichiers

Créez un dossier pour le déploiement, puis copiez-y [`docker-compose.yml`](../../docker-compose.yml) et
[`.env.example`](../../.env.example) depuis ce dépôt.

```sh
mkdir morfphoto && cd morfphoto
# copier ici docker-compose.yml et .env.example
cp .env.example .env
```

## 2. Configurer

Modifiez `.env` :

| Réglage | Obligatoire | Description |
|---------|-------------|-------------|
| `PHOTOS_DIR` | Oui | Chemin absolu du dossier de photos sur l'hôte. Il doit déjà exister. |
| `PUID`, `PGID` | Non | Compte d'exécution du service. Il doit pouvoir lire `PHOTOS_DIR`. Défaut `1000`. |
| `MORFPHOTO_PORT` | Non | Port publié sur l'hôte. Défaut `8793`. |
| `MORFPHOTO_API_KEY` | Non | Clé protégeant l'API, pour les images qui la prennent en charge. Vide = aucune clé. |
| `MORFPHOTO_EXIF_WORKERS` | Non | Nombre de lectures ExifTool simultanées (1–4). Valeur par défaut `2`. |
| `MORFPHOTO_IMAGE` | Non | Image à exécuter, par exemple pour figer une version. |

Pour un déploiement existant, ajouter la variable d’environnement
`MORFPHOTO_EXIF_WORKERS` dans `docker-compose.yml` avant de la définir dans
`.env`. Recréer le conteneur après chaque modification de la valeur.

Pour trouver les bonnes valeurs de `PUID` et `PGID`, lancez `id` avec un compte qui peut lire les photos :

```sh
id
# uid=1000(photos) gid=1000(photos) ...
```

Pour générer une clé d'API :

```sh
openssl rand -hex 32
```

Gardez `.env` privé s'il contient une clé.

## 3. Démarrer

```sh
docker compose pull
docker compose up -d
```

Au premier démarrage, morfPhoto déclare `/photos` et lance l'indexation. Une grande photothèque peut prendre
du temps, car les métadonnées de chaque photo sont lues. Aux démarrages suivants,
le conteneur sert l’index existant dès l’ouverture. La surveillance suit les changements
en fonctionnement et une passe quotidienne rattrape ceux effectués pendant l’arrêt.
Pour un rattrapage immédiat, demander une passe incrémentale avec `POST /api/v1/index`.

## 4. Vérifier le fonctionnement

```sh
docker compose ps                                       # STATUS doit passer à « healthy »
curl http://127.0.0.1:8793/healthz                      # {"status":"ok"}
curl http://127.0.0.1:8793/api/v1/index/status          # progression de l'indexation
curl http://127.0.0.1:8793/api/v1/photos/summary        # compteurs de photos
```

Si vous avez défini une clé d'API, ajoutez-la aux requêtes :

```sh
curl -H "Authorization: Bearer VOTRE_CLE" http://127.0.0.1:8793/api/v1/photos/summary
```

## Mettre à jour

```sh
docker compose pull
docker compose up -d
```

La base est conservée.

## Sauvegarder la base

```sh
docker compose stop
docker run --rm -v morfphoto-data:/data:ro -v "$PWD":/backup debian:trixie-slim \
    tar czf /backup/morfphoto-data.tar.gz -C /data .
docker compose start
```

## Désinstaller

```sh
docker compose down      # retire le conteneur et conserve la base
docker compose down -v   # supprime aussi la base
```

Vos photos ne sont jamais modifiées ni supprimées.

## Limites

- Le dossier de photos est monté en lecture seule : `PUT` et `DELETE /api/v1/context` renvoient une erreur. Les
  fichiers `.morfphoto.json` existants restent lus.
- Les sources SMB (`POST /api/v1/sources`) ne sont pas disponibles dans le conteneur. Montez le partage sur
  l'hôte et faites pointer `PHOTOS_DIR` dessus.
- L'annonce sur le réseau local via morfBeacon est désactivée.

## Dépannage

| Symptôme | Que faire |
|----------|-----------|
| `Set PHOTOS_DIR in .env` | `.env` est absent, ou n'est pas dans le même dossier que `docker-compose.yml`. |
| Le montage échoue au démarrage | `PHOTOS_DIR` n'existe pas sur l'hôte. |
| Aucune photo trouvée | Vérifiez que `PUID` et `PGID` peuvent lire `PHOTOS_DIR`, puis lisez `docker compose logs morfphoto`. |
| Le port est déjà utilisé | Changez `MORFPHOTO_PORT` dans `.env`, puis lancez `docker compose up -d`. |
| `docker compose pull` est refusé | L'image est privée ou son nom est erroné. Vérifiez `MORFPHOTO_IMAGE`. |
