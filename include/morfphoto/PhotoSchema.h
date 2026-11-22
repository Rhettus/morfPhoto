/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once
#include <QString>
#include <QStringList>

// -----------------------------------------------------------------------------
// Schéma SQLite v1 du domaine photo (source de vérité du schéma).
//
// Le numéro de schéma courant est porté par `PRAGMA user_version` : le dépôt
// applique les migrations dont le numéro dépasse la version courante, puis scelle
// la nouvelle version. Le driver SQLite exécute UNE instruction par requête ;
// chaque migration est donc une liste d'instructions séparées.
//
// Souveraineté : les valeurs EXIF sont stockées BRUTES, jamais corrigées ni
// regroupées. 49, 50 et 51 mm restent 49, 50 et 51. Un RAW et son JPEG sont deux
// lignes distinctes : morfPhoto ne décide jamais qu'ils sont un même déclenchement
// (c'est le rôle de la couche d'analyse, ailleurs).
// -----------------------------------------------------------------------------
namespace morfphoto {

inline constexpr int kSchemaVersion = 10;

// Instructions de la migration 001 (création initiale). La colonne calculée
// `taken_year` permet de regrouper par année sans reparser la date à chaque fois.
inline QStringList schemaV1Statements() {
    return {
        // folders : les sélections que l'utilisateur demande à surveiller.
        // Modèle hybride : /etc définit les RACINES AUTORISÉES, cette table ce que
        // l'utilisateur demande effectivement, toujours sous une racine autorisée.
        QStringLiteral(
            "CREATE TABLE folders ("
            "  id            INTEGER PRIMARY KEY,"
            "  path          TEXT    NOT NULL UNIQUE,"
            "  root_path     TEXT    NOT NULL,"
            "  label         TEXT,"
            "  enabled       INTEGER NOT NULL DEFAULT 1,"
            "  auto_disabled INTEGER NOT NULL DEFAULT 0,"
            "  recursive     INTEGER NOT NULL DEFAULT 1,"
            "  added_at      TEXT    NOT NULL,"
            "  last_scan_at  TEXT"
            ")"),

        // files : le cœur. Une ligne par fichier présent sur le disque. Le triplet
        // (path, size, mtime) suffit à décider d'un retraitement (pas de hash).
        QStringLiteral(
            "CREATE TABLE files ("
            "  id                    INTEGER PRIMARY KEY,"
            "  folder_id             INTEGER NOT NULL REFERENCES folders(id),"
            "  path                  TEXT    NOT NULL UNIQUE,"
            "  directory             TEXT    NOT NULL,"
            "  filename              TEXT    NOT NULL,"
            "  extension             TEXT,"
            "  file_type             TEXT,"
            "  size                  INTEGER NOT NULL,"
            "  mtime                 INTEGER NOT NULL,"
            "  taken_at              TEXT,"
            "  taken_year            INTEGER GENERATED ALWAYS AS"
            "                        (CAST(strftime('%Y', taken_at) AS INTEGER)) STORED,"
            "  make                  TEXT,"
            "  camera_model          TEXT,"
            "  lens                  TEXT,"
            "  focal_length          REAL,"
            "  focal_length_35mm     REAL,"
            "  aperture              REAL,"
            "  shutter_speed         TEXT,"
            "  shutter_speed_s       REAL,"
            "  iso                   INTEGER,"
            "  exposure_compensation REAL,"
            "  rating                INTEGER,"
            "  latitude              REAL,"
            "  longitude             REAL,"
            "  raw_exif              TEXT,"
            "  state                 TEXT    NOT NULL DEFAULT 'present',"
            "  exif_ok               INTEGER NOT NULL DEFAULT 0,"
            "  first_seen_at         TEXT    NOT NULL,"
            "  last_seen_at          TEXT    NOT NULL,"
            "  last_indexed_at       TEXT    NOT NULL,"
            "  disappeared_at        TEXT"
            ")"),

        QStringLiteral("CREATE INDEX idx_files_folder ON files(folder_id)"),
        QStringLiteral("CREATE INDEX idx_files_state  ON files(state)"),
        QStringLiteral("CREATE INDEX idx_files_year   ON files(taken_year)"),
        QStringLiteral("CREATE INDEX idx_files_camera ON files(camera_model)"),
        QStringLiteral("CREATE INDEX idx_files_lens   ON files(lens)"),
        QStringLiteral("CREATE INDEX idx_files_type   ON files(file_type)"),

        // index_runs : historique des passes (progression, compteurs, déclencheur).
        QStringLiteral(
            "CREATE TABLE index_runs ("
            "  id            INTEGER PRIMARY KEY,"
            "  started_at    TEXT    NOT NULL,"
            "  finished_at   TEXT,"
            "  mode          TEXT    NOT NULL,"
            "  trigger       TEXT    NOT NULL DEFAULT 'watch',"
            "  state         TEXT    NOT NULL,"
            "  files_seen    INTEGER NOT NULL DEFAULT 0,"
            "  files_new     INTEGER NOT NULL DEFAULT 0,"
            "  files_updated INTEGER NOT NULL DEFAULT 0,"
            "  files_missing INTEGER NOT NULL DEFAULT 0,"
            "  errors_count  INTEGER NOT NULL DEFAULT 0"
            ")"),

        // index_errors : erreurs par fichier, jamais avalées en silence.
        QStringLiteral(
            "CREATE TABLE index_errors ("
            "  id          INTEGER PRIMARY KEY,"
            "  run_id      INTEGER NOT NULL REFERENCES index_runs(id),"
            "  path        TEXT,"
            "  stage       TEXT    NOT NULL,"
            "  message     TEXT    NOT NULL,"
            "  occurred_at TEXT    NOT NULL"
            ")"),
    };
}

// Migration 002 : distinguer un dossier RETIRÉ (suppression douce) d'un dossier
// simplement désactivé. Jusque-là les deux valaient `enabled = 0`, donc PhotoHub
// ne pouvait pas les séparer. `deleted_at` est NULL tant que le dossier est
// surveillé (actif ou en pause) et horodaté au moment du retrait doux. La donnée
// n'est jamais supprimée : un dossier retiré peut être restauré.
inline QStringList schemaV2Statements() {
    return {
        QStringLiteral("ALTER TABLE folders ADD COLUMN deleted_at TEXT"),
    };
}

// Migration 003 : rendre visible une passe INTERROMPUE par une source indisponible.
// Une racine réseau (SMB/CIFS, NFS...) valide au départ peut disparaître pendant
// une passe. On ne marque alors AUCUN fichier disparu (un scan partiel n'est pas
// une référence fiable) : on compte les sélections sautées ici, et `index_runs.state`
// vaut alors 'interrupted' au lieu de 'done'. Colonne additive, valeur 0 par défaut
// pour tout l'historique existant.
inline QStringList schemaV3Statements() {
    return {
        QStringLiteral("ALTER TABLE index_runs ADD COLUMN files_unavailable INTEGER NOT NULL DEFAULT 0"),
    };
}

// Migration 004 : gestion des SUPPORTS AMOVIBLES (CD/DVD, disques d'archive) et de
// la portée d'analyse. Trois colonnes additives sur `folders` :
//   - `removable` : la sélection vit sur un support qu'on retire (CD gravé rangé sur
//     une étagère). Son absence est NORMALE : une passe ne marque alors jamais ses
//     fichiers disparus (l'archive reste dans la base, donc dans morfAnalytics, même
//     support éjecté et même après un reboot). Voir Indexer::reconcileFolder.
//   - `volume_label` : nom du support saisi par l'utilisateur (« PHOTOS-2015 »), pour
//     reconnaître le disque d'une insertion à l'autre et l'étiqueter dans l'interface.
//   - `analytics_excluded` : sortir une sélection des ANALYSES sans effacer ses
//     données. Les fichiers restent indexés (consultables, restaurables), mais les
//     agrégats analytiques (dataset, années, boîtiers, objectifs, focales) les
//     ignorent. Réversible, non destructif - à distinguer de la purge.
// Colonnes additives, valeurs par défaut neutres pour tout l'historique existant.
inline QStringList schemaV4Statements() {
    return {
        QStringLiteral("ALTER TABLE folders ADD COLUMN removable INTEGER NOT NULL DEFAULT 0"),
        QStringLiteral("ALTER TABLE folders ADD COLUMN volume_label TEXT"),
        QStringLiteral("ALTER TABLE folders ADD COLUMN analytics_excluded INTEGER NOT NULL DEFAULT 0"),
    };
}

// Migration 005 : CONTEXTE PHOTOGRAPHIQUE par dossier (contrat morfphoto-context/2).
// Chaque répertoire de photos peut porter un fichier `.morfphoto.json` (donnée
// sémantique sur disque, source de vérité). Cette table en est la PROJECTION
// reconstructible, clé = le répertoire réel (files.directory). Aucune colonne n'est
// ajoutée à `files` : le contexte se joint par `files.directory = folder_contexts.directory`,
// ce qui évite de réécrire des milliers de lignes `files` à chaque édition de contexte.
// Deux dimensions INDÉPENDANTES : `context` (conditions/intention de la séance) et
// `subject` (sujet dominant). Valeurs stockées BRUTES (une valeur hors vocabulaire est
// conservée et signalée, jamais convertie). `status` distingue une lecture réussie
// (ok) d'un JSON invalide (invalid, à réparer) ; l'ABSENCE de fichier = absence de
// ligne (état « non qualifié », jamais stocké). `source_mtime` rend la découverte
// idempotente (ne relire que si le fichier a changé). Colonnes/tables additives.
inline QStringList schemaV5Statements() {
    return {
        QStringLiteral(
            "CREATE TABLE folder_contexts ("
            "  directory     TEXT    PRIMARY KEY,"   // = files.directory
            "  schema        INTEGER,"
            "  context       TEXT,"                  // valeur brute (peut etre hors vocabulaire)
            "  subject       TEXT,"                  // valeur brute (idem)
            "  motif         TEXT,"
            "  description   TEXT,"
            "  created       TEXT,"
            "  updated       TEXT,"
            "  source_mtime  INTEGER,"               // mtime du .morfphoto.json lu (idempotence)
            "  status        TEXT    NOT NULL,"      // ok | invalid
            "  warnings      TEXT,"                  // future_schema, context_unknown, subject_unknown (CSV)
            "  error         TEXT,"                  // detail de diagnostic si status = invalid
            "  indexed_at    TEXT    NOT NULL"
            ")"),
        QStringLiteral("CREATE INDEX idx_ctx_context ON folder_contexts(context)"),
        QStringLiteral("CREATE INDEX idx_ctx_subject ON folder_contexts(subject)"),
    };
}

// Migration 006 : index composite (directory, state) sur `files`. summary() joint chaque
// ligne de `folder_contexts` aux photos présentes de son répertoire (EXISTS corrélé) et
// compte les répertoires distincts : sans cet index, chaque jointure balayait toute la
// table. Sur une photothèque de plusieurs dizaines de milliers de fichiers, pendant une
// indexation, /api/v1/photos/summary durait des minutes et bloquait le thread HTTP unique
// (donc /status). Index seul : aucune donnée touchée, reconstructible.
inline QStringList schemaV6Statements() {
    return {
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_files_dir_state ON files(directory, state)"),
    };
}

// Migration 007 : BIBLIOTHÈQUE (EXIF + XMP réunis). Tables à part : `files` ne change pas,
// donc les réponses existantes de l'API non plus. Reconstructible depuis les sidecars.
inline QStringList schemaV7Statements() {
    return {
        QStringLiteral(
            "CREATE TABLE library_files ("
            "  file_id        INTEGER PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,"
            "  fingerprint    TEXT NOT NULL,"
            "  kind_label     TEXT NOT NULL,"
            "  ext_label      TEXT NOT NULL,"
            "  camera_label   TEXT NOT NULL,"
            "  body_key       TEXT NOT NULL,"
            "  body_serial    TEXT NOT NULL,"
            "  iso_label      TEXT NOT NULL,"
            "  aperture_label TEXT NOT NULL,"
            "  focal_label    TEXT NOT NULL,"
            "  shutter_label  TEXT NOT NULL"
            ")"),
        QStringLiteral(
            "CREATE TABLE library_versions ("
            "  id           INTEGER PRIMARY KEY,"
            "  file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,"
            "  version      INTEGER NOT NULL,"
            "  is_copy      INTEGER NOT NULL,"
            "  sidecar      TEXT,"
            "  rating       INTEGER NOT NULL,"
            "  rejected     INTEGER NOT NULL,"
            "  labels       INTEGER NOT NULL,"
            "  edited       INTEGER,"              // NULL = inconnu
            "  taken_at     TEXT,"
            "  latitude     REAL,"
            "  longitude    REAL,"
            "  title        TEXT,"
            "  description  TEXT,"
            "  creator      TEXT,"
            "  rights       TEXT,"
            "  version_name TEXT,"
            "  raw_xmp      TEXT,"
            "  UNIQUE (file_id, version)"
            ")"),
        QStringLiteral(
            "CREATE TABLE library_keywords ("
            "  version_id INTEGER NOT NULL REFERENCES library_versions(id) ON DELETE CASCADE,"
            "  keyword    TEXT    NOT NULL,"
            "  PRIMARY KEY (version_id, keyword)"
            ") WITHOUT ROWID"),
        QStringLiteral("CREATE INDEX idx_library_keyword ON library_keywords(keyword)"),
        QStringLiteral("CREATE INDEX idx_library_rating  ON library_versions(rating, rejected)"),
        QStringLiteral("CREATE INDEX idx_library_taken   ON library_versions(taken_at)"),
        QStringLiteral("CREATE INDEX idx_library_camera  ON library_files(camera_label)"),
    };
}

// Migration 008 : index composites et de filtrage pour accélérer les lectures et
// les recherches de portée lors de l'indexation et des requêtes bibliothèque.
inline QStringList schemaV8Statements() {
    return {
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_files_folder_dir ON files(folder_id, directory)"),
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_files_state_taken ON files(state, taken_at, id)"),
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_library_ver_lookup ON library_versions(version, edited, file_id)"),
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_library_rejected_rating ON library_versions(rejected, rating)"),
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_library_ext ON library_files(ext_label)"),
        QStringLiteral("CREATE INDEX IF NOT EXISTS idx_library_kind ON library_files(kind_label)"),
    };
}

// Migration 009 : index plein texte FTS5 trigram sur `files(filename)` pour
// accélérer les recherches par sous-chaîne de nom de fichier, synchronisé par triggers.
inline QStringList schemaV9Statements() {
    return {
        QStringLiteral(
            "CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5("
            "  filename,"
            "  content='files',"
            "  content_rowid='id',"
            "  tokenize='trigram'"
            ")"),
        QStringLiteral(
            "CREATE TRIGGER IF NOT EXISTS files_fts_ai AFTER INSERT ON files BEGIN "
            "  INSERT INTO files_fts(rowid, filename) VALUES (new.id, new.filename); "
            "END"),
        QStringLiteral(
            "CREATE TRIGGER IF NOT EXISTS files_fts_ad AFTER DELETE ON files BEGIN "
            "  INSERT INTO files_fts(files_fts, rowid, filename) VALUES ('delete', old.id, old.filename); "
            "END"),
        QStringLiteral(
            "CREATE TRIGGER IF NOT EXISTS files_fts_au AFTER UPDATE OF filename ON files BEGIN "
            "  INSERT INTO files_fts(files_fts, rowid, filename) VALUES ('delete', old.id, old.filename); "
            "  INSERT INTO files_fts(rowid, filename) VALUES (new.id, new.filename); "
            "END"),
        QStringLiteral("INSERT INTO files_fts(files_fts) VALUES('rebuild')"),
    };
}

// Migration 010 : index couvrants sur `files` et `library_versions` pour eviter
// de lire les gros blobs `raw_exif` / `raw_xmp` lors des parcours catalogue et CLIP.
inline QStringList schemaV10Statements() {
    return {
        QStringLiteral(
            "CREATE INDEX IF NOT EXISTS idx_files_state_dir_meta "
            "ON files(state, directory, path, size, mtime)"),
        QStringLiteral(
            "CREATE INDEX IF NOT EXISTS idx_library_ver_cover "
            "ON library_versions(file_id, version, taken_at, edited, rejected, rating, labels)"),
    };
}

// Instructions à exécuter pour atteindre une version de schéma donnée. Le dépôt
// applique dans l'ordre chaque version manquante (voir applyMigrations).
inline QStringList migrationStatements(int version) {
    switch (version) {
    case 1:  return schemaV1Statements();
    case 2:  return schemaV2Statements();
    case 3:  return schemaV3Statements();
    case 4:  return schemaV4Statements();
    case 5:  return schemaV5Statements();
    case 6:  return schemaV6Statements();
    case 7:  return schemaV7Statements();
    case 8:  return schemaV8Statements();
    case 9:  return schemaV9Statements();
    case 10: return schemaV10Statements();
    default: return {};
    }
}

} // namespace morfphoto
