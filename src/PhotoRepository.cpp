/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/PhotoRepository.h"
#include "morfphoto/PhotoSchema.h"

#include <QSqlQuery>
#include <QSqlError>
#include <QSqlRecord>
#include <QJsonDocument>
#include <QJsonValue>
#include <QCryptographicHash>
#include <QVariant>
#include <QDate>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>
#include <QDebug>
#include <QMap>
#include <QSet>

#include <algorithm>
#include <cmath>
#include <utility>

namespace morfphoto {

namespace {

// Exécute une requête préparée avec ses valeurs liées positionnelles. Journalise
// et renvoie false en cas d'échec : une erreur SQL ne s'avale jamais en silence.
bool run(QSqlQuery& q, const QString& sql, const QVariantList& binds = {}) {
    if (!q.prepare(sql)) {
        const auto error = q.lastError();
        qWarning() << "morfPhoto SQL prepare:" << error.nativeErrorCode() << error.text() << sql;
        return false;
    }
    for (const QVariant& b : binds)
        q.addBindValue(b);
    if (!q.exec()) {
        const auto error = q.lastError();
        qWarning() << "morfPhoto SQL exec:" << error.nativeErrorCode() << error.text() << sql;
        return false;
    }
    return true;
}

// Extrait une fois les noms de colonnes d'une requête active pour éviter
// de reconstruire QSqlRecord à chaque ligne dans les boucles chaudes.
QStringList queryFieldNames(const QSqlQuery& q) {
    const QSqlRecord rec = q.record();
    QStringList names;
    names.reserve(rec.count());
    for (int i = 0; i < rec.count(); ++i)
        names.append(rec.fieldName(i));
    return names;
}

// Convertit la ligne courante d'une requête en objet JSON. Les NULL deviennent
// des null JSON ; raw_exif (stocké en texte JSON) est rendu comme objet.
QJsonObject rowToJson(const QSqlQuery& q, const QStringList& fieldNames) {
    QJsonObject o;
    for (int i = 0; i < fieldNames.size(); ++i) {
        const QString& name = fieldNames.at(i);
        const QVariant v = q.value(i);
        if (v.isNull()) {
            // Une colonne NULL doit ressortir en null JSON, pas en "" ni 0.
            o.insert(name, QJsonValue::Null);
            continue;
        }
        if (name == QLatin1String("raw_exif")) {
            const QJsonDocument d = QJsonDocument::fromJson(v.toString().toUtf8());
            o.insert(name, d.isObject() ? QJsonValue(d.object()) : QJsonValue::Null);
            continue;
        }
        o.insert(name, QJsonValue::fromVariant(v));
    }
    return o;
}

QJsonObject rowToJson(const QSqlQuery& q) {
    return rowToJson(q, queryFieldNames(q));
}

// Sérialise les tags bruts pour la colonne raw_exif (NULL si vide).
QVariant rawExifVariant(const ExifData& exif) {
    if (exif.raw.isEmpty())
        return {};
    return QString::fromUtf8(QJsonDocument(exif.raw).toJson(QJsonDocument::Compact));
}

// Fragment SQL : photos ÉLIGIBLES AUX ANALYSES = présentes ET hors d'un dossier
// sorti des analyses (analytics_excluded). Une archive amovible reste « présente »
// support éjecté (jamais marquée disparue), donc analysée par défaut ; l'utilisateur
// peut la sortir explicitement des analyses sans effacer ses données. Chaîne fixe
// interne, jamais construite depuis une entrée client : aucune injection possible.
QString analyzablePredicate() {
    return QStringLiteral(
        "state = 'present' AND folder_id NOT IN "
        "(SELECT id FROM folders WHERE analytics_excluded = 1)");
}

// Empreinte STABLE inter-machines d'une photo, pour le dédoublonnage de la couche
// d'analyse quand plusieurs postes indexent le MÊME fichier (un CD gravé indexé sur
// deux machines, un dossier partagé). Deux copies partagent nom+taille+date de prise,
// donc la même empreinte -- le CHEMIN est exclu à dessein (il varie d'un poste à
// l'autre, montage ou lettre de lecteur différents). FNV-1a 64 bits, rendu en hexa :
// opaque (l'anonymat du dataset est préservé, aucun nom de fichier n'est exposé),
// compact, déterministe (aucune graine aléatoire, contrairement à qHash).
QString fingerprintOf(const QString& filename, qint64 size, const QString& takenAt) {
    const QByteArray key = (filename.toLower() + QLatin1Char('\x1f')
                            + QString::number(size) + QLatin1Char('\x1f') + takenAt).toUtf8();
    quint64 h = 1469598103934665603ULL;               // offset de base FNV-1a 64 bits
    for (const char c : key) {
        h ^= static_cast<unsigned char>(c);
        h *= 1099511628211ULL;                         // nombre premier FNV 64 bits
    }
    return QString::number(h, 16);
}

// Traduction filtre public -> colonne SQL. Liste blanche : aucune autre clé
// n'atteint le SQL, pas d'injection possible par un nom de champ.
QString filterColumn(const QString& key) {
    if (key == QLatin1String("year"))   return QStringLiteral("taken_year");
    if (key == QLatin1String("camera")) return QStringLiteral("camera_model");
    if (key == QLatin1String("lens"))   return QStringLiteral("lens");
    if (key == QLatin1String("type"))   return QStringLiteral("file_type");
    if (key == QLatin1String("folder")) return QStringLiteral("folder_id");
    if (key == QLatin1String("directory")) return QStringLiteral("directory");
    if (key == QLatin1String("state"))  return QStringLiteral("state");
    return {};
}

// Construit le prédicat WHERE d'une portée sur `files` (avec préfixe de table
// optionnel, ex. "f.") et remplit `binds`.
QString scopePredicate(int folderId, const QString& path, bool recursive,
                       const QString& prefix, QVariantList& binds) {
    const QString clean = QDir::cleanPath(path);
    binds.clear();
    binds << folderId;
    if (!recursive) {
        binds << clean;
        return QStringLiteral("%1folder_id = ? AND %1directory = ?").arg(prefix);
    }
    if (clean == QLatin1String("/"))
        return QStringLiteral("%1folder_id = ?").arg(prefix);
    binds << clean << clean + QLatin1Char('/') << clean + QLatin1Char('0');
    return QStringLiteral("%1folder_id = ? AND (%1directory = ? OR (%1directory >= ? AND %1directory < ?))")
        .arg(prefix);
}

// Expression SQL : le dernier numero de changement attribue (compteur persistant).
const char* const kSeqNow = "(SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'change_seq')";

const char* const kBumpSeq =
    "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'change_seq'";

// Prend le numero suivant du compteur persistant. Le numero vaut ce que la
// transaction ECRIVANT la ligne l'a pris : l'appelant est donc dans cette transaction
// (voir PhotoRepository::beginOwn), sinon l'ordre des numeros ne suivrait plus celui
// des commits et un lecteur du flux pourrait sauter un changement.
bool bumpChangeSeq(QSqlDatabase database) {
    QSqlQuery q(database);
    return run(q, QString::fromLatin1(kBumpSeq));
}

// Numerote les lignes de `files` qui satisfont `where`, et seulement elles : un
// parcours inchange ne doit rien numeroter (sinon le miroir se retelechargerait a
// chaque passe). A appeler AVANT l'ecriture qui change l'etat dont `where` depend.
bool stampFilesWhere(QSqlDatabase database, const QString& where, const QVariantList& binds) {
    QSqlQuery bump(database);
    if (!run(bump, QString::fromLatin1(kBumpSeq)
                       + QStringLiteral(" AND EXISTS (SELECT 1 FROM files WHERE %1)").arg(where), binds))
        return false;
    if (bump.numRowsAffected() < 1)
        return true;   // aucune ligne ne change : aucun numero consomme
    QSqlQuery stamp(database);
    return run(stamp, QStringLiteral("UPDATE files SET change_seq = %1 WHERE %2")
                          .arg(QString::fromLatin1(kSeqNow), where), binds);
}

// Exécute une mise à jour par lots de 500 identifiants pour rester sous
// SQLITE_MAX_VARIABLE_NUMBER. `stampWhere` (avec %1 pour la liste d'identifiants) numerote
// avant la mise a jour les lignes dont l'etat va reellement changer. L'appelant fournit la
// transaction.
bool runBatchedFileUpdate(QSqlDatabase database, const QString& sqlTemplate,
                          const QString& stampWhere, const QVector<int>& fileIds,
                          const QString& now) {
    if (fileIds.isEmpty())
        return true;
    constexpr qsizetype kBatchSize = 500;
    for (qsizetype offset = 0; offset < fileIds.size(); offset += kBatchSize) {
        const qsizetype count = qMin(kBatchSize, fileIds.size() - offset);
        QStringList holders;
        holders.reserve(count);
        QVariantList ids;
        ids.reserve(count);
        for (qsizetype i = 0; i < count; ++i) {
            holders << QStringLiteral("?");
            ids << fileIds.at(offset + i);
        }
        const QString list = holders.join(QLatin1Char(','));
        if (!stampWhere.isEmpty() && !stampFilesWhere(database, stampWhere.arg(list), ids))
            return false;
        QVariantList binds;
        binds << now;
        binds += ids;
        QSqlQuery q(database);
        if (!run(q, sqlTemplate.arg(list), binds))
            return false;
    }
    return true;
}

} // namespace

PhotoRepository::PhotoRepository(QString connectionName)
    : m_connectionName(std::move(connectionName)) {}

PhotoRepository::~PhotoRepository() {
    close();
}

QSqlDatabase PhotoRepository::db() const {
    return QSqlDatabase::database(m_connectionName);
}

bool PhotoRepository::open(const QString& dbPath, bool readOnly) {
    m_hasFilesFts = false;
    if (!readOnly) {
        // Créer le dossier de la base au besoin (première installation).
        const QFileInfo fi(dbPath);
        QDir().mkpath(fi.absolutePath());
    }

    if (!QSqlDatabase::isDriverAvailable(QStringLiteral("QSQLITE"))) {
        m_openError = QStringLiteral("driver QSQLITE indisponible");
        qWarning() << "morfPhoto:" << m_openError;
        return false;
    }
    QSqlDatabase database = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_connectionName);
    database.setDatabaseName(dbPath);
    if (readOnly)
        database.setConnectOptions(QStringLiteral("QSQLITE_OPEN_READONLY"));
    if (!database.open()) {
        m_openError = database.lastError().text();
        qWarning() << "morfPhoto: ouverture base impossible" << dbPath << m_openError;
        return false;
    }
    if (readOnly) {
        {
            QSqlQuery q(database);
            q.exec(QStringLiteral("PRAGMA query_only = ON"));
            q.exec(QStringLiteral("PRAGMA busy_timeout = 5000"));
            q.exec(QStringLiteral("PRAGMA cache_size = -65536"));
            q.exec(QStringLiteral("PRAGMA temp_store = MEMORY"));
            q.exec(QStringLiteral("PRAGMA mmap_size = 268435456"));
        }
        QSqlQuery fq(database);
        m_hasFilesFts = fq.exec(QStringLiteral(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files_fts'")) && fq.next();
        return true;
    }
    // Scoper les PRAGMA : une requête encore active bloquerait le commit des
    // migrations (« SQL statements in progress »). La détruire la finalise.
    {
        QSqlQuery q(database);
        q.exec(QStringLiteral("PRAGMA foreign_keys = ON"));
        // WAL : lectures concurrentes (API) pendant l'écriture (indexation).
        q.exec(QStringLiteral("PRAGMA journal_mode = WAL"));
        // Attendre plutôt qu'échouer si une autre connexion écrit au même moment
        // (l'API et une passe d'indexation ont chacune leur connexion).
        q.exec(QStringLiteral("PRAGMA busy_timeout = 5000"));
        q.exec(QStringLiteral("PRAGMA synchronous = NORMAL"));
        q.exec(QStringLiteral("PRAGMA cache_size = -65536"));
        q.exec(QStringLiteral("PRAGMA temp_store = MEMORY"));
        q.exec(QStringLiteral("PRAGMA journal_size_limit = 67108864"));
    }
    if (!applyMigrations())
        return false;
    {
        QSqlQuery fq(database);
        m_hasFilesFts = fq.exec(QStringLiteral(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'files_fts'")) && fq.next();
    }
    return true;
}

void PhotoRepository::close() {
    m_inTransaction = false;
    m_hasFilesFts = false;
    if (QSqlDatabase::contains(m_connectionName)) {
        {
            QSqlDatabase database = QSqlDatabase::database(m_connectionName);
            if (database.isOpen())
                database.close();
        }
        QSqlDatabase::removeDatabase(m_connectionName);
    }
}

bool PhotoRepository::isOpen() const {
    return QSqlDatabase::contains(m_connectionName) && db().isOpen();
}

qint64 PhotoRepository::dataVersion() {
    QSqlQuery q(db());
    if (!run(q, QStringLiteral("PRAGMA data_version")) || !q.next())
        return 0;
    return q.value(0).toLongLong();
}

QString PhotoRepository::catalogRevision() {
    QSqlQuery q(db());
    if (!run(q, QStringLiteral(
             "SELECT "
             "  (SELECT COUNT(*) FROM files),"
             "  (SELECT COALESCE(MAX(id), 0) FROM files),"
             "  (SELECT COUNT(*) FROM files WHERE state = 'present'),"
             "  (SELECT COUNT(*) FROM library_versions),"
             "  (SELECT COALESCE(MAX(id), 0) FROM library_versions),"
             "  (SELECT COUNT(*) FROM folders WHERE deleted_at IS NULL),"
             "  (SELECT COALESCE(SUM(enabled), 0) FROM folders WHERE deleted_at IS NULL),"
             "  (SELECT COALESCE(MAX(id), 0) FROM index_runs),"
             "  (SELECT COALESCE(MAX(finished_at), '') FROM index_runs),"
             "  (SELECT COUNT(*) FROM folder_contexts),"
             "  (SELECT COALESCE(MAX(indexed_at), '') FROM folder_contexts)"))
        || !q.next())
        return {};

    QByteArray sig = QByteArray::number(kSchemaVersion);
    sig.reserve(160);
    for (int i = 0; i < 11; ++i) {
        sig.append('|');
        sig.append(q.value(i).toString().toUtf8());
    }
    return QString::fromLatin1(
        QCryptographicHash::hash(sig, QCryptographicHash::Sha256).toHex().left(16));
}

bool PhotoRepository::beginImmediate() {
    // BEGIN IMMEDIATE : le verrou d'ecriture est pris d'emblee, donc le premier numero de
    // changement vient d'une transaction qui ecrit vraiment (pas d'echec « snapshot » apres
    // une lecture). COMMIT/ROLLBACK de Qt restent valables.
    QSqlQuery q(db());
    return q.exec(QStringLiteral("BEGIN IMMEDIATE"));
}

PhotoRepository::Own PhotoRepository::beginOwn() {
    if (m_inTransaction)
        return Own::Outer;
    return beginImmediate() ? Own::Began : Own::Failed;
}

void PhotoRepository::endOwn(Own own, bool ok) {
    if (own != Own::Began)
        return;
    if (ok && db().commit())
        return;
    db().rollback();
}

bool PhotoRepository::beginTransaction() {
    if (m_inTransaction)
        return false;
    const bool ok = beginImmediate();
    m_inTransaction = ok;
    return ok;
}

bool PhotoRepository::commitTransaction() {
    if (!m_inTransaction)
        return true;
    m_inTransaction = false;
    return db().commit();
}

void PhotoRepository::rollbackTransaction() {
    if (!m_inTransaction)
        return;
    m_inTransaction = false;
    db().rollback();
}

bool PhotoRepository::applyMigrations() {
    QSqlDatabase database = db();
    int current = 0;
    {
        // Scoper la lecture : la requête doit être finalisée avant d'ouvrir la
        // transaction, sinon le commit échoue (« SQL statements in progress »).
        QSqlQuery q(database);
        if (!q.exec(QStringLiteral("PRAGMA user_version")) || !q.next()) {
            m_openError = QStringLiteral("user_version: ") + q.lastError().text();
            qWarning() << "morfPhoto: lecture user_version impossible" << q.lastError().text();
            return false;
        }
        current = q.value(0).toInt();
    }
    if (current >= kSchemaVersion)
        return true;

    // Appliquer, dans l'ordre, chaque version de schéma manquante. Chaque version
    // est sa propre transaction scellée par `PRAGMA user_version` : une base en v1
    // reçoit uniquement la v2, sans rejouer la création initiale.
    for (int version = current + 1; version <= kSchemaVersion; ++version) {
        const bool inTx = database.transaction();
        for (const QString& stmt : migrationStatements(version)) {
            QSqlQuery m(database);
            if (!m.exec(stmt)) {
                m_openError = QStringLiteral("migration v%1: %2").arg(version).arg(m.lastError().text());
                qWarning() << "morfPhoto: migration echouee" << version << m.lastError().text() << stmt;
                if (inTx) database.rollback();
                return false;
            }
        }
        // user_version est un entier de PRAGMA (pas de valeur externe) : interpolation sûre.
        { QSqlQuery v(database); v.exec(QStringLiteral("PRAGMA user_version = %1").arg(version)); }
        if (inTx && !database.commit()) {
            m_openError = QStringLiteral("commit v%1: %2").arg(version).arg(database.lastError().text());
            qWarning() << "morfPhoto: commit migration echoue" << version << database.lastError().text();
            return false;
        }
    }
    return true;
}

// --- Dossiers ---------------------------------------------------------------

int PhotoRepository::addFolder(const QString& path, const QString& rootPath,
                               const QVariant& label, bool recursive, bool removable,
                               const QVariant& volumeLabel, const QString& addedAt) {
    QSqlQuery q(db());
    if (!run(q, QStringLiteral(
                 "INSERT INTO folders (path, root_path, label, recursive, removable, "
                 "volume_label, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)"),
             {path, rootPath, label, recursive ? 1 : 0, removable ? 1 : 0, volumeLabel, addedAt}))
        return -1;
    return q.lastInsertId().toInt();
}

QVector<FolderRow> PhotoRepository::activeFolders() {
    QVector<FolderRow> out;
    QSqlQuery q(db());
    q.exec(QStringLiteral("SELECT id, path, root_path, recursive, enabled, removable "
                          "FROM folders WHERE enabled = 1 AND deleted_at IS NULL"));
    while (q.next())
        out.push_back({q.value(0).toInt(), q.value(1).toString(), q.value(2).toString(),
                       q.value(3).toBool(), q.value(4).toBool(), q.value(5).toBool()});
    return out;
}

QVector<FolderRow> PhotoRepository::allFolders() {
    QVector<FolderRow> out;
    QSqlQuery q(db());
    q.exec(QStringLiteral("SELECT id, path, root_path, recursive, enabled, removable FROM folders"));
    while (q.next())
        out.push_back({q.value(0).toInt(), q.value(1).toString(), q.value(2).toString(),
                       q.value(3).toBool(), q.value(4).toBool(), q.value(5).toBool()});
    return out;
}

void PhotoRepository::setFolderAutoDisabled(int folderId, bool autoDisabled) {
    // Couper (ou rétablir) la surveillance sans jamais toucher aux données
    // historiques. enabled suit auto_disabled pour arrêter les passes.
    QSqlQuery q(db());
    run(q, QStringLiteral("UPDATE folders SET auto_disabled = ?, enabled = ? WHERE id = ?"),
        {autoDisabled ? 1 : 0, autoDisabled ? 0 : 1, folderId});
}

void PhotoRepository::setFolderScanned(int folderId, const QString& when) {
    QSqlQuery q(db());
    run(q, QStringLiteral("UPDATE folders SET last_scan_at = ? WHERE id = ?"), {when, folderId});
}

bool PhotoRepository::getFolder(int folderId, FolderRow* out) {
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT id, path, root_path, recursive, enabled, removable "
                          "FROM folders WHERE id = ?"), {folderId});
    if (!q.next())
        return false;
    if (out)
        *out = {q.value(0).toInt(), q.value(1).toString(), q.value(2).toString(),
                q.value(3).toBool(), q.value(4).toBool(), q.value(5).toBool()};
    return true;
}

QJsonArray PhotoRepository::listFoldersDetail() {
    QJsonArray arr;
    QSqlQuery q(db());
    q.exec(QStringLiteral(
        "SELECT id, path, root_path, label, enabled, auto_disabled, recursive, "
        "removable, volume_label, analytics_excluded, added_at, last_scan_at, deleted_at "
        "FROM folders ORDER BY path"));
    QStringList names;
    while (q.next()) {
        if (names.isEmpty())
            names = queryFieldNames(q);
        arr.append(rowToJson(q, names));
    }
    return arr;
}

void PhotoRepository::setFolderEnabled(int folderId, bool enabled) {
    // Action volontaire de l'utilisateur : elle lève le drapeau auto_disabled.
    QSqlQuery q(db());
    run(q, QStringLiteral("UPDATE folders SET enabled = ?, auto_disabled = 0 WHERE id = ?"),
        {enabled ? 1 : 0, folderId});
}

void PhotoRepository::setFolderMedia(int folderId, bool removable, const QVariant& volumeLabel) {
    // Régler le caractère amovible et le libellé de volume. Ne touche jamais aux
    // fichiers : c'est une propriété de la sélection, appliquée dès la prochaine passe.
    QSqlQuery q(db());
    run(q, QStringLiteral("UPDATE folders SET removable = ?, volume_label = ? WHERE id = ?"),
        {removable ? 1 : 0, volumeLabel, folderId});
}

void PhotoRepository::setFolderAnalyticsExcluded(int folderId, bool excluded) {
    // Bascule NON destructive : les données restent, seules les analyses les ignorent.
    QSqlQuery q(db());
    run(q, QStringLiteral("UPDATE folders SET analytics_excluded = ? WHERE id = ?"),
        {excluded ? 1 : 0, folderId});
}

void PhotoRepository::softDeleteFolder(int folderId, const QString& now) {
    // Retrait DOUX : les fichiers passent 'deleted' (conservés), la sélection est
    // désactivée et horodatée. La donnée n'est jamais supprimée physiquement ;
    // `deleted_at` la classe comme retirée (fenêtre séparée dans PhotoHub).
    const Own own = beginOwn();
    if (own == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, softDeleteFolder abandonne";
        return;
    }
    // Numeroter les fichiers dont l'etat change (le flux les donne « missing »).
    bool ok = stampFilesWhere(db(), QStringLiteral("folder_id = ? AND state != 'deleted'"), {folderId});
    QSqlQuery q1(db());
    ok = run(q1, QStringLiteral("UPDATE files SET state = 'deleted', disappeared_at = ? "
                                "WHERE folder_id = ? AND state != 'deleted'"), {now, folderId}) && ok;
    QSqlQuery q2(db());
    ok = run(q2, QStringLiteral("UPDATE folders SET enabled = 0, deleted_at = ? WHERE id = ?"),
             {now, folderId}) && ok;
    endOwn(own, ok);
}

void PhotoRepository::restoreFolder(int folderId) {
    // Annule un retrait doux : la sélection redevient surveillée et active. Les
    // fichiers restent 'deleted' jusqu'à la prochaine passe, qui les ravive
    // (touchSeen/updateFile repassent 'present'). auto_disabled est remis à plat :
    // c'est un choix volontaire de l'utilisateur, comme setFolderEnabled.
    QSqlQuery q(db());
    run(q, QStringLiteral("UPDATE folders SET enabled = 1, auto_disabled = 0, "
                          "deleted_at = NULL WHERE id = ?"), {folderId});
}

int PhotoRepository::folderIdByPath(const QString& path, bool* deleted) {
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT id, deleted_at FROM folders WHERE path = ?"), {path});
    if (!q.next())
        return -1;
    if (deleted)
        *deleted = !q.value(1).isNull();
    return q.value(0).toInt();
}

// --- Fichiers ---------------------------------------------------------------

KnownFiles PhotoRepository::existingFilesInFolder(int folderId) {
    KnownFiles map;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT id, path, size, mtime, state FROM files WHERE folder_id = ?"),
        {folderId});
    while (q.next())
        map.insert(q.value(1).toString(),
                   {q.value(0).toInt(), q.value(2).toLongLong(),
                    q.value(3).toLongLong(), q.value(4).toString()});
    return map;
}

KnownFiles PhotoRepository::existingFilesInScope(int folderId, const QString& path, bool recursive) {
    QVariantList binds;
    const QString where = scopePredicate(folderId, path, recursive, QString(), binds);
    KnownFiles map;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT id, path, size, mtime, state FROM files WHERE ") + where, binds);
    while (q.next())
        map.insert(q.value(1).toString(),
                   {q.value(0).toInt(), q.value(2).toLongLong(),
                    q.value(3).toLongLong(), q.value(4).toString()});
    return map;
}

int PhotoRepository::insertFile(int folderId, const FileInfo& info, const ExifData& exif,
                                bool exifOk, const QString& now) {
    const Own own = beginOwn();
    if (own == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, insertFile abandonne";
        return -1;
    }
    const bool bumped = bumpChangeSeq(db());
    QSqlQuery q(db());
    const bool inserted = bumped && run(q, QStringLiteral(
             "INSERT INTO files (folder_id, path, directory, filename, extension, file_type, "
             "size, mtime, state, exif_ok, first_seen_at, last_seen_at, last_indexed_at, "
             "taken_at, make, camera_model, lens, focal_length, focal_length_35mm, aperture, "
             "shutter_speed, shutter_speed_s, iso, exposure_compensation, rating, latitude, "
             "longitude, raw_exif, original_width, original_height, change_seq) VALUES "
             "(?,?,?,?,?,?,?,?,'present',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%1)")
             .arg(QString::fromLatin1(kSeqNow)),
        {folderId, info.path, info.directory, info.filename, info.extension, info.fileType,
         info.size, info.mtime, exifOk ? 1 : 0, now, now, now,
         exif.takenAt, exif.make, exif.cameraModel, exif.lens, exif.focalLength,
         exif.focalLength35mm, exif.aperture, exif.shutterSpeed, exif.shutterSpeedS,
         exif.iso, exif.exposureCompensation, exif.rating, exif.latitude, exif.longitude,
         rawExifVariant(exif), exif.originalWidth, exif.originalHeight});
    const int id = inserted ? q.lastInsertId().toInt() : -1;
    endOwn(own, inserted);
    return id;
}

void PhotoRepository::updateFile(int fileId, const FileInfo& info, const ExifData& exif,
                                 bool exifOk, const QString& now) {
    // Ravive un fichier qui était 'missing'. Si l'extraction a échoué, mettre à
    // jour size/mtime mais NE PAS toucher aux colonnes EXIF : préférer garder
    // l'ancienne valeur plutôt que de l'effacer sur une erreur transitoire.
    QString sql = QStringLiteral(
        "UPDATE files SET directory = ?, filename = ?, extension = ?, file_type = ?, "
        "size = ?, mtime = ?, exif_ok = ?, last_seen_at = ?, last_indexed_at = ?, "
        "state = 'present', disappeared_at = NULL, change_seq = %1")
        .arg(QString::fromLatin1(kSeqNow));
    QVariantList binds = {info.directory, info.filename, info.extension, info.fileType,
                          info.size, info.mtime, exifOk ? 1 : 0, now, now};
    if (exifOk) {
        sql += QStringLiteral(
            ", taken_at = ?, make = ?, camera_model = ?, lens = ?, focal_length = ?, "
            "focal_length_35mm = ?, aperture = ?, shutter_speed = ?, shutter_speed_s = ?, "
            "iso = ?, exposure_compensation = ?, rating = ?, latitude = ?, longitude = ?, "
            "raw_exif = ?");
        binds += QVariantList{exif.takenAt, exif.make, exif.cameraModel, exif.lens,
                              exif.focalLength, exif.focalLength35mm, exif.aperture,
                              exif.shutterSpeed, exif.shutterSpeedS, exif.iso,
                              exif.exposureCompensation, exif.rating, exif.latitude,
                              exif.longitude, rawExifVariant(exif)};
    }
    if (exifOk || !exif.originalWidth.isNull()) {
        sql += QStringLiteral(", original_width = ?, original_height = ?");
        binds += QVariantList{exif.originalWidth, exif.originalHeight};
    }
    sql += QStringLiteral(" WHERE id = ?");
    binds += fileId;
    const Own own = beginOwn();
    if (own == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, updateFile abandonne";
        return;
    }
    bool ok = bumpChangeSeq(db());
    QSqlQuery q(db());
    ok = ok && run(q, sql, binds);
    endOwn(own, ok);
}

void PhotoRepository::touchSeen(int fileId, const QString& now) {
    touchSeen(QVector<int>{fileId}, now);
}

void PhotoRepository::touchSeen(const QVector<int>& fileIds, const QString& now) {
    // Fichier inchangé : noter qu'il est toujours là. Ravive un 'missing' réapparu ;
    // seul ce changement d'etat est numerote dans le flux (un fichier deja present ne
    // produit aucun changement).
    const Own own = beginOwn();
    if (own == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, touchSeen abandonne";
        return;
    }
    const bool ok = runBatchedFileUpdate(
        db(),
        QStringLiteral("UPDATE files SET last_seen_at = ?, state = 'present', "
                       "disappeared_at = NULL WHERE id IN (%1)"),
        QStringLiteral("id IN (%1) AND state != 'present'"),
        fileIds, now);
    endOwn(own, ok);
}

void PhotoRepository::markMissing(const QVector<int>& fileIds, const QString& now) {
    const Own own = beginOwn();
    if (own == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, markMissing abandonne";
        return;
    }
    const bool ok = runBatchedFileUpdate(
        db(),
        QStringLiteral("UPDATE files SET state = 'missing', disappeared_at = ? "
                       "WHERE id IN (%1) AND state != 'missing'"),
        QStringLiteral("id IN (%1) AND state != 'missing'"),
        fileIds, now);
    endOwn(own, ok);
}

// --- Bibliothèque -----------------------------------------------------------

namespace {

const char* const kLibraryFrom =
    " FROM files f"
    " JOIN library_files lf ON lf.file_id = f.id"
    " JOIN library_versions v ON v.file_id = f.id";

// Qt lie une QString nulle en NULL SQL ; un libelle absent est ici une chaine vide.
QString notNull(const QString& value) {
    return value.isNull() ? QStringLiteral("") : value;
}

void addIn(QStringList& clauses, QVariantList& binds, const QString& column, const QStringList& values) {
    if (values.isEmpty())
        return;
    QStringList holders;
    for (const QString& value : values) { holders << QStringLiteral("?"); binds << notNull(value); }
    clauses << QStringLiteral("%1 IN (%2)").arg(column, holders.join(QLatin1Char(',')));
}

// Toutes les conditions portent sur la MEME version : une note sur une copie et un
// mot-cle sur une autre ne font pas une photo qui repond aux deux.
QString libraryWhere(const LibraryFilter& f, QVariantList& binds, bool hasFilesFts) {
    QStringList c = {QStringLiteral("f.state = 'present'")};
    if (f.minRating > 0) {
        c << QStringLiteral("v.rejected = 0 AND v.rating >= ?");
        binds << f.minRating;
    }
    if (f.rejected == QLatin1String("hide")) c << QStringLiteral("v.rejected = 0");
    if (f.rejected == QLatin1String("only")) c << QStringLiteral("v.rejected = 1");
    // Un etat inconnu (NULL) ne satisfait jamais un filtre choisi.
    if (f.edited == QLatin1String("edited"))   c << QStringLiteral("v.edited = 1");
    if (f.edited == QLatin1String("unedited")) c << QStringLiteral("v.edited = 0");
    if (f.labels || f.unlabeled) {
        c << (f.unlabeled ? QStringLiteral("((v.labels & ?) != 0 OR v.labels = 0)")
                          : QStringLiteral("(v.labels & ?) != 0"));
        binds << f.labels;
    }
    if (!f.kinds.isEmpty()) {
        QStringList either;
        addIn(either, binds, QStringLiteral("lf.ext_label"), f.kinds);
        addIn(either, binds, QStringLiteral("lf.kind_label"), f.kinds);
        c << QLatin1Char('(') + either.join(QStringLiteral(" OR ")) + QLatin1Char(')');
    }
    addIn(c, binds, QStringLiteral("lf.camera_label"), f.cameras);
    addIn(c, binds, QStringLiteral("lf.body_key"), f.bodies);
    addIn(c, binds, QStringLiteral("f.lens"), f.lenses);
    addIn(c, binds, QStringLiteral("lf.iso_label"), f.iso);
    addIn(c, binds, QStringLiteral("lf.aperture_label"), f.aperture);
    addIn(c, binds, QStringLiteral("lf.focal_label"), f.focal);
    addIn(c, binds, QStringLiteral("lf.shutter_label"), f.shutter);
    for (const QString& keyword : f.keywords) {
        // « a » couvre « a|b » : '}' suit immediatement '|' dans l'ordre binaire.
        c << QStringLiteral("EXISTS (SELECT 1 FROM library_keywords k WHERE k.version_id = v.id "
                            "AND (k.keyword = ? OR (k.keyword >= ? AND k.keyword < ?)))");
        binds << keyword << keyword + QLatin1Char('|') << keyword + QLatin1Char('}');
    }
    if (!f.takenFrom.isEmpty()) {
        c << QStringLiteral("v.taken_at >= ?");
        binds << f.takenFrom;
    }
    if (!f.takenTo.isEmpty()) {
        const QDate toDate = QDate::fromString(f.takenTo, Qt::ISODate);
        if (toDate.isValid()) {
            c << QStringLiteral("v.taken_at < ?");
            binds << toDate.addDays(1).toString(Qt::ISODate);
        } else {
            c << QStringLiteral("substr(v.taken_at, 1, 10) <= ?");
            binds << f.takenTo;
        }
    }
    if (!f.folderPath.isEmpty()) {
        if (f.recursive) {
            if (f.folderPath == QLatin1String("/")) {
                c << QStringLiteral("f.directory >= '/' AND f.directory < '0'");
            } else {
                // Plage contigue [folder, folder0) exploitable par idx_files_state_dir_meta,
                // raffinee dans l'index couvrant pour exclure /folder-autre.
                c << QStringLiteral(
                    "f.directory >= ? AND f.directory < ? "
                    "AND (f.directory = ? OR f.directory >= ?)");
                binds << f.folderPath << f.folderPath + QLatin1Char('0')
                      << f.folderPath << f.folderPath + QLatin1Char('/');
            }
        } else {
            c << QStringLiteral("f.directory = ?");
            binds << f.folderPath;
        }
    }
    if (!f.filename.isEmpty()) {
        if (hasFilesFts && f.filename.size() >= 3) {
            const QString ftsQuery = QLatin1Char('"')
                + QString(f.filename).replace(QLatin1Char('"'), QStringLiteral("\"\""))
                + QLatin1Char('"');
            c << QStringLiteral(
                "f.id IN (SELECT rowid FROM files_fts WHERE filename MATCH ?) "
                "AND instr(lower(f.filename), lower(?)) > 0");
            binds << ftsQuery << f.filename;
        } else {
            c << QStringLiteral("instr(lower(f.filename), lower(?)) > 0");
            binds << f.filename;
        }
    }
    return QStringLiteral(" WHERE ") + c.join(QStringLiteral(" AND "));
}

struct LibraryCursor {
    bool hasTakenAt = false;
    QString takenAt;
    int fileId = 0;
};

// Encode un curseur keyset [takenAtOrNull, lastFileId] en Base64URL sans padding.
QString encodeLibraryCursor(const QVariant& takenAt, int fileId) {
    QJsonArray arr;
    if (takenAt.isNull() || takenAt.toString().isEmpty())
        arr.append(QJsonValue::Null);
    else
        arr.append(takenAt.toString());
    arr.append(fileId);
    const QByteArray json = QJsonDocument(arr).toJson(QJsonDocument::Compact);
    return QString::fromLatin1(
        json.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

// Décode et valide un curseur keyset Base64URL [takenAtOrNull, lastFileId].
bool decodeLibraryCursor(const QString& cursor, LibraryCursor* out) {
    if (cursor.isEmpty())
        return false;
    const QByteArray raw = cursor.toUtf8();
    if (raw.size() % 4 == 1)
        return false;
    for (const char ch : raw) {
        const bool okChar = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
        if (!okChar)
            return false;
    }
    QByteArray padded = raw;
    while (padded.size() % 4 != 0)
        padded.append('=');
    const auto decoded = QByteArray::fromBase64Encoding(
        padded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok)
        return false;

    QJsonParseError parseErr{};
    const QJsonDocument doc = QJsonDocument::fromJson(decoded.decoded, &parseErr);
    if (parseErr.error != QJsonParseError::NoError || !doc.isArray())
        return false;
    const QJsonArray arr = doc.array();
    if (arr.size() != 2)
        return false;

    const QJsonValue v0 = arr.at(0);
    const QJsonValue v1 = arr.at(1);
    bool hasTakenAt = false;
    QString takenAt;
    if (v0.isNull()) {
        hasTakenAt = false;
    } else if (v0.isString()) {
        takenAt = v0.toString();
        if (takenAt.isEmpty())
            return false;
        hasTakenAt = true;
    } else {
        return false;
    }

    if (!v1.isDouble())
        return false;
    const double idD = v1.toDouble();
    if (idD < 1.0 || idD > 2147483647.0 || std::floor(idD) != idD)
        return false;

    if (out) {
        out->hasTakenAt = hasTakenAt;
        out->takenAt = takenAt;
        out->fileId = static_cast<int>(idD);
    }
    return true;
}

} // namespace

QHash<int, QString> PhotoRepository::libraryFingerprints(int folderId) {
    QHash<int, QString> out;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT lf.file_id, lf.fingerprint FROM library_files lf "
                          "JOIN files f ON f.id = lf.file_id WHERE f.folder_id = ?"), {folderId});
    while (q.next())
        out.insert(q.value(0).toInt(), q.value(1).toString());
    return out;
}

QHash<int, QString> PhotoRepository::libraryFingerprintsInScope(int folderId, const QString& path,
                                                                 bool recursive) {
    QVariantList binds;
    const QString where = scopePredicate(folderId, path, recursive, QStringLiteral("f."), binds);
    QHash<int, QString> out;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT lf.file_id, lf.fingerprint FROM library_files lf "
                          "JOIN files f ON f.id = lf.file_id WHERE ") + where, binds);
    while (q.next())
        out.insert(q.value(0).toInt(), q.value(1).toString());
    return out;
}

ExifData PhotoRepository::libraryBase(int fileId) {
    ExifData base;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT taken_at, make, camera_model, lens, focal_length, aperture, "
                          "shutter_speed_s, iso, rating, latitude, longitude, raw_exif "
                          "FROM files WHERE id = ?"), {fileId});
    if (!q.next())
        return base;
    base.takenAt = q.value(0);
    base.make = q.value(1);
    base.cameraModel = q.value(2);
    base.lens = q.value(3);
    base.focalLength = q.value(4);
    base.aperture = q.value(5);
    base.shutterSpeedS = q.value(6);
    base.iso = q.value(7);
    base.rating = q.value(8);
    base.latitude = q.value(9);
    base.longitude = q.value(10);
    base.raw = QJsonDocument::fromJson(q.value(11).toString().toUtf8()).object();
    base.ok = true;
    return base;
}

void PhotoRepository::storeLibrary(int fileId, const QString& fingerprint, const LibraryFileLabels& l,
                                   const QVector<LibraryVersion>& versions) {
    QSqlDatabase database = db();
    const Own ownTransaction = beginOwn();
    if (ownTransaction == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, storeLibrary abandonne";
        return;
    }
    {
        // Toute modification de versions, mots-cles ou sidecar change le fichier pour
        // le flux : l'appelant n'ecrit ici que lorsque l'empreinte a vraiment change.
        bumpChangeSeq(database);
        QSqlQuery stamp(database);
        run(stamp, QStringLiteral("UPDATE files SET change_seq = %1 WHERE id = ?")
                       .arg(QString::fromLatin1(kSeqNow)), {fileId});
        QSqlQuery del(database);
        run(del, QStringLiteral("DELETE FROM library_versions WHERE file_id = ?"), {fileId});
        QSqlQuery file(database);
        run(file, QStringLiteral(
                "INSERT OR REPLACE INTO library_files (file_id, fingerprint, kind_label, ext_label, "
                "camera_label, body_key, body_serial, iso_label, aperture_label, focal_label, "
                "shutter_label) VALUES (?,?,?,?,?,?,?,?,?,?,?)"),
            {fileId, notNull(fingerprint), notNull(l.kind), notNull(l.extension), notNull(l.camera),
             notNull(l.bodyKey), notNull(l.bodySerial), notNull(l.iso), notNull(l.aperture),
             notNull(l.focal), notNull(l.shutter)});
        QSqlQuery kw(database);
        bool kwPrepared = false;
        for (const LibraryVersion& v : versions) {
            const QVariant raw = v.rawXmp.isEmpty() ? QVariant()
                : QVariant(QString::fromUtf8(QJsonDocument(v.rawXmp).toJson(QJsonDocument::Compact)));
            const QVariant edited = v.edited.isValid() ? QVariant(v.edited.toBool() ? 1 : 0) : QVariant();
            QSqlQuery row(database);
            run(row, QStringLiteral(
                    "INSERT INTO library_versions (file_id, version, is_copy, sidecar, rating, rejected, "
                    "labels, edited, taken_at, latitude, longitude, title, description, creator, rights, "
                    "version_name, raw_xmp, publisher, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"),
                {fileId, v.version, v.copy ? 1 : 0, v.sidecar.isEmpty() ? QVariant() : QVariant(v.sidecar),
                 v.rating, v.rejected ? 1 : 0, v.labels, edited, v.takenAt, v.latitude, v.longitude,
                 v.title, v.description, v.creator, v.rights, v.versionName, raw, v.publisher, v.notes});
            const QVariant versionId = row.lastInsertId();
            if (!v.keywords.isEmpty() && !kwPrepared) {
                kwPrepared = kw.prepare(QStringLiteral(
                    "INSERT OR IGNORE INTO library_keywords (version_id, keyword) VALUES (?, ?)"));
                if (!kwPrepared) {
                    const auto error = kw.lastError();
                    qWarning() << "morfPhoto SQL prepare:" << error.nativeErrorCode() << error.text();
                }
            }
            if (kwPrepared) {
                for (const QString& keyword : v.keywords) {
                    kw.bindValue(0, versionId);
                    kw.bindValue(1, keyword);
                    if (!kw.exec()) {
                        const auto error = kw.lastError();
                        qWarning() << "morfPhoto SQL exec:" << error.nativeErrorCode() << error.text();
                    }
                }
            }
        }
    }
    endOwn(ownTransaction, true);
}

QJsonArray PhotoRepository::libraryItems(const QVector<int>& fileIds, const QHash<int, QString>& matched,
                                         bool withRaw) {
    if (fileIds.isEmpty())
        return {};
    QStringList idList;
    idList.reserve(fileIds.size());
    for (int id : fileIds)
        idList << QString::number(id);    // entiers venus de la base : interpolation sure
    const QString ids = idList.join(QLatin1Char(','));

    auto valOrNull = [](const QSqlQuery& q, int idx) -> QJsonValue {
        const QVariant v = q.value(idx);
        return v.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue::fromVariant(v);
    };

    struct PendingVersion {
        int versionId = 0;
        int fileId = 0;
        QJsonObject obj;
    };
    QVector<PendingVersion> pendingVersions;
    pendingVersions.reserve(fileIds.size());
    QStringList versionIdList;
    versionIdList.reserve(fileIds.size());
    {
        QSqlQuery q(db());
        q.exec(QStringLiteral("SELECT id, file_id, version, is_copy, sidecar, rating, rejected, labels, "
                              "edited, taken_at, latitude, longitude, title, description, creator, rights, "
                              "version_name, publisher, notes%1 FROM library_versions WHERE file_id IN (%2) ORDER BY version")
                   .arg(withRaw ? QStringLiteral(", raw_xmp") : QString(), ids));
        while (q.next()) {
            const int versionId = q.value(0).toInt();
            const int fileId = q.value(1).toInt();
            versionIdList << QString::number(versionId);

            const QVariant sidecarV = q.value(4);
            const QVariant editedV = q.value(8);
            QJsonObject o;
            o.insert(QStringLiteral("version"), q.value(2).toInt());
            o.insert(QStringLiteral("copy"), q.value(3).toInt() != 0);
            o.insert(QStringLiteral("sidecar"), sidecarV.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(sidecarV.toString()));
            o.insert(QStringLiteral("rating"), q.value(5).toInt());
            o.insert(QStringLiteral("rejected"), q.value(6).toInt() != 0);
            o.insert(QStringLiteral("labels"), q.value(7).toInt());
            o.insert(QStringLiteral("edited"), editedV.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(editedV.toInt() != 0));
            o.insert(QStringLiteral("taken_at"), valOrNull(q, 9));
            o.insert(QStringLiteral("latitude"), valOrNull(q, 10));
            o.insert(QStringLiteral("longitude"), valOrNull(q, 11));
            o.insert(QStringLiteral("title"), valOrNull(q, 12));
            o.insert(QStringLiteral("description"), valOrNull(q, 13));
            o.insert(QStringLiteral("creator"), valOrNull(q, 14));
            o.insert(QStringLiteral("rights"), valOrNull(q, 15));
            o.insert(QStringLiteral("version_name"), valOrNull(q, 16));
            o.insert(QStringLiteral("publisher"), valOrNull(q, 17));
            o.insert(QStringLiteral("notes"), valOrNull(q, 18));
            o.insert(QStringLiteral("has_sidecar"), !sidecarV.isNull());
            if (withRaw) {
                const QVariant rawV = q.value(19);
                if (rawV.isNull()) {
                    o.insert(QStringLiteral("raw_xmp"), QJsonValue::Null);
                } else {
                    const QJsonDocument raw = QJsonDocument::fromJson(rawV.toString().toUtf8());
                    o.insert(QStringLiteral("raw_xmp"), raw.isObject() ? QJsonValue(raw.object()) : QJsonValue(QJsonValue::Null));
                }
            }
            pendingVersions.push_back({versionId, fileId, std::move(o)});
        }
    }

    QHash<int, QJsonArray> keywords;
    if (!versionIdList.isEmpty()) {
        // library_keywords est PRIMARY KEY (version_id, keyword) WITHOUT ROWID :
        // requete directe sans joindre library_versions et deja triee par keyword.
        QSqlQuery q(db());
        q.exec(QStringLiteral("SELECT version_id, keyword FROM library_keywords "
                              "WHERE version_id IN (%1)").arg(versionIdList.join(QLatin1Char(','))));
        while (q.next())
            keywords[q.value(0).toInt()].append(q.value(1).toString());
    }

    QHash<int, QJsonArray> versions;
    versions.reserve(fileIds.size());
    const QJsonArray emptyKeywords;
    for (PendingVersion& pv : pendingVersions) {
        const auto kwIt = keywords.constFind(pv.versionId);
        pv.obj.insert(QStringLiteral("keywords"), kwIt != keywords.constEnd() ? kwIt.value() : emptyKeywords);
        versions[pv.fileId].append(std::move(pv.obj));
    }

    static const QJsonArray kDefaultMatched{0};
    QHash<int, QJsonObject> rows;
    rows.reserve(fileIds.size());
    {
        QSqlQuery q(db());
        q.exec(QStringLiteral(
            "SELECT f.id, f.path, fo.root_path AS root, f.directory, f.filename, f.extension, f.file_type, "
            "f.size, f.mtime, f.make, f.camera_model, f.lens, f.focal_length, f.focal_length_35mm, "
            "f.aperture, f.shutter_speed, f.shutter_speed_s, f.iso, f.exposure_compensation, "
            "lf.kind_label AS kind, lf.ext_label AS file_ext, lf.camera_label AS camera, lf.body_key, "
            "lf.body_serial, lf.iso_label, lf.aperture_label, lf.focal_label, lf.shutter_label, "
            "f.original_width, f.original_height, f.first_seen_at%1 "
            "FROM files f JOIN library_files lf ON lf.file_id = f.id JOIN folders fo ON fo.id = f.folder_id "
            "WHERE f.id IN (%2)").arg(withRaw ? QStringLiteral(", f.raw_exif") : QString(), ids));
        while (q.next()) {
            const int id = q.value(0).toInt();
            const QString filePath = q.value(1).toString();
            const QString root = q.value(2).toString();
            QJsonObject o;
            o.insert(QStringLiteral("id"), id);
            o.insert(QStringLiteral("path"), filePath);
            o.insert(QStringLiteral("root"), root);
            o.insert(QStringLiteral("directory"), valOrNull(q, 3));
            o.insert(QStringLiteral("filename"), valOrNull(q, 4));
            o.insert(QStringLiteral("extension"), valOrNull(q, 5));
            o.insert(QStringLiteral("file_type"), valOrNull(q, 6));
            o.insert(QStringLiteral("size"), valOrNull(q, 7));
            o.insert(QStringLiteral("mtime"), valOrNull(q, 8));
            o.insert(QStringLiteral("make"), valOrNull(q, 9));
            o.insert(QStringLiteral("camera_model"), valOrNull(q, 10));
            o.insert(QStringLiteral("lens"), valOrNull(q, 11));
            o.insert(QStringLiteral("focal_length"), valOrNull(q, 12));
            o.insert(QStringLiteral("focal_length_35mm"), valOrNull(q, 13));
            o.insert(QStringLiteral("aperture"), valOrNull(q, 14));
            o.insert(QStringLiteral("shutter_speed"), valOrNull(q, 15));
            o.insert(QStringLiteral("shutter_speed_s"), valOrNull(q, 16));
            o.insert(QStringLiteral("iso"), valOrNull(q, 17));
            o.insert(QStringLiteral("exposure_compensation"), valOrNull(q, 18));
            o.insert(QStringLiteral("kind"), valOrNull(q, 19));
            o.insert(QStringLiteral("file_ext"), valOrNull(q, 20));
            o.insert(QStringLiteral("camera"), valOrNull(q, 21));
            o.insert(QStringLiteral("body_key"), valOrNull(q, 22));
            o.insert(QStringLiteral("body_serial"), valOrNull(q, 23));
            o.insert(QStringLiteral("iso_label"), valOrNull(q, 24));
            o.insert(QStringLiteral("aperture_label"), valOrNull(q, 25));
            o.insert(QStringLiteral("focal_label"), valOrNull(q, 26));
            o.insert(QStringLiteral("shutter_label"), valOrNull(q, 27));
            o.insert(QStringLiteral("original_width"), valOrNull(q, 28));
            o.insert(QStringLiteral("original_height"), valOrNull(q, 29));
            o.insert(QStringLiteral("first_seen_at"), valOrNull(q, 30));
            if (withRaw) {
                const QVariant rawV = q.value(31);
                if (rawV.isNull()) {
                    o.insert(QStringLiteral("raw_exif"), QJsonValue::Null);
                } else {
                    const QJsonDocument d = QJsonDocument::fromJson(rawV.toString().toUtf8());
                    o.insert(QStringLiteral("raw_exif"), d.isObject() ? QJsonValue(d.object()) : QJsonValue(QJsonValue::Null));
                }
            }
            // Le client voit ces fichiers sous un autre chemin que le conteneur.
            QString relPath;
            if (root == QLatin1String("/") && filePath.startsWith(QLatin1Char('/'))) {
                relPath = filePath.mid(1);
            } else if (!root.isEmpty() && filePath.size() > root.size()
                       && filePath.startsWith(root) && filePath.at(root.size()) == QLatin1Char('/')) {
                relPath = filePath.mid(root.size() + 1);
            } else {
                relPath = QDir(root).relativeFilePath(filePath);
            }
            o.insert(QStringLiteral("relative_path"), relPath);
            o.insert(QStringLiteral("versions"), versions.value(id));
            const auto mIt = matched.constFind(id);
            if (mIt != matched.constEnd()) {
                if (mIt.value() == QLatin1String("0")) {
                    o.insert(QStringLiteral("matched_versions"), kDefaultMatched);
                } else {
                    QJsonArray list;
                    for (const QString& version : mIt.value().split(QLatin1Char(',')))
                        list.append(version.toInt());
                    o.insert(QStringLiteral("matched_versions"), list);
                }
            }
            rows.insert(id, std::move(o));
        }
    }

    QJsonArray items;
    for (int id : fileIds) {
        const auto it = rows.constFind(id);
        if (it != rows.constEnd())
            items.append(it.value());
    }
    return items;
}

QJsonObject PhotoRepository::librarySubfolders(const QString& folder) {
    const QString prefix = folder == QLatin1String("/") ? folder : folder + QLatin1Char('/');
    const QString upper = prefix.chopped(1) + QLatin1Char('0');
    QSqlQuery q(db());
    if (!run(q, QStringLiteral("SELECT DISTINCT directory FROM files INDEXED BY idx_files_dir_state "
                               "WHERE state = 'present' AND directory >= ? AND directory < ?"),
             {prefix, upper}))
        return {};

    QMap<QString, bool> children;
    while (q.next()) {
        const QString relative = q.value(0).toString().mid(prefix.size());
        const auto parts = relative.split(QLatin1Char('/'));
        if (relative.isEmpty() || std::any_of(parts.cbegin(), parts.cend(), [](const QString& part) {
                return part.isEmpty() || part.startsWith(QLatin1Char('.'));
            }))
            continue;
        bool& hasChildren = children[parts.first()];
        hasChildren = hasChildren || parts.size() > 1;
    }
    if (q.lastError().isValid()) {
        qWarning() << "morfPhoto subfolder query:" << q.lastError().nativeErrorCode() << q.lastError().text();
        return {};
    }
    QJsonArray items;
    for (auto it = children.cbegin(); it != children.cend(); ++it)
        items.append(QJsonObject{{"path", prefix + it.key()}, {"has_children", it.value()}});
    return {{"items", items}};
}

QJsonObject PhotoRepository::libraryList(const LibraryFilter& filter, int page, int pageSize,
                                         const QString& cursor, bool* cursorValid, bool skipTotal) {
    LibraryCursor parsedCursor;
    const bool useCursor = !cursor.isEmpty();
    if (useCursor && !decodeLibraryCursor(cursor, &parsedCursor)) {
        if (cursorValid)
            *cursorValid = false;
        return {};
    }
    if (cursorValid)
        *cursorValid = true;

    QVariantList binds;
    const QString tail = QLatin1String(kLibraryFrom) + libraryWhere(filter, binds, m_hasFilesFts);

    int total = 0;
    if (!skipTotal) {
        QSqlQuery q(db());
        run(q, QStringLiteral("SELECT COUNT(DISTINCT f.id)") + tail, binds);
        if (q.next())
            total = q.value(0).toInt();
    }

    page = qBound(1, page, 1000000);
    pageSize = qMax(1, pageSize);
    QVariantList pageBinds = binds;
    QString sql = QStringLiteral("SELECT f.id, GROUP_CONCAT(v.version), MIN(v.taken_at)") +
                  tail + QStringLiteral(" GROUP BY f.id");
    if (useCursor) {
        if (parsedCursor.hasTakenAt) {
            sql += QStringLiteral(
                " HAVING (MIN(v.taken_at) IS NULL OR MIN(v.taken_at) > ? "
                "OR (MIN(v.taken_at) = ? AND f.id > ?))");
            pageBinds << parsedCursor.takenAt << parsedCursor.takenAt << parsedCursor.fileId;
        } else {
            sql += QStringLiteral(" HAVING (MIN(v.taken_at) IS NULL AND f.id > ?)");
            pageBinds << parsedCursor.fileId;
        }
        sql += QStringLiteral(" ORDER BY MIN(v.taken_at) IS NULL, MIN(v.taken_at), f.id LIMIT ?");
        pageBinds << (pageSize + 1);
    } else {
        sql += QStringLiteral(" ORDER BY MIN(v.taken_at) IS NULL, MIN(v.taken_at), f.id LIMIT ? OFFSET ?");
        pageBinds << (pageSize + 1) << static_cast<qint64>(page - 1) * pageSize;
    }

    QVector<int> ids;
    QHash<int, QString> matched;
    QVariant lastTakenAt;
    bool hasMore = false;
    {
        QSqlQuery q(db());
        run(q, sql, pageBinds);
        while (q.next()) {
            if (ids.size() == pageSize) {
                hasMore = true;
                break;
            }
            const int id = q.value(0).toInt();
            ids << id;
            matched.insert(id, q.value(1).toString());
            lastTakenAt = q.value(2);
        }
    }

    QJsonObject o;
    o["items"]       = libraryItems(ids, matched, false);
    if (!skipTotal)
        o["total"]   = total;
    o["page"]        = page;
    o["page_size"]   = pageSize;
    o["has_more"]    = hasMore;
    o["next_cursor"] = (hasMore && !ids.isEmpty())
        ? QJsonValue(encodeLibraryCursor(lastTakenAt, ids.last()))
        : QJsonValue(QJsonValue::Null);
    return o;
}

LibraryIdList PhotoRepository::libraryIdList(const LibraryFilter& filter) {
    QVariantList binds;
    const QString tail = QLatin1String(kLibraryFrom) + libraryWhere(filter, binds, m_hasFilesFts);
    LibraryIdList out;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT f.id, GROUP_CONCAT(v.version)") + tail +
               QStringLiteral(" GROUP BY f.id ORDER BY MIN(v.taken_at) IS NULL, MIN(v.taken_at), f.id"),
        binds);
    while (q.next()) {
        const int id = q.value(0).toInt();
        out.ids.append(id);
        const QString matched = q.value(1).toString();
        if (matched != QLatin1String("0"))
            out.nonDefaultMatched.insert(id, matched);
    }
    return out;
}

QJsonObject PhotoRepository::libraryListFromCache(const LibraryIdList& cached, int page, int pageSize,
                                                  const QString& cursor, bool* cursorValid,
                                                  bool skipTotal, bool* cacheMiss) {
    if (cacheMiss)
        *cacheMiss = false;
    LibraryCursor parsedCursor;
    const bool useCursor = !cursor.isEmpty();
    if (useCursor && !decodeLibraryCursor(cursor, &parsedCursor)) {
        if (cursorValid)
            *cursorValid = false;
        return {};
    }
    if (cursorValid)
        *cursorValid = true;

    page = qBound(1, page, 1000000);
    pageSize = qMax(1, pageSize);

    qsizetype startIdx = 0;
    if (useCursor) {
        const qsizetype pos = cached.ids.indexOf(parsedCursor.fileId);
        if (pos < 0) {
            if (cacheMiss)
                *cacheMiss = true;
            return {};
        }
        startIdx = pos + 1;
    } else {
        const qint64 offset = static_cast<qint64>(page - 1) * pageSize;
        startIdx = (offset >= cached.ids.size()) ? cached.ids.size() : static_cast<qsizetype>(offset);
    }

    const qsizetype count = qMin<qsizetype>(pageSize, qMax<qsizetype>(0, cached.ids.size() - startIdx));
    const bool hasMore = (startIdx + count) < cached.ids.size();

    QVector<int> pageIds;
    pageIds.reserve(count);
    QHash<int, QString> pageMatched;
    pageMatched.reserve(count);
    for (qsizetype i = 0; i < count; ++i) {
        const int id = cached.ids.at(startIdx + i);
        pageIds.append(id);
        const auto it = cached.nonDefaultMatched.constFind(id);
        pageMatched.insert(id, it != cached.nonDefaultMatched.constEnd()
                                   ? it.value()
                                   : QStringLiteral("0"));
    }

    QVariant lastTakenAt;
    if (hasMore && !pageIds.isEmpty()) {
        const int lastId = pageIds.last();
        const QStringList vParts = pageMatched.value(lastId).split(QLatin1Char(','), Qt::SkipEmptyParts);
        QStringList vHolders;
        QVariantList vBinds;
        vBinds << lastId;
        for (const QString& vp : vParts) {
            bool okV = false;
            const int vNum = vp.toInt(&okV);
            if (okV) {
                vHolders << QStringLiteral("?");
                vBinds << vNum;
            }
        }
        QSqlQuery q(db());
        const QString vSql = vHolders.isEmpty()
            ? QStringLiteral("SELECT MIN(taken_at) FROM library_versions WHERE file_id = ?")
            : QStringLiteral("SELECT MIN(taken_at) FROM library_versions WHERE file_id = ? AND version IN (%1)")
                  .arg(vHolders.join(QLatin1Char(',')));
        if (run(q, vSql, vBinds) && q.next())
            lastTakenAt = q.value(0);
    }

    QJsonObject o;
    o["items"]       = libraryItems(pageIds, pageMatched, false);
    if (!skipTotal)
        o["total"]   = static_cast<int>(cached.ids.size());
    o["page"]        = page;
    o["page_size"]   = pageSize;
    o["has_more"]    = hasMore;
    o["next_cursor"] = (hasMore && !pageIds.isEmpty())
        ? QJsonValue(encodeLibraryCursor(lastTakenAt, pageIds.last()))
        : QJsonValue(QJsonValue::Null);
    return o;
}

QJsonObject PhotoRepository::libraryPhoto(int fileId, bool* found) {
    const QJsonArray items = libraryItems({fileId}, {}, true);
    if (found) *found = !items.isEmpty();
    return items.isEmpty() ? QJsonObject() : items.first().toObject();
}

QJsonArray PhotoRepository::libraryPhotos(const QVector<int>& fileIds, bool withRaw) {
    return libraryItems(fileIds, {}, withRaw);
}

// --- Flux de changements ----------------------------------------------------

bool PhotoRepository::changeState(QString* catalogId, qint64* highWater) {
    QSqlDatabase database = db();
    const bool own = !m_inTransaction && database.transaction();   // lecture : un instantane
    QSqlQuery q(database);
    const bool ok = run(q, QStringLiteral(
        "SELECT (SELECT value FROM meta WHERE key = 'catalog_id'), "
        "       (SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'change_seq')"))
        && q.next();
    if (ok) {
        if (catalogId) *catalogId = q.value(0).toString();
        if (highWater) *highWater = q.value(1).toLongLong();
    }
    q.finish();
    if (own)
        database.commit();
    return ok;
}

QJsonObject PhotoRepository::libraryChanges(qint64 afterSeq, qint64 afterId, int limit) {
    QSqlDatabase database = db();
    // Tout dans UNE transaction de lecture : identite, plus haut numero et lignes
    // viennent du meme instantane (WAL), meme si l'indexation ecrit pendant ce temps.
    const bool own = !m_inTransaction && database.transaction();

    struct Change {
        qint64 seq = 0;
        qint64 id = 0;
        int kind = 0;        // 0 = present, 1 = missing, 2 = deleted
        QString path;
    };
    QVector<Change> rows;
    QString catalogId;
    qint64 highWater = 0;
    bool ok = false;
    bool more = false;
    {
        QSqlQuery st(database);
        if (run(st, QStringLiteral(
                "SELECT (SELECT value FROM meta WHERE key = 'catalog_id'), "
                "       (SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'change_seq')"))
            && st.next()) {
            catalogId = st.value(0).toString();
            highWater = st.value(1).toLongLong();
            ok = true;
        }
    }
    if (ok) {
        // Deux sources ordonnees par (change_seq, id), fusionnees : un id n'est jamais
        // dans les deux (le trigger d'insertion retire la pierre tombale).
        QVector<Change> files;
        QVector<Change> tombs;
        {
            QSqlQuery q(database);
            ok = run(q, QStringLiteral(
                     "SELECT id, change_seq, state, path FROM files "
                     "WHERE (change_seq, id) > (?, ?) ORDER BY change_seq, id LIMIT ?"),
                     {afterSeq, afterId, limit + 1});
            while (ok && q.next()) {
                Change c;
                c.id = q.value(0).toLongLong();
                c.seq = q.value(1).toLongLong();
                c.kind = q.value(2).toString() == QLatin1String("present") ? 0 : 1;
                c.path = q.value(3).toString();
                files.push_back(std::move(c));
            }
        }
        if (ok) {
            QSqlQuery q(database);
            ok = run(q, QStringLiteral(
                     "SELECT id, change_seq, path FROM deleted_files "
                     "WHERE (change_seq, id) > (?, ?) ORDER BY change_seq, id LIMIT ?"),
                     {afterSeq, afterId, limit + 1});
            while (ok && q.next()) {
                Change c;
                c.id = q.value(0).toLongLong();
                c.seq = q.value(1).toLongLong();
                c.kind = 2;
                c.path = q.value(2).toString();
                tombs.push_back(std::move(c));
            }
        }
        qsizetype fi = 0, ti = 0;
        while (ok && (fi < files.size() || ti < tombs.size())) {
            const bool takeFile = ti >= tombs.size()
                || (fi < files.size()
                    && (files[fi].seq < tombs[ti].seq
                        || (files[fi].seq == tombs[ti].seq && files[fi].id < tombs[ti].id)));
            if (rows.size() >= limit) {
                more = true;
                break;
            }
            rows.push_back(takeFile ? files[fi++] : tombs[ti++]);
        }
    }

    QJsonArray items;
    if (ok) {
        // Fiches completes des fichiers presents, via la serialisation de /library
        // (toutes les versions courantes, jamais un delta de versions).
        QVector<int> presentIds;
        for (const Change& c : rows)
            if (c.kind == 0)
                presentIds.push_back(static_cast<int>(c.id));
        QHash<qint64, QJsonObject> full;
        const QJsonArray fullItems = libraryItems(presentIds, {}, false);
        for (const QJsonValue& v : fullItems) {
            const QJsonObject o = v.toObject();
            full.insert(o.value(QStringLiteral("id")).toInteger(), o);
        }
        static const char* const kStates[] = {"present", "missing", "deleted"};
        for (const Change& c : rows) {
            QJsonObject o;
            if (c.kind == 0) {
                const auto it = full.constFind(c.id);
                if (it == full.constEnd())
                    continue;   // sans fiche bibliotheque : le prochain storeLibrary le renumerotera
                o = it.value();
            } else {
                o.insert(QStringLiteral("id"), c.id);
                o.insert(QStringLiteral("path"), c.path);
            }
            o.insert(QStringLiteral("seq"), c.seq);
            o.insert(QStringLiteral("state"), QString::fromLatin1(kStates[c.kind]));
            items.append(o);
        }
    }
    if (own)
        database.commit();
    if (!ok)
        return {};

    QJsonObject out;
    out.insert(QStringLiteral("catalog_id"), catalogId);
    out.insert(QStringLiteral("high_water"), highWater);
    if (more && !rows.isEmpty()) {
        QJsonObject next;
        next.insert(QStringLiteral("seq"), rows.last().seq);
        next.insert(QStringLiteral("id"), rows.last().id);
        out.insert(QStringLiteral("next"), next);
    } else {
        out.insert(QStringLiteral("next"), QJsonValue(QJsonValue::Null));
    }
    out.insert(QStringLiteral("items"), items);
    return out;
}

QJsonObject PhotoRepository::libraryFacets(const LibraryFilter& filter) {
    auto without = [&filter](QStringList LibraryFilter::*member) {
        LibraryFilter f = filter;
        (f.*member).clear();
        return f;
    };

    QJsonObject o;
    const bool noFacetOverrides =
        filter.kinds.isEmpty() && filter.cameras.isEmpty() && filter.bodies.isEmpty() &&
        filter.lenses.isEmpty() && filter.iso.isEmpty() && filter.aperture.isEmpty() &&
        filter.focal.isEmpty() && filter.shutter.isEmpty() && filter.takenFrom.isEmpty() &&
        filter.takenTo.isEmpty() && filter.rejected.isEmpty();

    if (noFacetOverrides) {
        struct KindBucket {
            int count = 0;
            bool isRaw = false;
        };
        struct NumericFacet {
            struct Bucket {
                int count = 0;
                bool hasNum = false;
                double minNum = 0.0;
            };
            QHash<QString, Bucket> buckets;

            void add(const QString& label, const QVariant& num) {
                if (label.isEmpty())
                    return;
                Bucket& b = buckets[label];
                ++b.count;
                if (!num.isNull()) {
                    bool ok = false;
                    const double v = num.toDouble(&ok);
                    if (ok && (!b.hasNum || v < b.minNum)) {
                        b.hasNum = true;
                        b.minNum = v;
                    }
                }
            }

            QJsonArray toJson() const {
                struct Entry {
                    QString value;
                    int count;
                    bool hasNum;
                    double minNum;
                };
                QVector<Entry> entries;
                entries.reserve(buckets.size());
                for (auto it = buckets.constBegin(); it != buckets.constEnd(); ++it)
                    entries.append({it.key(), it.value().count, it.value().hasNum, it.value().minNum});
                std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
                    if (a.hasNum != b.hasNum)
                        return !a.hasNum;
                    if (a.hasNum && a.minNum != b.minNum)
                        return a.minNum < b.minNum;
                    return a.value < b.value;
                });
                QJsonArray out;
                for (const Entry& e : std::as_const(entries))
                    out.append(QJsonObject{{QStringLiteral("value"), e.value},
                                           {QStringLiteral("count"), e.count}});
                return out;
            }
        };

        auto mapToJson = [](const QMap<QString, int>& counts, bool descending = false) {
            QJsonArray out;
            if (!descending) {
                for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
                    out.append(QJsonObject{{QStringLiteral("value"), it.key()},
                                           {QStringLiteral("count"), it.value()}});
            } else {
                auto it = counts.constEnd();
                while (it != counts.constBegin()) {
                    --it;
                    out.append(QJsonObject{{QStringLiteral("value"), it.key()},
                                           {QStringLiteral("count"), it.value()}});
                }
            }
            return out;
        };

        QVariantList binds;
        QSqlQuery q(db());
        if (run(q, QStringLiteral(
                       "SELECT lf.kind_label, lf.ext_label, lf.camera_label, lf.body_key, f.lens, "
                       "lf.iso_label, f.iso, lf.aperture_label, f.aperture, "
                       "lf.focal_label, f.focal_length, lf.shutter_label, f.shutter_speed_s, "
                       "substr(v.taken_at, 1, 7), v.rejected") +
                       QLatin1String(kLibraryFrom) + libraryWhere(filter, binds, m_hasFilesFts),
                binds)) {
            int rawCount = 0;
            QHash<QString, KindBucket> extBuckets;
            QMap<QString, int> cameras;
            QMap<QString, int> bodies;
            QMap<QString, int> lenses;
            NumericFacet iso;
            NumericFacet aperture;
            NumericFacet focal;
            NumericFacet shutter;
            QMap<QString, int> months;
            int totalRows = 0;
            int rejectedSum = 0;

            while (q.next()) {
                const QString kindLabel = q.value(0).toString();
                const QString extLabel = q.value(1).toString();
                const bool isRaw = (kindLabel == QLatin1String("RAW"));
                if (isRaw)
                    ++rawCount;
                if (!extLabel.isEmpty()) {
                    KindBucket& kb = extBuckets[extLabel];
                    ++kb.count;
                    kb.isRaw = kb.isRaw || isRaw;
                }

                const QString camera = q.value(2).toString();
                if (!camera.isEmpty())
                    ++cameras[camera];

                const QVariant bodyVar = q.value(3);
                if (!bodyVar.isNull())
                    ++bodies[bodyVar.toString()];

                const QString lens = q.value(4).toString();
                if (!lens.isEmpty())
                    ++lenses[lens];

                iso.add(q.value(5).toString(), q.value(6));
                aperture.add(q.value(7).toString(), q.value(8));
                focal.add(q.value(9).toString(), q.value(10));
                shutter.add(q.value(11).toString(), q.value(12));

                const QString month = q.value(13).toString();
                if (!month.isEmpty())
                    ++months[month];

                ++totalRows;
                rejectedSum += q.value(14).toInt();
            }

            struct KindEntry {
                QString value;
                int count;
                bool isRaw;
            };
            QVector<KindEntry> kindEntries;
            kindEntries.reserve(extBuckets.size());
            for (auto it = extBuckets.constBegin(); it != extBuckets.constEnd(); ++it)
                kindEntries.append({it.key(), it.value().count, it.value().isRaw});
            std::sort(kindEntries.begin(), kindEntries.end(), [](const KindEntry& a, const KindEntry& b) {
                if (a.isRaw != b.isRaw)
                    return a.isRaw;
                return a.value < b.value;
            });
            QJsonArray kinds;
            if (rawCount > 0)
                kinds.append(QJsonObject{{QStringLiteral("value"), QStringLiteral("RAW")},
                                         {QStringLiteral("count"), rawCount}});
            for (const KindEntry& ke : std::as_const(kindEntries))
                kinds.append(QJsonObject{{QStringLiteral("value"), ke.value},
                                         {QStringLiteral("count"), ke.count}});

            o["kinds"]    = kinds;
            o["cameras"]  = mapToJson(cameras);
            o["bodies"]   = mapToJson(bodies);
            o["lenses"]   = mapToJson(lenses);
            o["iso"]      = iso.toJson();
            o["aperture"] = aperture.toJson();
            o["focal"]    = focal.toJson();
            o["shutter"]  = shutter.toJson();
            o["months"]   = mapToJson(months, true);
            o["rejected"] = QJsonObject{{QStringLiteral("all"), totalRows},
                                        {QStringLiteral("hide"), totalRows - rejectedSum},
                                        {QStringLiteral("only"), rejectedSum}};
        }
    } else {
        // Chaque liste ignore son propre choix : choisir un boitier ne masque pas les autres.
        auto counted = [this](const LibraryFilter& f, const QString& column, const QString& order,
                              bool keepEmpty = false) {
            QVariantList binds;
            QString where = libraryWhere(f, binds, m_hasFilesFts);
            where += QStringLiteral(" AND %1 IS NOT NULL").arg(column);
            if (!keepEmpty)
                where += QStringLiteral(" AND %1 != ''").arg(column);
            QSqlQuery q(db());
            run(q, QStringLiteral("SELECT %1 AS value, COUNT(*) AS count").arg(column) +
                       QLatin1String(kLibraryFrom) + where +
                       QStringLiteral(" GROUP BY %1 ORDER BY %2").arg(column, order), binds);
            QJsonArray out;
            while (q.next())
                out.append(QJsonObject{{QStringLiteral("value"), q.value(0).toString()},
                                       {QStringLiteral("count"), q.value(1).toInt()}});
            return out;
        };

        {
            // Le groupe RAW d'abord, puis chaque extension, comme la liste du client.
            const LibraryFilter f = without(&LibraryFilter::kinds);
            QVariantList binds;
            QSqlQuery q(db());
            run(q, QStringLiteral("SELECT lf.ext_label, lf.kind_label, COUNT(*)") +
                       QLatin1String(kLibraryFrom) + libraryWhere(f, binds, m_hasFilesFts) +
                       QStringLiteral(" GROUP BY lf.ext_label, lf.kind_label "
                                      "ORDER BY lf.kind_label != 'RAW', lf.ext_label"),
                binds);
            int rawCount = 0;
            QVector<QPair<QString, int>> extList;
            QHash<QString, int> extIndex;
            while (q.next()) {
                const QString ext = q.value(0).toString();
                const QString kind = q.value(1).toString();
                const int count = q.value(2).toInt();
                if (kind == QLatin1String("RAW"))
                    rawCount += count;
                if (!ext.isEmpty()) {
                    const auto it = extIndex.constFind(ext);
                    if (it != extIndex.constEnd()) {
                        extList[*it].second += count;
                    } else {
                        extIndex.insert(ext, extList.size());
                        extList.append({ext, count});
                    }
                }
            }
            QJsonArray kinds;
            if (rawCount > 0)
                kinds.append(QJsonObject{{QStringLiteral("value"), QStringLiteral("RAW")},
                                         {QStringLiteral("count"), rawCount}});
            for (const auto& entry : std::as_const(extList))
                kinds.append(QJsonObject{{QStringLiteral("value"), entry.first},
                                         {QStringLiteral("count"), entry.second}});
            o["kinds"] = kinds;
        }
        o["cameras"]  = counted(without(&LibraryFilter::cameras), QStringLiteral("lf.camera_label"), QStringLiteral("value"));
        o["bodies"]   = counted(without(&LibraryFilter::bodies), QStringLiteral("lf.body_key"), QStringLiteral("value"), true);
        o["lenses"]   = counted(without(&LibraryFilter::lenses), QStringLiteral("f.lens"), QStringLiteral("value"));
        o["iso"]      = counted(without(&LibraryFilter::iso), QStringLiteral("lf.iso_label"), QStringLiteral("MIN(f.iso)"));
        o["aperture"] = counted(without(&LibraryFilter::aperture), QStringLiteral("lf.aperture_label"), QStringLiteral("MIN(f.aperture)"));
        o["focal"]    = counted(without(&LibraryFilter::focal), QStringLiteral("lf.focal_label"), QStringLiteral("MIN(f.focal_length)"));
        o["shutter"]  = counted(without(&LibraryFilter::shutter), QStringLiteral("lf.shutter_label"), QStringLiteral("MIN(f.shutter_speed_s)"));

        {
            LibraryFilter f = filter;
            f.takenFrom.clear();
            f.takenTo.clear();
            o["months"] = counted(f, QStringLiteral("substr(v.taken_at, 1, 7)"), QStringLiteral("value DESC"));
        }
        {
            LibraryFilter f = filter;
            f.rejected.clear();
            QVariantList binds;
            QSqlQuery q(db());
            run(q, QStringLiteral("SELECT COUNT(*), COALESCE(SUM(v.rejected), 0)") + QLatin1String(kLibraryFrom) +
                       libraryWhere(f, binds, m_hasFilesFts), binds);
            if (q.next()) {
                const int all = q.value(0).toInt();
                const int rejected = q.value(1).toInt();
                o["rejected"] = QJsonObject{{QStringLiteral("all"), all}, {QStringLiteral("hide"), all - rejected},
                                            {QStringLiteral("only"), rejected}};
            }
        }
    }

    {
        // Un mot-cle compte sa version une fois, et chaque niveau au-dessus aussi.
        const LibraryFilter f = without(&LibraryFilter::keywords);
        QVariantList binds;
        QSqlQuery q(db());
        run(q, QStringLiteral("SELECT v.id, k.keyword") + QLatin1String(kLibraryFrom) +
                   QStringLiteral(" JOIN library_keywords k ON k.version_id = v.id") +
                   libraryWhere(f, binds, m_hasFilesFts) + QStringLiteral(" ORDER BY v.id"), binds);
        QMap<QString, int> counts;
        QSet<QString> levels;
        int current = -1;
        auto flush = [&]() { for (const QString& level : levels) ++counts[level]; levels.clear(); };
        while (q.next()) {
            if (q.value(0).toInt() != current) { flush(); current = q.value(0).toInt(); }
            const QStringList parts = q.value(1).toString().split(QLatin1Char('|'));
            for (int n = 1; n <= parts.size(); ++n)
                levels.insert(parts.mid(0, n).join(QLatin1Char('|')));
        }
        flush();
        QJsonArray keywords;
        for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
            keywords.append(QJsonObject{{QStringLiteral("value"), it.key()}, {QStringLiteral("count"), it.value()}});
        o["keywords"] = keywords;
    }
    return o;
}

// --- Passes -----------------------------------------------------------------

int PhotoRepository::startRun(const QString& mode, const QString& trigger,
                              const QString& startedAt) {
    QSqlQuery q(db());
    if (!run(q, QStringLiteral(
                 "INSERT INTO index_runs (started_at, mode, trigger, state) "
                 "VALUES (?, ?, ?, 'running')"), {startedAt, mode, trigger}))
        return -1;
    return q.lastInsertId().toInt();
}

void PhotoRepository::finishRun(int runId, const QString& state, const RunCounts& counts,
                                const QString& finishedAt) {
    QSqlQuery q(db());
    run(q, QStringLiteral(
             "UPDATE index_runs SET finished_at = ?, state = ?, files_seen = ?, files_new = ?, "
             "files_updated = ?, files_missing = ?, files_unavailable = ?, errors_count = ? "
             "WHERE id = ?"),
        {finishedAt, state, counts.seen, counts.created, counts.updated, counts.missing,
         counts.unavailable, counts.errors, runId});
}

void PhotoRepository::logError(int runId, const QVariant& path, const QString& stage,
                               const QString& message, const QString& when) {
    QSqlQuery q(db());
    run(q, QStringLiteral(
             "INSERT INTO index_errors (run_id, path, stage, message, occurred_at) "
             "VALUES (?, ?, ?, ?, ?)"), {runId, path, stage, message, when});
}

// --- Lectures ---------------------------------------------------------------

QJsonObject PhotoRepository::statusCounts() {
    // /status est servi par le thread HTTP UNIQUE et sonde par morfMonitor (timeout
    // 3 s). summary() (DISTINCT, EXISTS correles) dure plus de 10 s sur une grosse base
    // pendant une indexation : /status devenait muet et l'activite en cours restait
    // invisible. Ici, uniquement les trois compteurs que /status expose.
    auto scalar = [this](const QString& sql) -> int {
        QSqlQuery q(db());
        q.exec(sql);
        return q.next() ? q.value(0).toInt() : 0;
    };
    QJsonObject o;
    o["files_present"]  = scalar(QStringLiteral("SELECT COUNT(*) FROM files WHERE state='present'"));
    o["files_missing"]  = scalar(QStringLiteral("SELECT COUNT(*) FROM files WHERE state='missing'"));
    o["folders_active"] = scalar(QStringLiteral("SELECT COUNT(*) FROM folders WHERE enabled=1"));
    return o;
}

QJsonObject PhotoRepository::summary() {
    auto scalar = [this](const QString& sql) -> int {
        QSqlQuery q(db());
        q.exec(sql);
        return q.next() ? q.value(0).toInt() : 0;
    };
    QJsonArray yearsArr = years();
    QJsonObject o;
    o["files_total"]    = scalar(QStringLiteral("SELECT COUNT(*) FROM files"));
    o["files_present"]  = scalar(QStringLiteral("SELECT COUNT(*) FROM files WHERE state='present'"));
    o["files_missing"]  = scalar(QStringLiteral("SELECT COUNT(*) FROM files WHERE state='missing'"));
    o["folders_total"]  = scalar(QStringLiteral("SELECT COUNT(*) FROM folders"));
    o["folders_active"] = scalar(QStringLiteral("SELECT COUNT(*) FROM folders WHERE enabled=1"));
    // Boîtiers / objectifs / années : dimensions ANALYTIQUES, elles respectent
    // l'exclusion d'analyse (un dossier sorti des analyses n'y compte plus). Les
    // totaux bruts de photothèque ci-dessus (total/présentes/disparues, dossiers)
    // décrivent au contraire TOUTE la base indexée : ils l'ignorent volontairement.
    o["cameras"]        = scalar(QStringLiteral("SELECT COUNT(DISTINCT camera_model) FROM files "
                                                "WHERE ") + analyzablePredicate() +
                                                QStringLiteral(" AND camera_model IS NOT NULL"));
    o["lenses"]         = scalar(QStringLiteral("SELECT COUNT(DISTINCT lens) FROM files "
                                                "WHERE ") + analyzablePredicate() +
                                                QStringLiteral(" AND lens IS NOT NULL"));
    o["years"]          = yearsArr;

    // Couverture du CONTEXTE (morfphoto-context/2), par RÉPERTOIRE de photos présentes.
    // Trois états distincts : qualified (ligne ok), invalid (ligne invalide), unqualified
    // (aucun `.morfphoto.json` valide). unqualified n'est jamais fusionné avec INCONNU,
    // qui est une valeur de `context` (donc comptée parmi les qualifiés).
    const int dirsTotal = scalar(QStringLiteral(
        "SELECT COUNT(*) FROM (SELECT DISTINCT directory FROM files WHERE state='present')"));
    const int qualified = scalar(QStringLiteral(
        "SELECT COUNT(*) FROM folder_contexts c WHERE c.status='ok' AND EXISTS "
        "(SELECT 1 FROM files f WHERE f.directory=c.directory AND f.state='present')"));
    const int invalid = scalar(QStringLiteral(
        "SELECT COUNT(*) FROM folder_contexts c WHERE c.status='invalid' AND EXISTS "
        "(SELECT 1 FROM files f WHERE f.directory=c.directory AND f.state='present')"));
    auto coverageBy = [this](const QString& column) -> QJsonObject {
        QJsonObject by;
        QSqlQuery q(db());
        q.exec(QStringLiteral(
            "SELECT c.%1 AS v, COUNT(*) AS n FROM folder_contexts c "
            "WHERE c.status='ok' AND c.%1 IS NOT NULL AND EXISTS "
            "(SELECT 1 FROM files f WHERE f.directory=c.directory AND f.state='present') "
            "GROUP BY c.%1 ORDER BY n DESC, v").arg(column));
        while (q.next())
            by.insert(q.value(0).toString(), q.value(1).toInt());
        return by;
    };
    QJsonObject contexts;
    contexts["qualified"]   = qualified;
    contexts["invalid"]     = invalid;
    contexts["unqualified"] = dirsTotal - qualified - invalid;
    contexts["by_context"]  = coverageBy(QStringLiteral("context"));
    contexts["by_subject"]  = coverageBy(QStringLiteral("subject"));
    o["contexts"] = contexts;
    return o;
}

QJsonObject PhotoRepository::listPhotos(const QVariantMap& filters, int page, int pageSize) {
    QStringList clauses;
    QVariantList binds;
    for (auto it = filters.constBegin(); it != filters.constEnd(); ++it) {
        const QString col = filterColumn(it.key());
        if (col.isEmpty() || it.value().isNull())
            continue;
        clauses << (col + QStringLiteral(" = ?"));
        binds << it.value();
    }
    const QString where = clauses.isEmpty() ? QString()
                                            : QStringLiteral(" WHERE ") + clauses.join(QStringLiteral(" AND "));

    int total = 0;
    {
        QSqlQuery q(db());
        run(q, QStringLiteral("SELECT COUNT(*) FROM files") + where, binds);
        if (q.next())
            total = q.value(0).toInt();
    }

    // Borner page et taille avant le produit : (page - 1) * pageSize en int deborde
    // (comportement indefini) pour une page enorme venue de la requete. Calcul en 64 bits.
    constexpr int kMaxPage = 1000000;
    page = qBound(1, page, kMaxPage);
    pageSize = qMax(1, pageSize);
    const qint64 offset = static_cast<qint64>(page - 1) * pageSize;
    QVariantList pageBinds = binds;
    pageBinds << pageSize << offset;
    QSqlQuery q(db());
    // Exclut raw_exif (lourd) ; la fiche complète le donne via getPhoto.
    run(q, QStringLiteral(
             "SELECT id, folder_id, path, directory, filename, extension, file_type, size, mtime, "
             "taken_at, taken_year, make, camera_model, lens, focal_length, focal_length_35mm, "
             "aperture, shutter_speed, shutter_speed_s, iso, exposure_compensation, rating, "
             "latitude, longitude, state FROM files") + where +
             QStringLiteral(" ORDER BY taken_at IS NULL, taken_at, id LIMIT ? OFFSET ?"),
        pageBinds);

    QJsonArray items;
    QStringList names;
    while (q.next()) {
        if (names.isEmpty())
            names = queryFieldNames(q);
        items.append(rowToJson(q, names));
    }

    QJsonObject o;
    o["items"]     = items;
    o["total"]     = total;
    o["page"]      = page;
    o["page_size"] = pageSize;
    return o;
}

QStringList PhotoRepository::directorySample(const QString& directory, int count) {
    if (count < 1)
        count = 1;
    QSqlQuery q(db());
    // Ordre par prise de vue puis NOM : un RAW et son JPEG (meme prise, meme instant)
    // tombent cote a cote, ce qui rend la deduplication par radical fiable.
    run(q, QStringLiteral(
             "SELECT path, filename FROM files "
             "WHERE directory = ? AND state = 'present' "
             "ORDER BY taken_at IS NULL, taken_at, filename, id"),
        {directory});

    // Une entree par PRISE : on deduplique par radical (nom sans extension), pour ne
    // pas compter deux fois le RAW et le JPEG d'une meme photo.
    QStringList paths;
    QSet<QString> seenStems;
    while (q.next()) {
        const QString path     = q.value(0).toString();
        const QString filename = q.value(1).toString();
        const int dot  = filename.lastIndexOf(QLatin1Char('.'));
        const QString stem = (dot > 0 ? filename.left(dot) : filename).toLower();
        if (seenStems.contains(stem))
            continue;
        seenStems.insert(stem);
        paths << path;
    }

    // Echantillon REPARTI sur tout le dossier, pas les N premieres : deux photos qui
    // se suivent sont souvent la meme scene (rafale, ou RAW+JPEG deja ecarte). On prend
    // des prises espacees, centrees dans leur tranche, pour un apercu representatif de
    // la journee entiere.
    const int n = paths.size();
    if (n <= count)
        return paths;
    QStringList out;
    out.reserve(count);
    for (int i = 0; i < count; ++i) {
        qint64 idx = (static_cast<qint64>(i) * n) / count + (n / count) / 2;
        if (idx >= n)
            idx = n - 1;
        out << paths.at(static_cast<int>(idx));
    }
    return out;
}

QJsonObject PhotoRepository::getPhoto(int fileId, bool* found) {
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT * FROM files WHERE id = ?"), {fileId});
    if (!q.next()) {
        if (found) *found = false;
        return {};
    }
    if (found) *found = true;
    return rowToJson(q);
}

QJsonArray PhotoRepository::distinct(const QString& column, const QString& label) {
    // `column` vient d'un appelant interne fixe, jamais d'une entrée client.
    QJsonArray arr;
    QSqlQuery q(db());
    q.exec(QStringLiteral("SELECT %1 AS %2, COUNT(*) AS count FROM files "
                          "WHERE %3 AND %1 IS NOT NULL "
                          "GROUP BY %1 ORDER BY count DESC, %2")
               .arg(column, label, analyzablePredicate()));
    QStringList names;
    while (q.next()) {
        if (names.isEmpty())
            names = queryFieldNames(q);
        arr.append(rowToJson(q, names));
    }
    return arr;
}

QJsonArray PhotoRepository::distinctCameras() { return distinct(QStringLiteral("camera_model"), QStringLiteral("camera")); }
QJsonArray PhotoRepository::distinctLenses()  { return distinct(QStringLiteral("lens"), QStringLiteral("lens")); }
QJsonArray PhotoRepository::distinctFocals()  { return distinct(QStringLiteral("focal_length"), QStringLiteral("focal_length")); }

QJsonArray PhotoRepository::years() {
    QJsonArray arr;
    QSqlQuery q(db());
    q.exec(QStringLiteral("SELECT taken_year AS year, COUNT(*) AS count FROM files "
                          "WHERE ") + analyzablePredicate() +
                          QStringLiteral(" AND taken_year IS NOT NULL "
                          "GROUP BY taken_year ORDER BY taken_year"));
    QStringList names;
    while (q.next()) {
        if (names.isEmpty())
            names = queryFieldNames(q);
        arr.append(rowToJson(q, names));
    }
    return arr;
}

QVector<QPair<qint64, QString>> PhotoRepository::thumbnailCandidates(qint64 afterId, int limit) {
    QVector<QPair<qint64, QString>> candidates;
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT f.id, f.path FROM files f JOIN folders d ON d.id = f.folder_id "
                          "WHERE f.id > ? AND f.state = 'present' AND d.enabled = 1 "
                          "AND d.deleted_at IS NULL ORDER BY f.id LIMIT ?"), {afterId, limit});
    while (q.next())
        candidates.append({q.value(0).toLongLong(), q.value(1).toString()});
    return candidates;
}

qint64 PhotoRepository::lastPhotoId() {
    QSqlQuery q(db());
    return q.exec(QStringLiteral("SELECT MAX(id) FROM files")) && q.next() ?
           q.value(0).toLongLong() : -1;
}

QJsonObject PhotoRepository::photoDataset() {
    // Dictionnaires : chaque chaine repetee (boitier, objectif, type) n'est stockee
    // qu'une fois ; les colonnes ne portent que son index. Un QHash retient l'index
    // deja attribue, un QJsonArray garde l'ordre d'apparition (l'index EST la position).
    QJsonArray camDict, lensDict, typeDict, ctxDict, subjDict;
    QHash<QString, int> camIdx, lensIdx, typeIdx, ctxIdx, subjIdx;
    auto intern = [](const QVariant& v, QJsonArray& dict, QHash<QString, int>& idx) -> QJsonValue {
        if (v.isNull())
            return QJsonValue::Null;   // valeur absente preservee (jamais un index bidon)
        const QString s = v.toString();
        auto it = idx.constFind(s);
        if (it != idx.constEnd())
            return it.value();
        const int n = dict.size();
        dict.append(s);
        idx.insert(s, n);
        return n;
    };
    // Un reel brut, ou null si la colonne est NULL (pas de 0 trompeur).
    auto num = [](const QVariant& v) -> QJsonValue {
        return v.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue::fromVariant(v);
    };

    QJsonArray takenAt, camera, lens, fileType, focal, focal35, aperture, iso, shutterS, folder;
    QJsonArray context, subject;   // contexte photographique (morfphoto-context/2)
    QJsonArray fingerprint;   // empreinte de dedup (une par photo), pour l'analyse multi-sources
    int count = 0;

    QSqlQuery q(db());
    // Un seul parcours des photos presentes ; ordre chronologique stable et utile.
    // filename et size ne sont PAS exposes : ils servent uniquement a calculer
    // l'empreinte (le dataset reste anonyme, seule l'empreinte opaque en sort).
    // Jointure GAUCHE sur folder_contexts (cle = repertoire) : context/subject sont deux
    // dimensions INDEPENDANTES, null si le dossier n'est pas qualifie. La distinction
    // null (aucun .morfphoto.json) vs "INCONNU" (valeur choisie) est ainsi preservee.
    q.exec(QStringLiteral(
        "SELECT f.taken_at, f.camera_model, f.lens, f.file_type, f.focal_length, "
        "f.focal_length_35mm, f.aperture, f.iso, f.shutter_speed_s, f.folder_id, "
        "f.filename, f.size, c.context, c.subject "
        "FROM files f LEFT JOIN folder_contexts c ON c.directory = f.directory WHERE ")
        + analyzablePredicate() +
        QStringLiteral(" ORDER BY f.taken_at IS NULL, f.taken_at, f.id"));
    while (q.next()) {
        takenAt.append(num(q.value(0)));
        camera.append(intern(q.value(1), camDict, camIdx));
        lens.append(intern(q.value(2), lensDict, lensIdx));
        fileType.append(intern(q.value(3), typeDict, typeIdx));
        focal.append(num(q.value(4)));
        focal35.append(num(q.value(5)));
        aperture.append(num(q.value(6)));
        iso.append(num(q.value(7)));
        shutterS.append(num(q.value(8)));
        folder.append(num(q.value(9)));
        fingerprint.append(fingerprintOf(q.value(10).toString(), q.value(11).toLongLong(),
                                         q.value(0).toString()));
        context.append(intern(q.value(12), ctxDict, ctxIdx));
        subject.append(intern(q.value(13), subjDict, subjIdx));
        ++count;
    }

    QJsonObject columns{
        {"taken_at", takenAt}, {"camera", camera}, {"lens", lens}, {"file_type", fileType},
        {"focal_length", focal}, {"focal_length_35mm", focal35}, {"aperture", aperture},
        {"iso", iso}, {"shutter_speed_s", shutterS}, {"folder_id", folder},
        {"context", context}, {"subject", subject},
        {"fingerprint", fingerprint},
    };
    QJsonObject dictionaries{
        {"camera", camDict}, {"lens", lensDict}, {"file_type", typeDict},
        {"context", ctxDict}, {"subject", subjDict},
    };

    // Libellés des dossiers : la colonne folder_id porte l'identifiant brut ; cette
    // table de correspondance id -> libellé permet à la couche d'analyse de filtrer
    // et d'étiqueter par dossier sans deviner un nom. Libellé = label si présent,
    // sinon le chemin. Clé en texte (JSON n'a pas de clé entière).
    QJsonObject folders;
    {
        QSqlQuery fq(db());
        fq.exec(QStringLiteral("SELECT id, COALESCE(label, path) FROM folders"));
        while (fq.next())
            folders.insert(QString::number(fq.value(0).toInt()), fq.value(1).toString());
    }

    return QJsonObject{
        {"count", count}, {"dictionaries", dictionaries}, {"columns", columns},
        {"folders", folders},
    };
}

// --- Contexte photographique par répertoire (morfphoto-context/2) -----------
//
// La table folder_contexts est une PROJECTION reconstructible des `.morfphoto.json`.
// Le fichier disque reste souverain ; la base n'est qu'un cache d'index.

void PhotoRepository::upsertContext(const FolderContext& ctx) {
    // UPSERT par répertoire (clé unique) : une passe met à jour sans dupliquer.
    const QString warnings = ctx.warnings.isEmpty()
        ? QString() : ctx.warnings.join(QLatin1Char(','));
    QSqlQuery q(db());
    run(q, QStringLiteral(
             "INSERT INTO folder_contexts "
             "(directory, schema, context, subject, motif, description, created, updated, "
             " source_mtime, status, warnings, error, indexed_at) "
             "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
             "ON CONFLICT(directory) DO UPDATE SET "
             " schema=excluded.schema, context=excluded.context, subject=excluded.subject, "
             " motif=excluded.motif, description=excluded.description, created=excluded.created, "
             " updated=excluded.updated, source_mtime=excluded.source_mtime, "
             " status=excluded.status, warnings=excluded.warnings, error=excluded.error, "
             " indexed_at=excluded.indexed_at"),
        {ctx.directory, ctx.schema, ctx.context, ctx.subject, ctx.motif, ctx.description,
         ctx.created, ctx.updated, ctx.sourceMtime, ctx.status,
         warnings.isEmpty() ? QVariant() : QVariant(warnings), ctx.error,
         QDateTime::currentDateTimeUtc().toString(Qt::ISODate)});
}

void PhotoRepository::deleteContextRow(const QString& directory) {
    QSqlQuery q(db());
    run(q, QStringLiteral("DELETE FROM folder_contexts WHERE directory = ?"), {directory});
}

QHash<QString, qint64> PhotoRepository::knownContextMtimes() {
    QHash<QString, qint64> out;
    QSqlQuery q(db());
    q.exec(QStringLiteral("SELECT directory, source_mtime FROM folder_contexts"));
    while (q.next())
        out.insert(q.value(0).toString(), q.value(1).toLongLong());
    return out;
}

bool PhotoRepository::directoryHasPhotos(const QString& directory) {
    QSqlQuery q(db());
    run(q, QStringLiteral("SELECT 1 FROM files WHERE directory = ? AND state = 'present' LIMIT 1"),
        {directory});
    return q.next();
}

QJsonObject PhotoRepository::getContext(const QString& directory) {
    QJsonObject o;
    o["directory"]   = directory;
    o["photo_count"] = 0;
    {
        QSqlQuery c(db());
        run(c, QStringLiteral("SELECT COUNT(*) FROM files WHERE directory = ? AND state='present'"),
            {directory});
        if (c.next())
            o["photo_count"] = c.value(0).toInt();
    }
    QSqlQuery q(db());
    run(q, QStringLiteral(
             "SELECT schema, context, subject, motif, description, created, updated, "
             "status, warnings, error FROM folder_contexts WHERE directory = ?"),
        {directory});
    if (!q.next()) {
        // Aucune ligne = aucun `.morfphoto.json` valide : NON QUALIFIÉ (distinct d'INCONNU).
        o["status"] = QStringLiteral("unqualified");
        return o;
    }
    // "invalid" en base reste "invalid" côté API ; sinon "qualified".
    const QString st = q.value(7).toString();
    o["status"]      = (st == QLatin1String("invalid")) ? QStringLiteral("invalid")
                                                        : QStringLiteral("qualified");
    auto sv = [](const QVariant& v) -> QJsonValue {
        return v.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(v.toString());
    };
    o["schema"]      = q.value(0).isNull() ? QJsonValue(QJsonValue::Null)
                                           : QJsonValue(q.value(0).toInt());
    o["context"]     = sv(q.value(1));
    o["subject"]     = sv(q.value(2));
    o["motif"]       = sv(q.value(3));
    o["description"] = sv(q.value(4));
    o["created"]     = sv(q.value(5));
    o["updated"]     = sv(q.value(6));
    const QString warnings = q.value(8).toString();
    QJsonArray warr;
    if (!warnings.isEmpty())
        for (const QString& w : warnings.split(QLatin1Char(','), Qt::SkipEmptyParts))
            warr.append(w);
    o["warnings"]    = warr;
    o["error"]       = sv(q.value(9));
    return o;
}

QJsonArray PhotoRepository::listContexts(const QString& statusFilter) {
    QJsonArray arr;
    QSqlQuery q(db());
    // Un répertoire par groupe (files.directory) contenant des photos PRÉSENTES, joint
    // à son contexte éventuel. date = plus ancienne prise de vue du dossier (repli sur
    // le nom du dossier plus bas). L'exclusion analytique n'entre PAS en jeu ici : la
    // qualification concerne toute la photothèque indexée.
    q.exec(QStringLiteral(
        "SELECT f.directory AS directory, COUNT(*) AS photo_count, MIN(f.taken_at) AS date, "
        "c.status, c.context, c.subject, c.motif, c.description, c.updated, c.warnings "
        "FROM files f LEFT JOIN folder_contexts c ON c.directory = f.directory "
        "WHERE f.state = 'present' "
        "GROUP BY f.directory ORDER BY date IS NULL, date, f.directory"));
    while (q.next()) {
        const QString directory = q.value(0).toString();
        const QVariant rawStatus = q.value(3);
        // Statut EXPOSÉ : aucune ligne -> unqualified ; ligne invalide -> invalid ; sinon qualified.
        QString status;
        if (rawStatus.isNull())
            status = QStringLiteral("unqualified");
        else if (rawStatus.toString() == QLatin1String("invalid"))
            status = QStringLiteral("invalid");
        else
            status = QStringLiteral("qualified");
        if (!statusFilter.isEmpty() && statusFilter != status)
            continue;

        auto sv = [](const QVariant& v) -> QJsonValue {
            return v.isNull() ? QJsonValue(QJsonValue::Null) : QJsonValue(v.toString());
        };
        QJsonObject o;
        o["directory"]   = directory;
        o["label"]       = QFileInfo(directory).fileName();
        o["photo_count"] = q.value(1).toInt();
        const QVariant date = q.value(2);
        // date lisible AAAA-MM-JJ si connue, sinon nom du dossier (souvent daté).
        o["date"] = date.isNull() ? QJsonValue(QFileInfo(directory).fileName())
                                   : QJsonValue(date.toString().left(10));
        o["status"]      = status;
        o["context"]     = sv(q.value(4));
        o["subject"]     = sv(q.value(5));
        o["motif"]       = sv(q.value(6));
        o["description"] = sv(q.value(7));
        o["updated"]     = sv(q.value(8));
        const QString warnings = q.value(9).toString();
        QJsonArray warr;
        if (!warnings.isEmpty())
            for (const QString& w : warnings.split(QLatin1Char(','), Qt::SkipEmptyParts))
                warr.append(w);
        o["warnings"]    = warr;
        arr.append(o);
    }
    return arr;
}

QJsonObject PhotoRepository::latestRun(bool* found) {
    QSqlQuery q(db());
    q.exec(QStringLiteral("SELECT * FROM index_runs ORDER BY id DESC LIMIT 1"));
    if (!q.next()) {
        if (found) *found = false;
        return {};
    }
    if (found) *found = true;
    return rowToJson(q);
}

// --- Purge (suppression DÉFINITIVE) -----------------------------------------
//
// Contrairement au retrait doux (state='deleted', réversible), la purge efface
// vraiment les lignes : aucune restauration. Réservée à un choix explicite de
// l'utilisateur (nettoyer un boîtier de test, une année en double, un CD ré-gravé).

int PhotoRepository::purgeFolder(int folderId) {
    // Ordre imposé par la clé étrangère files.folder_id -> folders.id : effacer les
    // fichiers AVANT la sélection, sinon la suppression du dossier échoue.
    QSqlQuery q1(db());
    run(q1, QStringLiteral("DELETE FROM files WHERE folder_id = ?"), {folderId});
    const int n = q1.numRowsAffected();
    QSqlQuery q2(db());
    run(q2, QStringLiteral("DELETE FROM folders WHERE id = ?"), {folderId});
    return n < 0 ? 0 : n;
}

int PhotoRepository::purgeByYear(int year) {
    // taken_year est une colonne calculée (année de prise de vue). Toutes les
    // sélections confondues : c'est une suppression par critère, pas par dossier.
    QSqlQuery q(db());
    run(q, QStringLiteral("DELETE FROM files WHERE taken_year = ?"), {year});
    const int n = q.numRowsAffected();
    return n < 0 ? 0 : n;
}

int PhotoRepository::purgeByCamera(const QString& camera) {
    QSqlQuery q(db());
    run(q, QStringLiteral("DELETE FROM files WHERE camera_model = ?"), {camera});
    const int n = q.numRowsAffected();
    return n < 0 ? 0 : n;
}

int PhotoRepository::purgeAll() {
    // Remise à zéro complète du domaine : fichiers, sélections et historique des
    // passes. L'ordre respecte les clés étrangères (enfants d'abord). La base et son
    // schéma restent en place (aucune migration à rejouer), seulement vidés.
    // Le catalogue change d'identite : un miroir qui connaissait l'ancien catalog_id
    // repart de zero au lieu de croire que les pierres tombales le couvrent. Le
    // compteur change_seq, lui, ne revient jamais en arriere.
    const Own own = beginOwn();
    if (own == Own::Failed) {
        qWarning() << "morfPhoto: transaction impossible, purgeAll abandonne";
        return 0;
    }
    QSqlQuery qc(db());
    run(qc, QStringLiteral("SELECT COUNT(*) FROM files"));
    const int n = qc.next() ? qc.value(0).toInt() : 0;
    QSqlQuery q1(db()); run(q1, QStringLiteral("DELETE FROM index_errors"));
    QSqlQuery q2(db()); run(q2, QStringLiteral("DELETE FROM files"));
    QSqlQuery q2b(db()); run(q2b, QStringLiteral("DELETE FROM deleted_files"));
    QSqlQuery q3(db()); run(q3, QStringLiteral("DELETE FROM index_runs"));
    QSqlQuery q4(db()); run(q4, QStringLiteral("DELETE FROM folders"));
    QSqlQuery q5(db());
    const bool ok = run(q5, QStringLiteral(
        "UPDATE meta SET value = lower(hex(randomblob(8))) WHERE key = 'catalog_id'"));
    endOwn(own, ok);
    return n;
}

} // namespace morfphoto
