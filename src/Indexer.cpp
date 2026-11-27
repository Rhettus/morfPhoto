/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/Indexer.h"
#include "morfphoto/PhotoRepository.h"
#include "morfphoto/ExifExtractor.h"
#include "morfphoto/PhotoScanner.h"
#include "morfphoto/ContextFile.h"
#include "morfphoto/LibraryMetadata.h"

#include <QDateTime>
#include <QSet>
#include <QDir>
#include <QFileInfo>
#include <QImageReader>
#include <QFile>
#include <QMutexLocker>

#include <chrono>
#include <utility>

namespace morfphoto {

namespace {
// Horodatage UTC lisible pour la comptabilité d'indexation.
QString nowIso() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
}

// Garde-fou : un fichier .xmp demesure n'est pas un sidecar.
constexpr qint64 kMaxSidecarBytes = 64 * 1024 * 1024;
} // namespace

Indexer::Indexer(PhotoRepository* repo, ExifExtractor* extractor, QStringList roots,
                 int probeTimeoutMs)
    : m_repo(repo), m_extractor(extractor), m_roots(std::move(roots)),
      m_normalizedRoots(normalizeRoots(m_roots)),
      m_probeTimeoutMs(probeTimeoutMs) {}

int Indexer::run(IndexMode mode, const QVector<int>& folderIds, const QString& trigger) {
    // Verrou non bloquant : refuser tout de suite plutôt que d'empiler des passes.
    if (!m_runMutex.tryLock())
        return -1;

    {
        QMutexLocker lock(&m_stateMutex);
        m_indexing = true;
        m_startedAt = nowIso();
    }

    // Dénominateur initial : dernière passe, si elle a vu des fichiers. Ça donne
    // un pourcentage dès la première photo, sans re-parcourir l'arbre. Le total
    // s'ajuste ensuite (il grandit, ou il se recale quand tous les dossiers sont
    // listés). startRun() viendrait après : latestRun() serait alors CETTE passe vide.
    bool hadPrev = false;
    const QJsonObject prevRun = m_repo->latestRun(&hadPrev);
    const qint64 estimate = (hadPrev)
        ? qint64(prevRun.value(QStringLiteral("files_seen")).toDouble())
        : 0;

    const int runId = m_repo->startRun(indexModeName(mode), trigger, nowIso());
    RunCounts counts;

    // mtimes de contexte connus, chargés une fois : la découverte ne relit un
    // `.morfphoto.json` que s'il a changé, et sait quelles lignes retirer.
    m_ctxMtimes = m_repo->knownContextMtimes();

    QVector<FolderRow> folders = m_repo->activeFolders();
    if (!folderIds.isEmpty()) {
        const QSet<int> wanted(folderIds.begin(), folderIds.end());
        QVector<FolderRow> kept;
        for (const FolderRow& f : folders)
            if (wanted.contains(f.id))
                kept.push_back(f);
        folders = kept;
    }

    // Racines constatées indisponibles pendant CETTE passe : une fois une racine KO,
    // ses autres sélections sont sautées sans re-sonder (ne pas s'acharner sur une
    // source muette : un timeout par racine, pas un par dossier).
    // Pas de parcours de comptage : l'EXIF (ou le touch) commence avec le premier
    // dossier. Un walk à vide doublerait l'I/O disque/SMB pour un pourcentage.
    initProgress(folders.size(), (estimate > 0) ? estimate : -1);

    QSet<QString> unavailableRoots;

    bool interrupted = false;
    for (const FolderRow& folder : folders) {
        if (isCancelled()) {
            interrupted = true;
            break;
        }
        m_pCurrentFolder = folder.path;
        reportProgress(counts.seen);            // dossier entamé
        if (reconcileFolder(folder, mode, runId, counts, unavailableRoots))
            interrupted = true;
        ++m_pFoldersDone;
        if (m_pFoldersDone >= m_pFoldersTotal) {
            // Tous les dossiers ont été listés (ou sautés) : le total ne bougera plus.
            m_pFilesTotal = m_pFilesDiscovered;
            m_pFilesTotalFinal = true;
        }
        reportProgress(counts.seen);            // dossier terminé
    }

    finishPass(runId, interrupted, counts);
    return runId;
}

int Indexer::runScopes(IndexMode mode, const QVector<IndexScope>& scopes, const QString& trigger) {
    if (!m_runMutex.tryLock())
        return -1;

    {
        QMutexLocker lock(&m_stateMutex);
        m_indexing = true;
        m_startedAt = nowIso();
    }

    const int runId = m_repo->startRun(indexModeName(mode), trigger, nowIso());
    RunCounts counts;
    m_ctxMtimes = m_repo->knownContextMtimes();

    QHash<int, FolderRow> activeById;
    for (const FolderRow& f : m_repo->activeFolders())
        activeById.insert(f.id, f);

    QVector<IndexScope> resolved;
    for (IndexScope scope : scopes) {
        const auto it = activeById.constFind(scope.folderId);
        if (it == activeById.constEnd())
            continue;
        const FolderRow& folder = it.value();
        const QString cleanFolderPath = QDir::cleanPath(folder.path);
        if (scope.path.isEmpty()) {
            scope.path = cleanFolderPath;
            scope.recursive = folder.recursive;
        } else {
            scope.path = QDir::cleanPath(scope.path);
            if (!folder.recursive) {
                if (scope.path != cleanFolderPath)
                    continue;
                scope.recursive = false;
            } else if (scope.path != cleanFolderPath && !isSubpathOf(scope.path, cleanFolderPath)) {
                continue;
            }
        }
        mergeScope(resolved, std::move(scope));
    }

    initProgress(resolved.size(), -1);

    QSet<QString> unavailableRoots;

    bool interrupted = false;
    for (const IndexScope& scope : resolved) {
        if (isCancelled()) {
            interrupted = true;
            break;
        }
        const FolderRow& folder = activeById.value(scope.folderId);
        const QString cleanFolderPath = QDir::cleanPath(folder.path);
        const bool isFullFolder = (scope.path == cleanFolderPath && scope.recursive == folder.recursive);
        m_pCurrentFolder = scope.path;
        reportProgress(counts.seen);
        if (reconcileScope(folder, scope.path, scope.recursive, isFullFolder,
                           mode, runId, counts, unavailableRoots))
            interrupted = true;
        ++m_pFoldersDone;
        if (m_pFoldersDone >= m_pFoldersTotal) {
            m_pFilesTotal = m_pFilesDiscovered;
            m_pFilesTotalFinal = true;
        }
        reportProgress(counts.seen);
    }

    finishPass(runId, interrupted, counts);
    return runId;
}

void Indexer::initProgress(int foldersTotal, qint64 initialFilesTotal) {
    m_pFoldersTotal    = foldersTotal;
    m_pFoldersDone     = 0;
    m_pCurrentFolder.clear();
    m_pFilesDiscovered = 0;
    m_pFilesTotalFinal = false;
    m_pPhase           = QStringLiteral("indexing");
    m_pFilesTotal      = initialFilesTotal;
    reportProgress(0);
    if (m_pFoldersTotal == 0) {
        m_pFilesTotal = 0;
        m_pFilesTotalFinal = true;
        reportProgress(0);
    }
}

void Indexer::finishPass(int runId, bool interrupted, const RunCounts& counts) {
    // Une passe qui a perdu au moins une source n'est PAS une passe normale : le
    // dire pour que /status distingue « terminée » de « interrompue ».
    const QString finalState = interrupted ? QStringLiteral("interrupted")
                                           : QStringLiteral("done");
    m_repo->finishRun(runId, finalState, counts, nowIso());

    {
        QMutexLocker lock(&m_stateMutex);
        m_indexing = false;
        m_lastError.clear();
    }
    m_runMutex.unlock();
}

bool Indexer::reconcileFolder(const FolderRow& folder, IndexMode mode, int runId,
                              RunCounts& counts, QSet<QString>& unavailableRoots) {
    return reconcileScope(folder, QDir::cleanPath(folder.path), folder.recursive,
                          /*isFullFolder=*/true, mode, runId, counts, unavailableRoots);
}

bool Indexer::reconcileScope(const FolderRow& folder, const QString& scopePath, bool scopeRecursive,
                             bool isFullFolder, IndexMode mode, int runId,
                             RunCounts& counts, QSet<QString>& unavailableRoots) {
    const QString cleanFolderPath = QDir::cleanPath(folder.path);
    const QString cleanScopePath  = QDir::cleanPath(scopePath);

    // Garde-fou : la sélection doit rester sous sa propre racine autorisée.
    if (!isWithinRoots(folder.path, {folder.rootPath})) {
        m_repo->logError(runId, folder.path, QStringLiteral("scan"),
                         QStringLiteral("selection hors de sa racine autorisee, ignoree"),
                         nowIso());
        ++counts.errors;
        return false;
    }
    if (!isFullFolder) {
        const bool lexicalOk = (cleanScopePath == cleanFolderPath)
                            || isSubpathOf(cleanScopePath, cleanFolderPath);
        if (!lexicalOk || (QFileInfo::exists(cleanScopePath)
                           && !isWithinRoots(cleanScopePath, {folder.rootPath}))) {
            m_repo->logError(runId, cleanScopePath, QStringLiteral("scan"),
                             QStringLiteral("portee hors de sa racine autorisee, ignoree"),
                             nowIso());
            ++counts.errors;
            return false;
        }
    }

    // Racine déjà déclarée indisponible plus tôt dans la passe : sauter tout de
    // suite, sans nouvelle sonde (ne pas re-solliciter une source muette).
    if (unavailableRoots.contains(folder.rootPath)) {
        ++counts.unavailable;
        return true;
    }

    // Sonde AVANT le scan : une racine réseau valide au dernier passage a pu
    // disparaître entre-temps. Indisponible => on ne touche à RIEN (surtout pas de
    // markMissing : une source absente n'est pas une suppression de fichiers).
    if (!probeAccessible(folder.rootPath, m_probeTimeoutMs)) {
        unavailableRoots.insert(folder.rootPath);
        m_repo->logError(runId, folder.rootPath, QStringLiteral("availability"),
                         QStringLiteral("racine indisponible au demarrage du scan "
                                        "(source injoignable), selection ignoree"),
                         nowIso());
        ++counts.unavailable;
        return true;
    }

    const KnownFiles known = isFullFolder
        ? m_repo->existingFilesInFolder(folder.id)
        : m_repo->existingFilesInScope(folder.id, cleanScopePath, scopeRecursive);
    const QHash<int, QString> fingerprints = m_library
        ? (isFullFolder
               ? m_repo->libraryFingerprints(folder.id)
               : m_repo->libraryFingerprintsInScope(folder.id, cleanScopePath, scopeRecursive))
        : QHash<int, QString>();
    QSet<QString> seen;
    QSet<QString> dirs;   // répertoires distincts vus, pour la découverte de contexte

    // Scan interruptible : la closure re-sonde la racine périodiquement. Si la
    // source meurt en plein parcours, le scan s'arrête et signale l'incomplétude.
    // Si une sous-portée n'existe plus sur disque alors que la racine répond, le
    // sous-répertoire a été supprimé ou déplacé hors portée : scan vide complet.
    ScanResult scan;
    if (!isFullFolder && !QFileInfo(cleanScopePath).exists()) {
        scan.completed = true;
    } else {
        scan = scanFolder(
            cleanScopePath, scopeRecursive,
            [this, &folder, lastProbe = std::chrono::steady_clock::now()]() mutable {
                if (isCancelled())
                    return false;
                const auto now = std::chrono::steady_clock::now();
                if (now - lastProbe < std::chrono::milliseconds(2000))
                    return true;
                lastProbe = now;
                return probeAccessible(folder.rootPath, m_probeTimeoutMs);
            },
            m_library);
    }

    if (isCancelled())
        return true;

    // Défense en profondeur : filtrer une seule fois hors des racines globales.
    // Cache canonique par répertoire pour les fichiers réguliers ; les liens
    // symboliques sont vérifiés individuellement.
    QVector<const FileInfo*> allowedFiles;
    allowedFiles.reserve(scan.files.size());
    QHash<QString, bool> dirAllowed;
    for (const FileInfo& info : scan.files) {
        bool allowed = false;
        if (info.isSymLink) {
            allowed = isPathWithinNormalizedRoots(normalizePath(info.path), m_normalizedRoots);
        } else {
            auto dirIt = dirAllowed.constFind(info.directory);
            if (dirIt == dirAllowed.constEnd()) {
                allowed = isPathWithinNormalizedRoots(normalizePath(info.directory), m_normalizedRoots);
                dirAllowed.insert(info.directory, allowed);
            } else {
                allowed = dirIt.value();
            }
        }
        if (allowed)
            allowedFiles.push_back(&info);
    }

    // Total « connu pour l'instant » = fichiers déjà listés. Ça grandit dossier
    // après dossier ; le pourcentage se recalcule sans second parcours.
    m_pFilesDiscovered += allowedFiles.size();
    if (m_pFilesTotal < 0 || m_pFilesDiscovered > m_pFilesTotal)
        m_pFilesTotal = m_pFilesDiscovered;
    reportProgress(counts.seen);

    enum class ChunkAction {
        Insert,
        Update,
        SidecarOnly,
        TouchOnly
    };
    struct ChunkItem {
        const FileInfo* info = nullptr;
        ChunkAction     action = ChunkAction::TouchOnly;
        int             knownId = 0;
        QString         knownState;
        bool            needsExif = false;
        ExifData        exif;
        bool            exifOk = false;
        QString         exifError;
    };

    constexpr qsizetype kChunkSize = 64;
    QVector<int> touchedIds;
    for (qsizetype chunkStart = 0; chunkStart < allowedFiles.size(); chunkStart += kChunkSize) {
        if (isCancelled())
            return true;
        const qsizetype chunkEnd = qMin(chunkStart + kChunkSize, allowedFiles.size());
        QVector<ChunkItem> chunk;
        chunk.reserve(chunkEnd - chunkStart);
        QStringList batchPaths;
        bool hasDbWork = false;

        for (qsizetype i = chunkStart; i < chunkEnd; ++i) {
            const FileInfo& info = *allowedFiles.at(i);
            ChunkItem item;
            item.info = &info;

            const auto it = known.constFind(info.path);
            if (it == known.constEnd()) {
                item.action = ChunkAction::Insert;
                item.needsExif = true;
            } else if (mode == IndexMode::Full || it->size != info.size || it->mtime != info.mtime) {
                item.action = ChunkAction::Update;
                item.knownId = it->id;
                item.knownState = it->state;
                item.needsExif = true;
            } else {
                item.knownId = it->id;
                item.knownState = it->state;
                if (m_library) {
                    const auto fp = fingerprints.constFind(it->id);
                    if (fp == fingerprints.constEnd() || fp->isEmpty()) {
                        // Activation de la bibliothèque ou migration des métadonnées d'origine.
                        item.action = ChunkAction::Update;
                        item.needsExif = true;
                    } else if (*fp != info.sidecarFingerprint) {
                        // Seul le sidecar a change : inutile de relire l'image.
                        item.action = ChunkAction::SidecarOnly;
                    }
                }
            }

            if (item.action != ChunkAction::TouchOnly)
                hasDbWork = true;
            if (item.needsExif && m_extractor && m_exifWorkers > 1)
                batchPaths.append(info.path);
            chunk.push_back(std::move(item));
        }

        // Extraire l'EXIF AVANT d'ouvrir la transaction SQLite (jamais de verrou
        // d'ecriture tenu pendant qu'ExifTool tourne).
        QHash<QString, QPair<ExifData, QString>> exifBatch;
        if (m_extractor && m_exifWorkers > 1 && !batchPaths.isEmpty())
            exifBatch = m_extractor->extractBatch(batchPaths, m_exifWorkers);

        for (ChunkItem& item : chunk) {
            ++counts.seen;
            seen.insert(item.info->path);
            dirs.insert(item.info->directory);

            if (item.needsExif && m_extractor) {
                if (auto cached = exifBatch.find(item.info->path); cached != exifBatch.end()) {
                    item.exif = std::move(cached->first);
                    item.exifError = std::move(cached->second);
                    exifBatch.erase(cached);
                } else {
                    if (isCancelled())
                        return true;
                    item.exif = m_extractor->extract(item.info->path, &item.exifError);
                }
                item.exifOk = item.exif.ok;
            }

            if (item.needsExif && m_library) {
                const bool raw = item.info->fileType == QLatin1String("raw");
                QSize size;
                if (!raw) {
                    QImageReader reader(item.info->path);
                    size = reader.size();
                }
                if (size.isEmpty())
                    size = ExifExtractor::originalSize(item.exif.raw, raw);
                if (!size.isEmpty()) {
                    item.exif.originalWidth = size.width();
                    item.exif.originalHeight = size.height();
                }
            }

            if (item.action != ChunkAction::Insert && item.action != ChunkAction::Update
                && item.knownState != QLatin1String("present")) {
                touchedIds.push_back(item.knownId);
            }

            // Un gros dossier ne doit pas figer la barre : rafraîchir assez souvent
            // pour qu'un corpus déséquilibré (10 / 5000 / 20) avance au fichier.
            if (counts.seen % 25 == 0)
                reportProgress(counts.seen);
        }

        if (hasDbWork) {
            const QString ts = nowIso();
            const bool inTx = m_repo->beginTransaction();
            for (const ChunkItem& item : chunk) {
                const FileInfo& info = *item.info;
                if (item.action == ChunkAction::Insert || item.action == ChunkAction::Update) {
                    if (m_extractor && !item.exifOk) {
                        // Une erreur d'extraction est journalisée et la passe continue.
                        m_repo->logError(runId, info.path, QStringLiteral("exif"),
                                         item.exifError, ts);
                        ++counts.errors;
                    }
                    if (item.action == ChunkAction::Insert) {
                        const int fileId = m_repo->insertFile(folder.id, info, item.exif,
                                                              item.exifOk, ts);
                        if (m_library && fileId > 0)
                            applyLibrary(fileId, info, &item.exif, runId, counts);
                        ++counts.created;
                    } else {
                        m_repo->updateFile(item.knownId, info, item.exif, item.exifOk, ts);
                        if (m_library)
                            applyLibrary(item.knownId, info, &item.exif, runId, counts);
                        ++counts.updated;
                    }
                } else if (item.action == ChunkAction::SidecarOnly) {
                    applyLibrary(item.knownId, info, nullptr, runId, counts);
                    ++counts.updated;
                }
            }
            if (inTx)
                m_repo->commitTransaction();
        }
    }
    if (isCancelled())
        return true;
    if (!touchedIds.isEmpty())
        m_repo->touchSeen(touchedIds, nowIso());

    if (isCancelled())
        return true;
    // Point crucial : le verdict de disparition n'est FIABLE que si la racine a été
    // parcourue entièrement ET qu'elle répond toujours à la fin. Un scan incomplet
    // (source perdue en cours) ne sert jamais de référence : les fichiers déjà vus
    // restent acquis, aucun n'est marqué disparu, la passe est interrompue.
    if (!scan.completed || !probeAccessible(folder.rootPath, m_probeTimeoutMs)) {
        unavailableRoots.insert(folder.rootPath);
        m_repo->logError(runId, folder.rootPath, QStringLiteral("availability"),
                         QStringLiteral("racine devenue indisponible pendant le scan : "
                                        "reconciliation partielle, aucun fichier marque "
                                        "disparu"),
                         nowIso());
        ++counts.unavailable;
        return true;
    }

    // Ici seulement : disque présent ET scan complet. Rafraîchir le CONTEXTE des
    // répertoires vus est alors sûr (on ne supprimera pas un contexte parce qu'une
    // source était momentanément muette). Vaut aussi pour un support amovible présent.
    dirs.insert(cleanScopePath);
    for (auto it = m_ctxMtimes.constBegin(); it != m_ctxMtimes.constEnd(); ++it) {
        const QString& dir = it.key();
        if (dir == cleanScopePath || (scopeRecursive && isSubpathOf(dir, cleanScopePath)))
            dirs.insert(dir);
    }
    refreshContexts(dirs, runId, counts);

    // Support amovible (CD/DVD, disque d'archive) : l'absence est NORMALE. Même un
    // scan mené jusqu'au bout ne vaut jamais suppression ici - un disque éjecté (ou
    // remplacé par un autre) monté sur un point resté présent mais vide renverrait
    // sinon « 0 fichier vu » et ferait marquer disparue toute l'archive, qui
    // sortirait alors de morfAnalytics. On ne marque donc JAMAIS disparu un fichier
    // d'un dossier amovible : ses photos restent acquises, support présent ou non
    // (seul un retrait volontaire les sort de l'analyse). Les neufs/modifiés ont déjà
    // été pris en compte plus haut quand le support est là.
    if (!folder.removable) {
        // Disparus : connus, non revus, encore marqués présents. Sûr ici : scan complet.
        QVector<int> missingIds;
        for (auto it = known.constBegin(); it != known.constEnd(); ++it)
            if (!seen.contains(it.key()) && it->state != QLatin1String("missing"))
                missingIds.push_back(it->id);
        if (!missingIds.isEmpty()) {
            m_repo->markMissing(missingIds, nowIso());
            counts.missing += missingIds.size();
        }
    }

    if (isFullFolder)
        m_repo->setFolderScanned(folder.id, nowIso());
    return false;
}

void Indexer::applyLibrary(int fileId, const FileInfo& info, const ExifData* knownExif,
                           int runId, RunCounts& counts) {
    ExifData loadedBase;
    const ExifData& base = knownExif ? *knownExif : (loadedBase = m_repo->libraryBase(fileId));
    QVector<LibraryVersion> versions;
    for (const SidecarRef& ref : info.sidecars) {
        // `photo_01` et `photo_001` designent la meme version : garder la premiere.
        if (!versions.isEmpty() && versions.last().version == ref.version)
            continue;
        SidecarData data;
        QFile file(ref.path);
        if (file.size() <= kMaxSidecarBytes && file.open(QIODevice::ReadOnly))
            data = parseSidecar(file.readAll());
        if (data.ok) {
            versions << mergeVersion(ref.version, ref.path, &data, base);
        } else {
            // Un sidecar illisible ne bloque jamais la passe, mais son etat reste inconnu.
            m_repo->logError(runId, ref.path, QStringLiteral("xmp"),
                             QStringLiteral("sidecar illisible"), nowIso());
            ++counts.errors;
            LibraryVersion version = mergeVersion(ref.version, QString(), nullptr, base);
            version.edited = QVariant();
            versions << version;
        }
    }
    if (versions.isEmpty())
        versions << mergeVersion(0, QString(), nullptr, base);
    for (LibraryVersion& version : versions)
        version.copy = version.version != versions.first().version;
    m_repo->storeLibrary(fileId, info.sidecarFingerprint, fileLabels(info.filename, base), versions);
}

void Indexer::refreshContexts(const QSet<QString>& directories, int runId, RunCounts& counts) {
    bool inTx = false;
    auto ensureTx = [&]() {
        if (!inTx)
            inTx = m_repo->beginTransaction();
    };

    for (const QString& dir : directories) {
        const QString path = QDir(dir).filePath(ContextFile::fileName());
        const QFileInfo fi(path);

        if (!fi.exists()) {
            // `.morfphoto.json` retiré depuis la dernière fois : effacer la projection.
            // (S'il n'a jamais existé, il n'y a pas de ligne : rien à faire.)
            if (m_ctxMtimes.contains(dir)) {
                ensureTx();
                m_repo->deleteContextRow(dir);
                m_ctxMtimes.remove(dir);
            }
            continue;
        }

        const qint64 mtime = fi.lastModified().toSecsSinceEpoch();
        if (m_ctxMtimes.value(dir, -1) == mtime)
            continue;   // inchangé depuis la dernière lecture : idempotent

        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            ensureTx();
            m_repo->logError(runId, path, QStringLiteral("context"),
                             QStringLiteral("lecture impossible: %1").arg(f.errorString()),
                             nowIso());
            ++counts.errors;
            continue;
        }
        const QByteArray bytes = f.readAll();
        f.close();

        FolderContext fc = ContextFile::parse(bytes);
        fc.directory   = dir;
        fc.sourceMtime = mtime;
        ensureTx();
        m_repo->upsertContext(fc);
        m_ctxMtimes[dir] = mtime;

        // Diagnostics : un JSON invalide ou un avertissement est journalisé sans jamais
        // interrompre la passe (un défaut sémantique ne casse pas l'analyse technique).
        if (fc.status == QLatin1String("invalid")) {
            m_repo->logError(runId, path, QStringLiteral("context"),
                             fc.error.toString(), nowIso());
            ++counts.errors;
        } else if (!fc.warnings.isEmpty()) {
            m_repo->logError(runId, path, QStringLiteral("context"),
                             QStringLiteral("avertissements: %1").arg(fc.warnings.join(QLatin1Char(','))),
                             nowIso());
        }
    }

    if (inTx)
        m_repo->commitTransaction();
}

void Indexer::reportProgress(qint64 filesSeen) const {
    if (!m_progress)
        return;
    IndexProgress p;
    p.phase         = m_pPhase;
    p.foldersDone   = m_pFoldersDone;
    p.foldersTotal  = m_pFoldersTotal;
    p.filesSeen     = filesSeen;
    p.filesTotal    = m_pFilesTotal;
    p.filesTotalFinal = m_pFilesTotalFinal;
    p.currentFolder = m_pCurrentFolder;
    m_progress(p);
}

QJsonObject Indexer::state() const {
    QMutexLocker lock(&m_stateMutex);
    QJsonObject o;
    o["state"]      = m_indexing ? QStringLiteral("indexing") : QStringLiteral("idle");
    o["started_at"] = m_indexing ? QJsonValue(m_startedAt) : QJsonValue(QJsonValue::Null);
    o["last_error"] = m_lastError.isEmpty() ? QJsonValue(QJsonValue::Null)
                                            : QJsonValue(m_lastError);
    return o;
}

} // namespace morfphoto
