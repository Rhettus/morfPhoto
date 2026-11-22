/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/PhotoModule.h"
#include "morfphoto/PhotoRepository.h"
#include "morfphoto/ExifExtractor.h"
#include "morfphoto/PhotoScanner.h"
#include "morfphoto/ContextFile.h"
#include "morfphoto/FolderWatcher.h"
#include "morfphoto/Paths.h"

#include <QThread>
#include <QThreadStorage>
#include <QTimer>
#include <QtConcurrent>
#include <QDateTime>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMutexLocker>
#include <QWaitCondition>
#include <QHostInfo>
#include <QFile>
#include <QImageReader>
#include <QImageWriter>
#include <QBuffer>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QProcess>
#include <QCryptographicHash>
#include <QLockFile>
#include <QSaveFile>
#include <QStorageInfo>
#include <QUrl>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QLoggingCategory>

#include <future>
#include <mutex>
#include <utility>
#include <vector>

namespace morfphoto {

namespace {
QString nowIso() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODate); }
constexpr qint64 kMinThumbnailFreeBytes = 512 * 1024 * 1024;

constexpr int kThumbnailEdge = 400;
constexpr qint64 kMaxThumbnailJpegBytes = 1024 * 1024;
constexpr auto kThumbnailCacheVersion = "grid-400-v1";
constexpr auto kJpegThumbnailCacheVersion = "grid-400-jpeg-v2";

QImage readGridImage(QImageReader& reader) {
    const QSize size = reader.size();
    if (size.isEmpty())
        return {};
    if (qMax(size.width(), size.height()) > kThumbnailEdge)
        reader.setScaledSize(size.scaled(kThumbnailEdge, kThumbnailEdge, Qt::KeepAspectRatio)
                                 .expandedTo(QSize(1, 1)));
    reader.setAutoTransform(true);
    const QImage image = reader.read();
    return qMax(image.width(), image.height()) <= kThumbnailEdge ? image : QImage{};
}

QByteArray encodeGridImage(const QImage& image) {
    if (image.isNull())
        return {};
    QByteArray jpeg;
    QBuffer output(&jpeg);
    output.open(QIODevice::WriteOnly);
    QImageWriter writer(&output, "jpeg");
    writer.setQuality(85);
    return writer.write(image) ? jpeg : QByteArray();
}

QByteArray gridThumbnail(QByteArray source, int* thumbnailEdge) {
    QBuffer input(&source);
    input.open(QIODevice::ReadOnly);
    QImageReader reader(&input, "jpeg");
    const QSize original = reader.size();
    const QImage image = readGridImage(reader);
    if (image.isNull())
        return {};
    *thumbnailEdge = qMax(image.width(), image.height());
    if (qMax(original.width(), original.height()) <= kThumbnailEdge && source.size() <= kMaxThumbnailJpegBytes)
        return source;
    return encodeGridImage(image);
}

// Retrouve le détail d'une sélection par son id dans une liste déjà chargée.
QJsonObject findById(const QJsonArray& folders, int id) {
    for (const QJsonValue& v : folders) {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("id")).toInt() == id)
            return o;
    }
    return {};
}

std::atomic<quint64> s_moduleInstanceCounter{0};

void appendFilterField(QString& out, const QString& value) {
    out += QString::number(value.size()) + QLatin1Char(':') + value + QLatin1Char('|');
}

void appendFilterList(QString& out, const QStringList& list) {
    out += QString::number(list.size()) + QLatin1Char('[');
    for (const QString& item : list)
        appendFilterField(out, item);
    out += QLatin1Char(']');
}

QString serializeLibraryFilter(const LibraryFilter& f) {
    QString out;
    out.reserve(128);
    out += QStringLiteral("F:");
    out += QString::number(f.minRating) + QLatin1Char('|');
    appendFilterField(out, f.rejected);
    appendFilterField(out, f.edited);
    out += QString::number(f.labels) + QLatin1Char('|');
    out += f.unlabeled ? QStringLiteral("1|") : QStringLiteral("0|");
    appendFilterList(out, f.kinds);
    appendFilterList(out, f.cameras);
    appendFilterList(out, f.bodies);
    appendFilterList(out, f.lenses);
    appendFilterList(out, f.keywords);
    appendFilterList(out, f.iso);
    appendFilterList(out, f.aperture);
    appendFilterList(out, f.focal);
    appendFilterList(out, f.shutter);
    appendFilterField(out, f.takenFrom);
    appendFilterField(out, f.takenTo);
    appendFilterField(out, f.folderPath);
    out += f.recursive ? QStringLiteral("1|") : QStringLiteral("0|");
    appendFilterField(out, f.filename);
    return out;
}

// ExifTool -stay_open process pinned to its own QThread so QProcess never
// crosses thread boundaries across QtConcurrent/HttpServer workers.
class PersistentExifProcess {
public:
    explicit PersistentExifProcess(QString binary)
        : m_binary(std::move(binary)) {}

    ~PersistentExifProcess() {
        shutdown();
    }

    bool start() {
        QMutexLocker lock(&m_mutex);
        if (m_thread)
            return m_running;
        m_shutdown = false;
        m_thread = QThread::create([this]() { runLoop(); });
        m_thread->start();
        while (!m_started && !m_shutdown)
            m_doneCond.wait(&m_mutex);
        return m_running;
    }

    QByteArray extract(const QString& tag, const QString& path, int timeoutMs, bool* processOk) {
        if (processOk)
            *processOk = false;
        if (path.contains(QLatin1Char('\n')) || path.contains(QLatin1Char('\r')))
            return {};
        QMutexLocker lock(&m_mutex);
        if (!m_thread || !m_running || m_shutdown)
            return {};
        m_reqTag = tag;
        m_reqPath = path;
        m_reqTimeoutMs = timeoutMs;
        m_respBytes.clear();
        m_respProcessOk = false;
        m_hasRequest = true;
        m_reqDone = false;
        m_reqCond.wakeOne();
        while (!m_reqDone)
            m_doneCond.wait(&m_mutex);
        if (processOk)
            *processOk = m_respProcessOk;
        return std::move(m_respBytes);
    }

    void shutdown() {
        QThread* t = nullptr;
        {
            QMutexLocker lock(&m_mutex);
            m_shutdown = true;
            m_reqCond.wakeOne();
            t = m_thread;
        }
        if (t) {
            t->wait();
            delete t;
            QMutexLocker lock(&m_mutex);
            m_thread = nullptr;
            m_running = false;
        }
    }

private:
    void runLoop() {
        QProcess proc;
        proc.setProcessChannelMode(QProcess::SeparateChannels);
        proc.start(m_binary, {QStringLiteral("-stay_open"), QStringLiteral("True"),
                              QStringLiteral("-@"), QStringLiteral("-")});
        const bool ok = proc.waitForStarted(5000);
        {
            QMutexLocker lock(&m_mutex);
            m_running = ok;
            m_started = true;
            m_doneCond.wakeAll();
        }
        if (!ok)
            return;

        quint64 counter = 0;
        while (true) {
            QString tag;
            QString path;
            int timeoutMs = 8000;
            {
                QMutexLocker lock(&m_mutex);
                while (!m_hasRequest && !m_shutdown)
                    m_reqCond.wait(&m_mutex);
                if (m_shutdown)
                    break;
                tag = std::move(m_reqTag);
                path = std::move(m_reqPath);
                timeoutMs = m_reqTimeoutMs;
                m_hasRequest = false;
            }

            bool procHealthy = false;
            QByteArray result = executeOne(proc, ++counter, tag, path, timeoutMs, &procHealthy);

            {
                QMutexLocker lock(&m_mutex);
                m_respBytes = std::move(result);
                m_respProcessOk = procHealthy;
                if (!procHealthy)
                    m_running = false;
                m_reqDone = true;
                m_doneCond.wakeAll();
            }
            if (!procHealthy)
                break;
        }

        if (proc.state() == QProcess::Running) {
            proc.write("-stay_open\nFalse\n");
            proc.waitForBytesWritten(3000);
            if (!proc.waitForFinished(3000)) {
                proc.kill();
                proc.waitForFinished(1000);
            }
        }
    }

    static QByteArray executeOne(QProcess& proc, quint64 seq, const QString& tag,
                                 const QString& path, int timeoutMs, bool* procHealthy) {
        *procHealthy = false;
        if (proc.state() != QProcess::Running)
            return {};

        const QByteArray marker = "{ready" + QByteArray::number(seq) + "}";
        QByteArray payload;
        payload += "-json\n-b\n";
        payload += tag.toUtf8() + "\n";
        payload += path.toUtf8() + "\n";
        payload += "-execute" + QByteArray::number(seq) + "\n";

        if (proc.write(payload) != payload.size() || !proc.waitForBytesWritten(timeoutMs)) {
            proc.kill();
            proc.waitForFinished(1000);
            return {};
        }

        QElapsedTimer timer;
        timer.start();
        QByteArray buf;
        int at = -1;
        while ((at = ExifExtractor::markerPos(buf, marker)) < 0) {
            if (proc.bytesAvailable() > 0) {
                buf += proc.readAllStandardOutput();
                continue;
            }
            if (proc.state() != QProcess::Running) {
                buf += proc.readAllStandardOutput();
                at = ExifExtractor::markerPos(buf, marker);
                break;
            }
            const qint64 remaining = timeoutMs - timer.elapsed();
            if (remaining <= 0 || !proc.waitForReadyRead(static_cast<int>(remaining))) {
                proc.kill();
                proc.waitForFinished(1000);
                return {};
            }
            buf += proc.readAllStandardOutput();
        }
        if (at < 0 || proc.state() != QProcess::Running) {
            proc.kill();
            proc.waitForFinished(1000);
            return {};
        }

        *procHealthy = true;
        proc.readAllStandardError();

        const QByteArray jsonBytes = buf.left(at).trimmed();
        if (jsonBytes.isEmpty())
            return {};

        QJsonParseError pe{};
        const QJsonDocument doc = QJsonDocument::fromJson(jsonBytes, &pe);
        if (pe.error != QJsonParseError::NoError || !doc.isArray() || doc.array().isEmpty())
            return {};

        const QJsonObject obj = doc.array().first().toObject();
        const QString keyName = tag.startsWith(QLatin1Char('-')) ? tag.mid(1) : tag;
        QJsonValue val = obj.value(keyName);
        if (val.isUndefined()) {
            for (auto it = obj.constBegin(); it != obj.constEnd(); ++it) {
                if (it.key().compare(keyName, Qt::CaseInsensitive) == 0) {
                    val = it.value();
                    break;
                }
            }
        }
        if (!val.isString())
            return {};
        const QString s = val.toString();
        if (s.startsWith(QLatin1String("base64:")))
            return QByteArray::fromBase64(s.mid(7).toLatin1());
        return {};
    }

    QString m_binary;
    QMutex m_mutex;
    QWaitCondition m_reqCond;
    QWaitCondition m_doneCond;
    QThread* m_thread = nullptr;
    bool m_started = false;
    bool m_running = false;
    bool m_shutdown = false;
    bool m_hasRequest = false;
    bool m_reqDone = false;
    QString m_reqTag;
    QString m_reqPath;
    int m_reqTimeoutMs = 8000;
    QByteArray m_respBytes;
    bool m_respProcessOk = false;
};

class ExifToolPreviewPool {
public:
    ExifToolPreviewPool(QString binary, bool stayOpen, int maxIdle)
        : m_binary(std::move(binary))
        , m_stayOpen(stayOpen)
        , m_maxIdle(qBound(2, maxIdle, 6)) {}

    ~ExifToolPreviewPool() {
        close();
    }

    void close() {
        std::vector<std::unique_ptr<PersistentExifProcess>> toClose;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_closed = true;
            toClose.swap(m_idle);
        }
        toClose.clear();
    }

    bool isClosed() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_closed;
    }

    QByteArray extract(const QString& tag, const QString& path, int timeoutMs) {
        if (path.contains(QLatin1Char('\n')) || path.contains(QLatin1Char('\r')))
            return {};
        if (!m_stayOpen)
            return extractOnce(tag, path, timeoutMs);

        std::unique_ptr<PersistentExifProcess> proc;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_closed)
                return {};
            if (!m_idle.empty()) {
                proc = std::move(m_idle.back());
                m_idle.pop_back();
            }
        }
        if (!proc) {
            proc = std::make_unique<PersistentExifProcess>(m_binary);
            if (!proc->start())
                return {};
        }

        bool procOk = false;
        QByteArray bytes = proc->extract(tag, path, timeoutMs, &procOk);
        if (procOk) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_closed && static_cast<int>(m_idle.size()) < m_maxIdle)
                m_idle.push_back(std::move(proc));
        }
        return bytes;
    }

private:
    QByteArray extractOnce(const QString& tag, const QString& path, int timeoutMs) {
        QProcess process;
        process.start(m_binary, {QStringLiteral("-b"), tag, QStringLiteral("--"), path});
        if (!process.waitForStarted(timeoutMs) || !process.waitForFinished(timeoutMs)) {
            process.kill();
            process.waitForFinished(1000);
            return {};
        }
        return process.readAllStandardOutput();
    }

    QString m_binary;
    bool m_stayOpen = true;
    int m_maxIdle = 4;
    std::mutex m_mutex;
    bool m_closed = false;
    std::vector<std::unique_ptr<PersistentExifProcess>> m_idle;
};
} // namespace

struct ThumbnailSupport {
    ThumbnailSupport(QString binary, bool stayOpen, int maxIdle)
        : previewPool(std::move(binary), stayOpen, maxIdle) {}

    ~ThumbnailSupport() {
        close();
    }

    void close() {
        previewPool.close();
    }

    bool isClosed() {
        return previewPool.isClosed();
    }

    void clearDirCache() {
        std::lock_guard<std::mutex> lock(dirCanonicalMutex);
        dirCanonicalCache.clear();
    }

    bool cachedProbeAccessible(const QString& rootPath, int probeMs) {
        constexpr qint64 kProbeTtlMs = 5000;
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        {
            std::lock_guard<std::mutex> lock(probeMutex);
            const auto it = probeCache.constFind(rootPath);
            if (it != probeCache.constEnd() && now >= it.value().first &&
                (now - it.value().first) < kProbeTtlMs)
                return it.value().second;
        }
        const bool ok = probeAccessible(rootPath, probeMs);
        const qint64 doneAt = QDateTime::currentMSecsSinceEpoch();
        {
            std::lock_guard<std::mutex> lock(probeMutex);
            probeCache.insert(rootPath, {doneAt, ok});
        }
        return ok;
    }

    bool cachedIsDirWithinRoots(const QString& dir, const QStringList& normalizedRoots) {
        {
            std::lock_guard<std::mutex> lock(dirCanonicalMutex);
            const auto it = dirCanonicalCache.constFind(dir);
            if (it != dirCanonicalCache.constEnd())
                return it.value();
        }
        const bool within = isPathWithinNormalizedRoots(normalizePath(dir), normalizedRoots);
        {
            std::lock_guard<std::mutex> lock(dirCanonicalMutex);
            if (dirCanonicalCache.size() > 4096)
                dirCanonicalCache.clear();
            dirCanonicalCache.insert(dir, within);
        }
        return within;
    }

    std::mutex probeMutex;
    QHash<QString, std::pair<qint64, bool>> probeCache;

    std::mutex dirCanonicalMutex;
    QHash<QString, bool> dirCanonicalCache;

    ExifToolPreviewPool previewPool;
};

PhotoModule::PhotoModule(const QString& id, const QJsonObject& params, QObject* parent)
    : IModule(id, QStringLiteral("photo"), parent) {
    // Emplacement de la base : configurable, sinon l'état du service (doctrine
    // FILESYSTEM.md : /var/lib/morfsystem/morfphoto, seule zone où le service écrit).
    m_dbPath = params.value(QStringLiteral("db_path")).toString();
    if (m_dbPath.isEmpty())
        m_dbPath = Paths::stateDir(QStringLiteral("morfphoto")) + QStringLiteral("/photos.db");

    // Racines AUTORISÉES : le périmètre que morfPhoto a le droit d'explorer.
    for (const QJsonValue& v : params.value(QStringLiteral("roots")).toArray())
        m_roots << v.toString();

    const QJsonObject watch = params.value(QStringLiteral("watch")).toObject();
    m_intervalMs = watch.value(QStringLiteral("interval_ms")).toInt(m_intervalMs);
    m_scanOnStartup = watch.value(QStringLiteral("scan_on_startup")).toBool(m_scanOnStartup);
    // Délai borné des sondes d'accessibilité de racine (tolérance aux montages
    // distants). Configurable : pas de seuil en dur (règle 11 morfSystem).
    m_probeTimeoutMs = watch.value(QStringLiteral("availability_timeout_ms")).toInt(m_probeTimeoutMs);
    m_realtime   = watch.value(QStringLiteral("realtime")).toBool(false);
    m_debounceMs = watch.value(QStringLiteral("debounce_ms")).toInt(m_debounceMs);

    const QJsonObject exif = params.value(QStringLiteral("exiftool")).toObject();
    m_exiftoolBinary = exif.value(QStringLiteral("binary")).toString(QStringLiteral("exiftool"));
    m_stayOpen       = exif.value(QStringLiteral("stay_open")).toBool(true);
    const int configuredWorkers = exif.value(QStringLiteral("workers")).toInt(m_exifWorkers);
    bool hasEnvWorkers = false;
    const int envWorkers = qEnvironmentVariableIntValue("MORFPHOTO_EXIF_WORKERS", &hasEnvWorkers);
    const auto validWorkerCount = [](int count) { return count >= 1 && count <= 4; };
    if (hasEnvWorkers && validWorkerCount(envWorkers))
        m_exifWorkers = envWorkers;
    else if (validWorkerCount(configuredWorkers))
        m_exifWorkers = configuredWorkers;
    bool hasThumbnailWorkers = false;
    const int thumbnailWorkers = qEnvironmentVariableIntValue("MORFPHOTO_THUMBNAIL_WORKERS", &hasThumbnailWorkers);
    if (hasThumbnailWorkers && validWorkerCount(thumbnailWorkers))
        m_thumbnailWorkers = thumbnailWorkers;
    m_library = params.value(QStringLiteral("xmp")).toObject().value(QStringLiteral("enabled")).toBool(false);
    m_instanceId = s_moduleInstanceCounter.fetch_add(1, std::memory_order_relaxed) + 1;
    m_thumbnailSupport = std::make_shared<ThumbnailSupport>(m_exiftoolBinary, m_stayOpen, m_thumbnailWorkers);
}

PhotoModule::~PhotoModule() {
    if (m_started.load(std::memory_order_acquire))
        stop();
    if (m_thumbnailSupport)
        m_thumbnailSupport->close();
}

PhotoRepository* PhotoModule::readRepo() const {
    if (QThread::currentThread() == thread())
        return m_readRepo;
    if (!m_started.load(std::memory_order_acquire) || m_dbPath.isEmpty())
        return nullptr;

    struct WorkerRepoHolder {
        std::unique_ptr<PhotoRepository> repo;
        QString openedDbPath;
        quint64 instanceId = 0;
    };
    static QThreadStorage<WorkerRepoHolder> tls;
    static std::atomic<quint64> s_connCounter{0};

    WorkerRepoHolder& holder = tls.localData();
    if (!holder.repo || holder.openedDbPath != m_dbPath || holder.instanceId != m_instanceId) {
        holder.repo.reset();
        holder.openedDbPath.clear();
        holder.instanceId = 0;
        const quint64 connId = s_connCounter.fetch_add(1, std::memory_order_relaxed) + 1;
        auto repo = std::make_unique<PhotoRepository>(QStringLiteral("morfphoto:read-%1").arg(connId));
        if (!repo->open(m_dbPath, /*readOnly=*/true))
            return nullptr;
        holder.repo = std::move(repo);
        holder.openedDbPath = m_dbPath;
        holder.instanceId = m_instanceId;
    }
    return holder.repo.get();
}

bool PhotoModule::start() {
    m_readRepo = new PhotoRepository(QStringLiteral("morfphoto:read"));
    if (!m_readRepo->open(m_dbPath)) {
        const QString e = m_readRepo->openError();
        delete m_readRepo;
        m_readRepo = nullptr;
        QMutexLocker lock(&m_stateMutex);
        m_lastError = QStringLiteral("db: ") + e;   // visible via /modules et /api/v1/index/status
        return false;
    }

    if (!m_thumbnailSupport || m_thumbnailSupport->isClosed()) {
        QMutexLocker lock(&m_stateMutex);
        m_thumbnailSupport = std::make_shared<ThumbnailSupport>(m_exiftoolBinary, m_stayOpen, m_thumbnailWorkers);
    }

    // Sources SMB poussées par PhotoHub : leurs points de montage sont des racines
    // autorisées au même titre que celles de la config. Les charger AVANT la
    // réconciliation, pour qu'une sélection sous un montage poussé reste couverte.
    m_sourceManager.load();
    for (const QString& mp : m_sourceManager.mountpoints())
        if (!m_roots.contains(mp))
            m_roots << mp;

    // Aligner les sélections sur les racines autorisées actuelles (une racine
    // retirée désactive ses sélections sans effacer l'historique).
    reconcileRoots();

    // Sonder le prérequis ExifTool UNE fois, dès le démarrage. Le service tourne
    // même sans lui (les fichiers restent indexés), mais l'extraction EXIF échoue
    // alors en silence : on capture le verdict pour l'exposer dans l'état observable
    // plutôt que de le découvrir en constatant des métadonnées toutes nulles.
    {
        QString detail;
        const bool ready = ExifExtractor::probe(m_exiftoolBinary, &detail);
        QMutexLocker lock(&m_stateMutex);
        m_exiftoolReady  = ready;
        m_exiftoolDetail = detail;
    }

    // Une cadence positive active la réconciliation périodique. La première
    // passe peut être différée jusqu'au premier déclenchement du minuteur.
    if (m_intervalMs > 0) {
        m_watchTimer = new QTimer(this);
        m_watchTimer->setInterval(m_intervalMs);
        connect(m_watchTimer, &QTimer::timeout, this, [this]() {
            triggerIndex(IndexMode::Incremental, {}, QStringLiteral("watch"));
        });
        m_watchTimer->start();

        if (m_scanOnStartup)
            triggerIndex(IndexMode::Incremental, {}, QStringLiteral("watch"));
    }

    if (m_realtime)
        startWatcher();

    const bool hasCacheDir = !qEnvironmentVariableIsEmpty("MORFPHOTO_THUMBNAIL_CACHE_DIR");
    m_thumbnailEnabled.store(hasCacheDir, std::memory_order_release);
    m_started.store(true, std::memory_order_release);
    if (hasCacheDir) {
        m_thumbnailTimer = new QTimer(this);
        m_thumbnailTimer->setSingleShot(true);
        connect(m_thumbnailTimer, &QTimer::timeout, this, &PhotoModule::warmThumbnails);
        m_thumbnailTimer->start(1000);
    }
    return true;
}

void PhotoModule::startWatcher() {
    m_realtimeRetry = new QTimer(this);
    m_realtimeRetry->setSingleShot(true);
    m_realtimeRetry->setInterval(1000);
    connect(m_realtimeRetry, &QTimer::timeout, this, &PhotoModule::submitRealtime);

    m_watcherThread = new QThread(this);
    m_watcher = new FolderWatcher(m_debounceMs, m_probeTimeoutMs);
    m_watcher->moveToThread(m_watcherThread);
    connect(m_watcherThread, &QThread::finished, m_watcher, &QObject::deleteLater);
    connect(m_watcher, &FolderWatcher::scopesChanged, this, [this](const QVector<IndexScope>& scopes) {
        for (const IndexScope& scope : scopes)
            mergeScope(m_pendingRealtime, scope);
        submitRealtime();
    });
    m_watcherThread->start();
    refreshWatcher();
}

void PhotoModule::stopWatcher() {
    if (!m_watcherThread)
        return;
    m_realtimeRetry->stop();
    m_watcher->requestStop();
    m_watcherThread->quit();
    if (!m_watcherThread->wait(15000)) {
        m_watcherThread->terminate();
        m_watcherThread->wait();
    }
    delete m_watcherThread;
    m_watcherThread = nullptr;
    m_watcher = nullptr;
}

void PhotoModule::refreshWatcher() {
    if (!m_watcher || !m_readRepo)
        return;
    QVector<WatchTarget> targets;
    for (const FolderRow& folder : m_readRepo->activeFolders())
        targets.push_back({folder.id, folder.path, folder.recursive});
    FolderWatcher* watcher = m_watcher;
    QMetaObject::invokeMethod(watcher, [watcher, targets]() { watcher->setTargets(targets); },
                              Qt::QueuedConnection);
}

void PhotoModule::submitRealtime() {
    if (m_pendingRealtime.isEmpty())
        return;
    // Une passe tourne deja : elle a pu manquer ce changement, on repassera apres elle.
    if (triggerIndexScopes(IndexMode::Incremental, m_pendingRealtime, QStringLiteral("inotify"))
            .value(QStringLiteral("accepted")).toBool())
        m_pendingRealtime.clear();
    else
        m_realtimeRetry->start();
}

void PhotoModule::stop() {
    m_started.store(false, std::memory_order_release);
    m_thumbnailEnabled.store(false, std::memory_order_release);
    if (m_thumbnailTimer) {
        delete m_thumbnailTimer;
        m_thumbnailTimer = nullptr;
    }
    if (m_thumbnailWarmPass) {
        m_thumbnailWarmStop->store(true);
        m_thumbnailWarmPass->waitForFinished();
        delete m_thumbnailWarmPass;
        m_thumbnailWarmPass = nullptr;
        m_thumbnailWarmStop.reset();
    }
    if (m_thumbnailSupport)
        m_thumbnailSupport->close();
    stopWatcher();
    if (m_watchTimer) {
        m_watchTimer->stop();
        m_watchTimer->deleteLater();
        m_watchTimer = nullptr;
    }
    // Attendre la fin d'une passe éventuellement en cours avant de fermer la base.
    if (m_pass.isRunning())
        m_pass.waitForFinished();
    if (m_readRepo) {
        m_readRepo->close();
        delete m_readRepo;
        m_readRepo = nullptr;
    }
}

void PhotoModule::warmThumbnails() {
    if (!m_started.load(std::memory_order_acquire) || m_thumbnailWarmPass)
        return;
    if (!m_exiftoolReady) {
        m_thumbnailTimer->start(10000);
        return;
    }
    {
        QMutexLocker lock(&m_stateMutex);
        if (m_indexing) {
            m_thumbnailTimer->start(1000);
            return;
        }
    }

    m_thumbnailWarmStop = std::make_shared<std::atomic_bool>(false);
    m_thumbnailWarmPass = new QFutureWatcher<ThumbnailWarmBatch>(this);
    connect(m_thumbnailWarmPass, &QFutureWatcher<ThumbnailWarmBatch>::finished, this, [this] {
        const auto result = m_thumbnailWarmPass->result();
        m_thumbnailWarmPass->deleteLater();
        m_thumbnailWarmPass = nullptr;
        m_thumbnailWarmStop.reset();
        m_thumbnailChecked.fetch_add(result.checked, std::memory_order_relaxed);
        const qint64 currentWrites = m_thumbnailWrites->load(std::memory_order_relaxed);
        if (result.cached >= 0) {
            const qint64 writesDuringWarm = qMax<qint64>(0, currentWrites - result.writesAtCount);
            m_thumbnailCached.store(result.cached + writesDuringWarm, std::memory_order_relaxed);
            m_thumbnailCountedAt = QDateTime::currentMSecsSinceEpoch();
        } else {
            const qint64 prevCached = m_thumbnailCached.load(std::memory_order_relaxed);
            const qint64 delta = currentWrites - m_thumbnailLastWrites;
            if (prevCached >= 0 && delta > 0)
                m_thumbnailCached.store(prevCached + delta, std::memory_order_relaxed);
        }
        m_thumbnailLastWrites = currentWrites;
        m_thumbnailCaughtUp.store(!result.more, std::memory_order_relaxed);
        if (m_thumbnailTimer)
            m_thumbnailTimer->start(result.more ? 250 : 10000);
    });
    const bool needCount = m_thumbnailCached.load(std::memory_order_relaxed) < 0 ||
                           (QDateTime::currentMSecsSinceEpoch() - m_thumbnailCountedAt >= 600000);
    auto future = QtConcurrent::run([dbPath = m_dbPath, stop = m_thumbnailWarmStop,
                                    read = thumbnailReader(true, true), workers = m_thumbnailWorkers,
                                    writes = m_thumbnailWrites, count = needCount,
                                    root = qEnvironmentVariable("MORFPHOTO_THUMBNAIL_CACHE_DIR")] {
        ThumbnailWarmBatch result;
        const QStorageInfo disk(root);
        if (!QDir::isAbsolutePath(root) || !QDir(root).exists())
            return result;
        if (count) {
            QDirIterator files(root, {QStringLiteral("*.jpg")}, QDir::Files | QDir::NoSymLinks,
                               QDirIterator::Subdirectories);
            qint64 cached = 0;
            while (!stop->load() && files.hasNext()) {
                files.next();
                ++cached;
            }
            if (stop->load())
                return result;
            result.cached = cached;
            result.writesAtCount = writes->load(std::memory_order_relaxed);
        }
        if (!disk.isValid() || disk.bytesAvailable() < kMinThumbnailFreeBytes)
            return result;
        PhotoRepository repo(QStringLiteral("morfphoto:thumbnail-warmer"));
        if (!repo.open(dbPath, /*readOnly=*/true))
            return result;
        const QString checkpoint = QDir(root).filePath(QStringLiteral(".warm-through-") + QString::fromLatin1(kJpegThumbnailCacheVersion));
        qint64 cursor = 0;
        {
            QFile input(checkpoint);
            if (input.open(QIODevice::ReadOnly))
                cursor = qMax(qint64(0), input.read(32).toLongLong());
        }
        if (const qint64 lastId = repo.lastPhotoId(); lastId >= 0 && lastId < cursor)
            cursor = 0;
        const auto candidates = repo.thumbnailCandidates(cursor, 32 * workers);
        repo.close();
        std::atomic<qsizetype> next{0};
        const auto warm = [&] {
            while (!stop->load()) {
                const qsizetype index = next.fetch_add(1);
                if (index >= candidates.size())
                    return;
                read(candidates.at(index).second);
            }
        };
        // Un seul lecteur SQLite. Les travailleurs se partagent les chemins
        // déjà chargés et terminent les lectures engagées avant le checkpoint.
        std::vector<std::future<void>> readers;
        const qsizetype lanes = qMin<qsizetype>(workers, candidates.size());
        for (qsizetype lane = 1; lane < lanes; ++lane)
            readers.push_back(std::async(std::launch::async | std::launch::deferred, warm));
        warm();
        for (auto& reader : readers)
            reader.get();
        result.checked = qMin(next.load(), candidates.size());
        result.more = !candidates.isEmpty();
        if (result.checked > 0) {
            QSaveFile output(checkpoint);
            const QByteArray contents = QByteArray::number(candidates.at(result.checked - 1).first);
            if (!output.open(QIODevice::WriteOnly) || output.write(contents) != contents.size() ||
                !output.commit())
                result.more = false;
        }
        return result;
    });
    m_thumbnailWarmPass->setFuture(future);
}

// --- Indexation -------------------------------------------------------------

QJsonObject PhotoModule::triggerIndex(IndexMode mode, const QVector<int>& folderIds,
                                      const QString& trigger) {
    return startPass(mode, folderIds, {}, trigger);
}

QJsonObject PhotoModule::triggerIndexScopes(IndexMode mode, const QVector<IndexScope>& scopes,
                                            const QString& trigger) {
    return startPass(mode, {}, scopes, trigger);
}

QJsonObject PhotoModule::startPass(IndexMode mode, const QVector<int>& folderIds,
                                   const QVector<IndexScope>& scopes, const QString& trigger) {
    {
        QMutexLocker lock(&m_stateMutex);
        if (m_indexing) {
            // Une seule passe à la fois : refuser sans empiler.
            QJsonObject o;
            o["accepted"]   = false;
            o["state"]      = QStringLiteral("already_running");
            o["started_at"] = m_startedAt;
            return o;
        }
        m_indexing  = true;
        m_startedAt = nowIso();
        m_startedAtEpoch = QDateTime::currentSecsSinceEpoch();
        m_lastError.clear();
        // Repartir d'une progression vierge : l'ancienne passe ne doit pas laisser
        // de compteurs résiduels visibles au tout début de la nouvelle.
        m_progFoldersTotal = 0;
        m_progFoldersDone  = 0;
        m_progFilesSeen    = 0;
        m_progFilesTotal   = -1;
        m_progFilesTotalFinal = false;
        m_progPhase        = QStringLiteral("indexing");
        m_progCurrentFolder.clear();
    }

    if (m_thumbnailWarmStop)
        m_thumbnailWarmStop->store(true);
    m_pass = QtConcurrent::run([this, mode, folderIds, scopes, trigger]() {
        doPass(mode, folderIds, scopes, trigger);
    });

    QJsonObject o;
    o["accepted"] = true;
    o["state"]    = QStringLiteral("indexing");
    return o;
}

void PhotoModule::doPass(IndexMode mode, QVector<int> folderIds, QVector<IndexScope> scopes, QString trigger) {
    int pass;
    QStringList roots;
    {
        QMutexLocker lock(&m_stateMutex);
        pass = ++m_passCounter;
        // Copie des racines sous verrou : addSource() (thread HTTP) peut en ajouter
        // une pendant qu'une passe démarre. La passe travaille sur son instantané.
        roots = m_roots;
    }
    QString error;
    {
        // Connexion et process ExifTool PROPRES à ce thread de passe.
        PhotoRepository repo(QStringLiteral("morfphoto:index:%1").arg(pass));
        if (repo.open(m_dbPath)) {
            ExifExtractor extractor(m_exiftoolBinary, m_stayOpen);
            extractor.setLibraryTags(m_library);
            extractor.open();
            Indexer indexer(&repo, &extractor, roots, m_probeTimeoutMs);
            indexer.setLibraryEnabled(m_library);
            indexer.setExifWorkers(m_exifWorkers);
            // Relais de progression : l'Indexer rappelle depuis CE thread ; on recopie
            // sous verrou dans les membres lus par observableState() (thread HTTP).
            indexer.setProgressCallback([this](const IndexProgress& p) {
                QMutexLocker lock(&m_stateMutex);
                m_progFoldersDone   = p.foldersDone;
                m_progFoldersTotal  = p.foldersTotal;
                m_progFilesSeen     = p.filesSeen;
                m_progFilesTotal    = p.filesTotal;
                m_progFilesTotalFinal = p.filesTotalFinal;
                m_progPhase         = p.phase;
                m_progCurrentFolder = p.currentFolder;
            });
            if (!scopes.isEmpty())
                indexer.runScopes(mode, scopes, trigger);
            else
                indexer.run(mode, folderIds, trigger);
            extractor.close();
            const QJsonObject st = indexer.state();
            if (!st.value(QStringLiteral("last_error")).isNull())
                error = st.value(QStringLiteral("last_error")).toString();
        } else {
            error = QStringLiteral("ouverture de la base impossible pour la passe");
        }
    }
    qint64 startEpoch = 0, filesSeen = 0;
    int    foldersTotal = 0;
    {
        QMutexLocker lock(&m_stateMutex);
        m_indexing = false;
        m_lastError = error;
        m_lastFoldersTotal = m_progFoldersTotal;
        startEpoch   = m_startedAtEpoch;
        filesSeen    = m_progFilesSeen;
        foldersTotal = m_progFoldersTotal;
    }

    // Passe terminee : la declarer a morfAnalytics comme activite HISTORIQUE
    // (contrat `activity/1` §6). Best-effort, hors verrou, jamais bloquant : une
    // telemetrie muette ne doit pas peser sur l'indexation. On est deja dans le
    // thread de passe, la synchronicite du POST (timeout court) est sans impact.
    reportIndexActivity(startEpoch, filesSeen, foldersTotal, error);
}

QJsonObject PhotoModule::observableState() const {
    QMutexLocker lock(&m_stateMutex);
    QJsonObject o;
    o["state"]      = m_indexing ? QStringLiteral("indexing") : QStringLiteral("idle");
    o["started_at"] = m_indexing ? QJsonValue(m_startedAt) : QJsonValue(QJsonValue::Null);

    // Progression de la passe en cours : le total de dossiers est un dénominateur
    // fiable (une barre déterminée), le compteur de fichiers montre l'avancée dans un
    // gros dossier. current_folder null si la passe vient juste de démarrer.
    if (m_indexing) {
        QJsonObject prog;
        prog["phase"]          = m_progPhase.isEmpty()
                                     ? QStringLiteral("indexing")
                                     : m_progPhase;
        prog["folders_total"]  = m_progFoldersTotal;
        prog["folders_done"]   = m_progFoldersDone;
        prog["files_seen"]     = static_cast<double>(m_progFilesSeen);
        prog["current_folder"] = m_progCurrentFolder.isEmpty()
                                     ? QJsonValue(QJsonValue::Null)
                                     : QJsonValue(m_progCurrentFolder);
        prog["files_total_final"] = m_progFilesTotalFinal;
        if (m_progFilesTotal >= 0) {
            prog["files_total"] = static_cast<double>(m_progFilesTotal);
            if (m_progFilesTotal == 0) {
                prog["percent"] = m_progFilesTotalFinal ? 100.0 : 0.0;
            } else {
                double pct = 100.0 * double(m_progFilesSeen) / double(m_progFilesTotal);
                // Tant que le total peut encore grandir, ne jamais afficher 100 % :
                // le dénominateur n'est pas clos, un 100 % mentirait.
                if (!m_progFilesTotalFinal && pct > 99.0)
                    pct = 99.0;
                prog["percent"] = qRound(pct * 10.0) / 10.0;
            }
        } else {
            prog["files_total"] = QJsonValue(QJsonValue::Null);
            prog["percent"]     = QJsonValue(QJsonValue::Null);
        }
        o["progress"] = prog;
    }

    // Cadence de l'indexation automatique : de quoi savoir, côté client, si une
    // passe de fond tourne et à quelle fréquence (ou si tout est à la demande).
    // m_intervalMs est fixé à la construction et ne change plus : lecture sûre.
    QJsonObject watch;
    watch["auto"]        = (m_intervalMs > 0);
    watch["interval_ms"] = m_intervalMs;
    watch["scan_on_startup"] = m_intervalMs > 0 && m_scanOnStartup;
    if (m_watcher)
        watch["realtime"] = m_watcher->statusJson();
    o["watch"] = watch;

    // État du prérequis ExifTool. Un binaire absent ne fait pas tomber le service
    // (les fichiers sont indexés), mais laisse les métadonnées vides : le dire ici
    // évite une enquête sur des colonnes EXIF mystérieusement nulles.
    QJsonObject exif;
    exif["available"] = m_exiftoolReady;
    exif["binary"]    = m_exiftoolBinary;
    exif["workers"]   = m_exifWorkers;
    exif["detail"]    = m_exiftoolDetail.isEmpty() ? QJsonValue(QJsonValue::Null)
                                                   : QJsonValue(m_exiftoolDetail);
    o["exiftool"] = exif;

    // last_error : priorité à l'erreur de la dernière passe ; à défaut, un ExifTool
    // introuvable est une cause d'échec permanente qui mérite ce champ (sinon
    // l'extraction rate chaque fichier sans que rien ne remonte au niveau module).
    QString err = m_lastError;
    if (err.isEmpty() && !m_exiftoolReady)
        err = QStringLiteral("ExifTool introuvable (%1) : les photos sont indexees mais "
                             "les metadonnees restent vides. Installer le paquet "
                             "libimage-exiftool-perl.").arg(m_exiftoolBinary);
    o["last_error"] = err.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(err);
    return o;
}

QJsonObject PhotoModule::activityJson() const {
    // Contrat generique `activity/1` : pendant une passe, on decrit l'indexation
    // en cours ; rien en cours => objet vide (le champ `activity` sera absent de
    // /status). Meme source verrouillee que observableState().
    QMutexLocker lock(&m_stateMutex);
    if (!m_indexing)
        return {};
    QJsonObject a;
    a["type"]  = QStringLiteral("indexation");
    a["state"] = QStringLiteral("running");
    if (m_startedAtEpoch > 0)
        a["started_at"] = static_cast<double>(m_startedAtEpoch);
    a["current"] = static_cast<double>(m_progFilesSeen);
    if (m_progFilesTotal >= 0) {
        a["total"] = static_cast<double>(m_progFilesTotal);
        double pct;
        if (m_progFilesTotal == 0) {
            pct = m_progFilesTotalFinal ? 100.0 : 0.0;
        } else {
            pct = 100.0 * double(m_progFilesSeen) / double(m_progFilesTotal);
            // Tant que le total peut grandir, ne jamais afficher 100 % : le
            // denominateur n'est pas clos, un 100 % mentirait.
            if (!m_progFilesTotalFinal && pct > 99.0)
                pct = 99.0;
        }
        a["progress_percent"] = qRound(pct * 10.0) / 10.0;
    }
    if (!m_progCurrentFolder.isEmpty())
        a["detail"] = m_progCurrentFolder;
    return a;
}

void PhotoModule::reportIndexActivity(qint64 startEpoch, qint64 filesSeen,
                                      int foldersTotal, const QString& error) const {
    // Ou envoyer : variable d'environnement d'abord, puis fichier admin partage
    // (meme convention que morfDeploy). Aucune source => rien n'est emis :
    // morfPhoto ne depend jamais de morfAnalytics.
    QString url = qEnvironmentVariable("MORFANALYTICS_ACTIVITY_URL").trimmed();
    if (url.isEmpty()) {
        QFile f(QStringLiteral("/etc/morfsystem/monitor-activity-url"));
        if (f.exists() && f.open(QIODevice::ReadOnly | QIODevice::Text))
            url = QString::fromUtf8(f.readAll()).trimmed();
    }
    if (url.isEmpty())
        return;

    const qint64 end   = QDateTime::currentSecsSinceEpoch();
    const qint64 start = startEpoch > 0 ? startEpoch : end;

    QJsonObject meta;
    meta["files"]   = static_cast<double>(filesSeen);
    meta["folders"] = foldersTotal;
    if (!error.isEmpty())
        meta["error"] = error;

    QJsonObject payload;
    payload["type"]     = QStringLiteral("indexation");
    payload["project"]  = QStringLiteral("morfPhoto");
    payload["machine"]  = QHostInfo::localHostName();
    payload["start_ts"] = static_cast<double>(start);
    payload["end_ts"]   = static_cast<double>(end);
    payload["status"]   = error.isEmpty() ? QStringLiteral("success")
                                          : QStringLiteral("failed");
    payload["metadata"] = meta;

    // POST synchrone avec timeout court : on est dans le thread de passe (deja
    // termine cote indexation), donc bloquer un instant ici n'impacte pas le
    // service. QNAM + QEventLoop local pour ne suspendre que ce thread.
    QNetworkAccessManager nam;
    QNetworkRequest req{QUrl(url)};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    QNetworkReply* reply = nam.post(req, QJsonDocument(payload).toJson(QJsonDocument::Compact));

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    timer.start(3000);
    loop.exec();
    if (!reply->isFinished())
        reply->abort();                 // timeout : on renonce, sans bruit ni blocage

    if (reply->error() != QNetworkReply::NoError)
        qWarning().noquote() << "morfPhoto: activite non signalee a morfAnalytics ("
                             << reply->errorString()
                             << ") - sans consequence pour l'indexation";
    reply->deleteLater();
}

QJsonObject PhotoModule::indexStatus() const {
    QJsonObject o = observableState();
    const bool indexing = o.value(QStringLiteral("state")).toString() == QStringLiteral("indexing");
    const auto clipRoot = qEnvironmentVariable("MORFPHOTO_CLIP_DIR");
    QJsonObject clipStatus{{"state", clipRoot.isEmpty() ? "disabled" : "starting"}};
    if (!clipRoot.isEmpty()) {
        QFile statusFile(QDir(clipRoot).filePath(QStringLiteral("status.json")));
        if (statusFile.open(QIODevice::ReadOnly)) {
            const auto status = QJsonDocument::fromJson(statusFile.read(4096));
            if (status.isObject())
                clipStatus = status.object();
        }
    }
    o["clip"] = clipStatus;
    const qint64 cachedThumbnails = m_thumbnailCached.load(std::memory_order_relaxed);
    o["thumbnails"] = QJsonObject{
        {"state", !m_thumbnailEnabled.load(std::memory_order_acquire) ? "disabled" : indexing ? "paused" :
                  m_thumbnailCaughtUp.load(std::memory_order_relaxed) ? "idle" : "warming"},
        {"workers", m_thumbnailWorkers},
        {"checked", m_thumbnailChecked.load(std::memory_order_relaxed)},
        {"generated", m_thumbnailWrites->load()},
        {"cached", cachedThumbnails < 0 ? QJsonValue() : QJsonValue(cachedThumbnails)},
    };
    bool found = false;
    PhotoRepository* repo = readRepo();
    const QJsonObject runRaw = repo ? repo->latestRun(&found) : QJsonObject{};
    if (found) {
        QJsonObject run = runRaw;
        int lastFolders = 0;
        {
            QMutexLocker lock(&m_stateMutex);
            lastFolders = m_lastFoldersTotal;
        }
        if (lastFolders > 0 && !run.contains(QStringLiteral("folders_total")))
            run[QStringLiteral("folders_total")] = lastFolders;
        o["last_run"] = run;
    } else {
        o["last_run"] = QJsonValue(QJsonValue::Null);
    }
    return o;
}

// --- Lectures ---------------------------------------------------------------

QJsonObject PhotoModule::summary() const {
    PhotoRepository* repo = readRepo();
    if (!repo)
        return {};
    // Le resume est couteux (DISTINCT, jointures par repertoire) et PhotoHub l'interroge en
    // boucle : pendant une indexation, les appels s'empilaient et /status (donc morfMonitor)
    // comme PhotoHub expiraient. On le garde donc en cache : 10 s au repos, 60 s pendant une
    // passe (les compteurs bougent, mais un resume legerement perime vaut mieux qu'un service muet).
    bool indexing;
    {
        QMutexLocker lock(&m_stateMutex);
        indexing = m_indexing;
    }
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 ttl = indexing ? 60000 : 10000;
    QMutexLocker summaryLock(&m_summaryMutex);
    if (m_summaryAtMs == 0 || now - m_summaryAtMs > ttl || m_summaryCache.isEmpty()) {
        m_summaryCache = repo->summary();
        m_summaryAtMs  = QDateTime::currentMSecsSinceEpoch();
    }
    return m_summaryCache;
}
QJsonObject PhotoModule::listPhotos(const QVariantMap& filters, int page, int pageSize) const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->listPhotos(filters, page, pageSize) : QJsonObject{};
}
QStringList PhotoModule::directorySample(const QString& directory, int count) const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->directorySample(directory, count) : QStringList{};
}
QJsonObject PhotoModule::getPhoto(int fileId, bool* found) const {
    PhotoRepository* repo = readRepo();
    if (!repo) { if (found) *found = false; return {}; }
    return repo->getPhoto(fileId, found);
}
QJsonArray PhotoModule::cameras() const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->distinctCameras() : QJsonArray{};
}
QJsonArray PhotoModule::lenses() const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->distinctLenses() : QJsonArray{};
}
QJsonArray PhotoModule::focals() const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->distinctFocals() : QJsonArray{};
}
QJsonArray PhotoModule::years() const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->years() : QJsonArray{};
}
QJsonObject PhotoModule::photoDataset() const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->photoDataset() : QJsonObject{};
}

// --- Bibliothèque -----------------------------------------------------------

QJsonObject PhotoModule::cachedLibraryQuery(PhotoRepository* repo, const QString& key,
                                             const std::function<QJsonObject()>& compute) const {
    const quint64 epoch = m_writeEpoch.load(std::memory_order_acquire);
    const qint64 dataVer = repo->dataVersion();
    {
        QMutexLocker lock(&m_libraryCacheMutex);
        for (auto it = m_libraryCache.begin(); it != m_libraryCache.end(); ++it) {
            if (it->writeEpoch == epoch && it->dataVersion == dataVer && it->key == key) {
                m_libraryCache.splice(m_libraryCache.begin(), m_libraryCache, it);
                return it->value;
            }
        }
    }
    const QJsonObject result = compute();
    {
        QMutexLocker lock(&m_libraryCacheMutex);
        for (auto it = m_libraryCache.begin(); it != m_libraryCache.end(); ++it) {
            if (it->writeEpoch == epoch && it->dataVersion == dataVer && it->key == key) {
                m_libraryCache.splice(m_libraryCache.begin(), m_libraryCache, it);
                return result;
            }
        }
        m_libraryCache.push_front({epoch, dataVer, key, result});
        if (m_libraryCache.size() > 16)
            m_libraryCache.pop_back();
    }
    return result;
}

QJsonObject PhotoModule::librarySubfolders(const QString& folder) const {
    PhotoRepository* repo = readRepo();
    if (!repo)
        return {};
    return cachedLibraryQuery(repo, QStringLiteral("S:") + folder,
                              [&]() { return repo->librarySubfolders(folder); });
}

QJsonObject PhotoModule::libraryList(const LibraryFilter& filter, int page, int pageSize) const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->libraryList(filter, page, pageSize) : QJsonObject{};
}

QJsonObject PhotoModule::libraryFacets(const LibraryFilter& filter) const {
    PhotoRepository* repo = readRepo();
    if (!repo)
        return {};
    return cachedLibraryQuery(repo, serializeLibraryFilter(filter),
                              [&]() { return repo->libraryFacets(filter); });
}
QJsonObject PhotoModule::libraryPhoto(int fileId, bool* found) const {
    PhotoRepository* repo = readRepo();
    if (!repo) { if (found) *found = false; return {}; }
    return repo->libraryPhoto(fileId, found);
}

QJsonArray PhotoModule::libraryPhotos(const QVector<int>& fileIds, bool withRaw) const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->libraryPhotos(fileIds, withRaw) : QJsonArray{};
}

// --- Contexte photographique (morfphoto-context/2) --------------------------

QJsonArray PhotoModule::listContexts(const QString& status) const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->listContexts(status) : QJsonArray{};
}

QJsonObject PhotoModule::getContext(const QString& directory) const {
    PhotoRepository* repo = readRepo();
    if (!repo) return {};
    return repo->getContext(directory);
}

bool PhotoModule::putContext(const QString& directory, const QString& context,
                             const QString& subject, const QVariant& motif,
                             const QVariant& description, QJsonObject* out, QString* error) {
    if (!m_readRepo) { if (error) *error = QStringLiteral("base non ouverte"); return false; }

    // Garde-fou de périmètre : n'écrire un `.morfphoto.json` que sous une racine autorisée.
    if (matchingRoot(directory).isEmpty()) {
        if (error) *error = QStringLiteral("le dossier %1 n'est sous aucune racine autorisee").arg(directory);
        return false;
    }
    // Contrat V2 : context ET subject obligatoires et dans le vocabulaire gelé. La
    // tolérance aux valeurs hors vocabulaire vaut à la LECTURE d'un fichier existant,
    // jamais à l'ÉCRITURE que morfPhoto produit lui-même.
    const QString ctx  = context.trimmed().toUpper();
    const QString subj = subject.trimmed().toUpper();
    if (!ContextFile::isKnownContext(ctx)) {
        if (error) *error = QStringLiteral("context invalide: %1").arg(context);
        return false;
    }
    if (!ContextFile::isKnownSubject(subj)) {
        if (error) *error = QStringLiteral("subject invalide: %1").arg(subject);
        return false;
    }
    // Ne qualifier qu'un répertoire réellement indexé (contient des photos présentes).
    if (!m_readRepo->directoryHasPhotos(directory)) {
        if (error) *error = QStringLiteral("dossier inconnu ou sans photo indexee: %1").arg(directory);
        return false;
    }
    // La source peut dormir (PC éteint la nuit) : son montage réseau figé ferait bloquer
    // l'écriture ~180 s (timeout CIFS) et gèlerait ce worker HTTP. Sonde bornée d'abord :
    // une source injoignable renvoie une erreur claire tout de suite au lieu de bloquer.
    if (!probeAccessible(directory, m_probeTimeoutMs)) {
        if (error) *error = QStringLiteral("source injoignable (endormie ou deconnectee ?) : "
                                           "impossible d'ecrire le contexte dans %1").arg(directory);
        return false;
    }

    // Préserver `created` d'un contexte antérieur ; toujours rafraîchir `updated`.
    const QString nowLocal = QDateTime::currentDateTime().toString(Qt::ISODate);
    const QJsonObject existing = m_readRepo->getContext(directory);
    const QJsonValue createdV = existing.value(QStringLiteral("created"));
    const QString created = (createdV.isString() && !createdV.toString().isEmpty())
        ? createdV.toString() : nowLocal;

    const QByteArray bytes = ContextFile::serialize(ctx, subj, motif, description,
                                                    created, nowLocal);
    QString werr;
    if (!ContextFile::write(directory, bytes, &werr)) {
        if (error) *error = QStringLiteral("ecriture du contexte impossible: %1").arg(werr);
        return false;
    }

    // Mettre à jour la projection tout de suite (sans attendre une passe), à partir du
    // fichier réellement écrit (mtime constaté).
    const QString filePath = QDir(directory).filePath(ContextFile::fileName());
    FolderContext fc;
    fc.directory   = directory;
    fc.schema      = 2;
    fc.context     = ctx;
    fc.subject     = subj;
    fc.motif       = motif;
    fc.description = description;
    fc.created     = created;
    fc.updated     = nowLocal;
    fc.sourceMtime = QFileInfo(filePath).lastModified().toSecsSinceEpoch();
    fc.status      = QStringLiteral("ok");
    m_readRepo->upsertContext(fc);
    m_writeEpoch.fetch_add(1, std::memory_order_release);

    if (out) *out = m_readRepo->getContext(directory);
    return true;
}

std::function<QByteArray(const QString&)> PhotoModule::thumbnailReader(bool requireCache, bool prewarm) const {
    const QString cacheRoot = qEnvironmentVariable("MORFPHOTO_THUMBNAIL_CACHE_DIR");
    qint64 shardBytes = 8LL * 1024 * 1024;
    bool hasMaxMb = false;
    const int maxMb = qEnvironmentVariableIntValue("MORFPHOTO_THUMBNAIL_MAX_MB", &hasMaxMb);
    if (hasMaxMb && maxMb > 0)
        shardBytes = qMax<qint64>(2LL * 1024 * 1024, (qint64(maxMb) * 1024LL * 1024LL) / 4096LL);

    QStringList roots;
    bool ready = false;
    std::shared_ptr<ThumbnailSupport> support;
    {
        QMutexLocker lock(&m_stateMutex);
        roots = m_roots;
        ready = m_exiftoolReady;
        support = m_thumbnailSupport;
    }
    if (!support)
        support = std::make_shared<ThumbnailSupport>(m_exiftoolBinary, m_stayOpen, m_thumbnailWorkers);

    QStringList cleanedRoots;
    cleanedRoots.reserve(roots.size());
    for (const QString& root : roots) {
        if (!root.isEmpty())
            cleanedRoots.push_back(QDir::cleanPath(root));
    }
    const QStringList normalizedRoots = normalizeRoots(roots);

    return [cleanedRoots, normalizedRoots, ready, probeMs = m_probeTimeoutMs,
            cacheRoot, shardBytes, requireCache, prewarm,
            writes = m_thumbnailWrites, support](const QString& path) -> QByteArray {
        if (path.isEmpty() || !QDir::isAbsolutePath(path) || path.contains(QChar::Null))
            return {};
        const bool cacheEnabled = QDir::isAbsolutePath(cacheRoot) && QDir(cacheRoot).exists();
        if (requireCache && !cacheEnabled)
            return {};

        const QString cleanPath = QDir::cleanPath(path);
        QString matchingRoot;
        for (const QString& root : cleanedRoots) {
            if (root == QLatin1String("/")) {
                matchingRoot = root;
                break;
            }
            if (cleanPath.startsWith(root + QLatin1Char('/'))) {
                matchingRoot = root;
                break;
            }
        }
        if (matchingRoot.isEmpty()) {
            for (const QString& root : normalizedRoots) {
                if (root == QLatin1String("/")) {
                    matchingRoot = root;
                    break;
                }
                if (cleanPath.startsWith(root + QLatin1Char('/'))) {
                    matchingRoot = root;
                    break;
                }
            }
        }
        if (matchingRoot.isEmpty() || !support->cachedProbeAccessible(matchingRoot, probeMs))
            return {};

        const QFileInfo file(cleanPath);
        const bool contained = file.isSymLink()
            ? isPathWithinNormalizedRoots(normalizePath(file.absoluteFilePath()), normalizedRoots)
            : support->cachedIsDirWithinRoots(file.absolutePath(), normalizedRoots);
        if (!contained || !file.isFile())
            return {};

        const qint64 size = file.size();
        const auto modified = file.lastModified();
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(file.absoluteFilePath().toUtf8());
        hash.addData(QByteArray::number(size).prepend('\0'));
        hash.addData(QByteArray::number(modified.toMSecsSinceEpoch()).prepend('\0'));
        const QByteArray key = hash.result().toHex();
        const QDir shard(cacheRoot + '/' + QString::fromLatin1(key.left(2)) + '/' +
                         QString::fromLatin1(key.mid(2, 1)));
        const QString stem = QString::fromLatin1(key);
        const QString legacy = shard.filePath(stem + QStringLiteral(".jpg"));
        const bool jpegSource = fileTypeFor(QLatin1Char('.') + file.suffix()) == QLatin1String("jpeg");
        const auto cachePath = [&](const char* version) {
            return shard.filePath(stem + '-' + QString::fromLatin1(version) + QStringLiteral(".jpg"));
        };
        const QString target = cachePath(jpegSource ? kJpegThumbnailCacheVersion : kThumbnailCacheVersion);
        const QString previous = jpegSource ? cachePath(kThumbnailCacheVersion) : QString{};
        QFile cached(target);
        if (cacheEnabled && cached.open(QIODevice::ReadOnly)) {
            const QByteArray jpeg = cached.read(kMaxThumbnailJpegBytes + 1);
            if (jpeg.size() <= kMaxThumbnailJpegBytes && jpeg.startsWith("\xff\xd8"))
                return jpeg;
        }
        if ((requireCache && !prewarm) || (!jpegSource && !ready))
            return {};

        QByteArray jpeg;
        if (jpegSource) {
            QImageReader reader(file.absoluteFilePath(), "jpeg");
            jpeg = encodeGridImage(readGridImage(reader));
        } else {
            const int extractTimeoutMs = requireCache ? 3000 : 8000;
            const QString filePath = file.absoluteFilePath();
            int edge = 0;
            for (const auto& tag : {QStringLiteral("-PreviewImage"),
                                    QStringLiteral("-JpgFromRaw"),
                                    QStringLiteral("-ThumbnailImage")}) {
                if (edge >= kThumbnailEdge)
                    break;
                int previewEdge = 0;
                auto preview = gridThumbnail(support->previewPool.extract(tag, filePath, extractTimeoutMs),
                                             &previewEdge);
                if (!preview.isEmpty() && previewEdge > edge) {
                    jpeg = std::move(preview);
                    edge = previewEdge;
                }
            }
        }
        if (jpeg.isEmpty() || jpeg.size() > kMaxThumbnailJpegBytes)
            return {};

        const QFileInfo now(file.absoluteFilePath());
        if (now.size() != size || now.lastModified() != modified)
            return {};
        if (!cacheEnabled)
            return jpeg;
        const QStorageInfo disk(cacheRoot);
        if (!disk.isValid() || disk.bytesAvailable() < kMinThumbnailFreeBytes ||
            !QDir().mkpath(shard.absolutePath()))
            return jpeg;
        QLockFile lock(shard.filePath(QStringLiteral(".write.lock")));
        if (!lock.tryLock(prewarm ? 100 : 0))
            return jpeg;
        // Retire the old format under the existing shard lock and budget.
        QFile::remove(legacy);
        const auto entries = shard.entryInfoList({QStringLiteral("*.jpg")}, QDir::Files,
                                                 QDir::Time | QDir::Reversed);
        qint64 bytes = jpeg.size();
        for (const QFileInfo& entry : entries)
            if (entry.absoluteFilePath() != target && entry.absoluteFilePath() != previous)
                bytes += entry.size();
        if (prewarm && bytes > shardBytes)
            return jpeg;
        for (const QFileInfo& entry : entries) {
            if (bytes <= shardBytes)
                break;
            if (entry.absoluteFilePath() != target && entry.absoluteFilePath() != previous &&
                QFile::remove(entry.absoluteFilePath()))
                bytes -= entry.size();
        }
        if (bytes <= shardBytes) {
            QSaveFile output(target);
            if (output.open(QIODevice::WriteOnly) && output.write(jpeg) == jpeg.size() &&
                output.commit()) {
                if (!previous.isEmpty())
                    QFile::remove(previous);
                writes->fetch_add(1);
            }
        }
        return jpeg;
    };
}

bool PhotoModule::deleteContext(const QString& directory, QJsonObject* out, QString* error) {
    if (!m_readRepo) { if (error) *error = QStringLiteral("base non ouverte"); return false; }
    if (matchingRoot(directory).isEmpty()) {
        if (error) *error = QStringLiteral("le dossier %1 n'est sous aucune racine autorisee").arg(directory);
        return false;
    }
    // Source endormie : sonde bornée avant de toucher le montage (voir putContext).
    if (!probeAccessible(directory, m_probeTimeoutMs)) {
        if (error) *error = QStringLiteral("source injoignable (endormie ou deconnectee ?) : "
                                           "impossible de retirer le contexte de %1").arg(directory);
        return false;
    }
    QString rerr;
    if (!ContextFile::remove(directory, &rerr)) {
        if (error) *error = QStringLiteral("suppression du contexte impossible: %1").arg(rerr);
        return false;
    }
    m_readRepo->deleteContextRow(directory);
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    if (out) *out = m_readRepo->getContext(directory);   // status:"unqualified"
    return true;
}

// --- Dossiers ---------------------------------------------------------------

QJsonArray PhotoModule::listFolders() const {
    PhotoRepository* repo = readRepo();
    return repo ? repo->listFoldersDetail() : QJsonArray{};
}

QJsonArray PhotoModule::allowedRoots() const {
    QStringList roots;
    {
        QMutexLocker lock(&m_stateMutex);
        roots = m_roots;
    }
    QJsonArray arr;
    for (const QString& root : roots)
        arr.append(root);
    return arr;
}

QString PhotoModule::matchingRoot(const QString& path) const {
    QStringList roots;
    {
        QMutexLocker lock(&m_stateMutex);
        roots = m_roots;
    }
    for (const QString& root : roots)
        if (isWithinRoots(path, {root}))
            return root;
    return {};
}

// --- Sources SMB poussées ---------------------------------------------------

bool PhotoModule::addSource(const QString& host, const QString& share, const QString& username,
                            const QString& password, const QString& hostname, bool writable,
                            QJsonObject* out, QString* error) {
    QJsonObject src;
    QString err;
    if (!m_sourceManager.addSource(host, share, username, password, hostname, writable, &src, &err)) {
        if (error) *error = err;
        if (out) *out = src;
        return false;
    }
    const QString mp = src.value(QStringLiteral("mountpoint")).toString();
    std::shared_ptr<ThumbnailSupport> support;
    {
        QMutexLocker lock(&m_stateMutex);
        if (!m_roots.contains(mp))
            m_roots << mp;
        support = m_thumbnailSupport;
    }
    if (support)
        support->clearDirCache();
    // Reactiver une selection eventuellement desactivee avant que la racine existe.
    // Pas d'indexation automatique : PhotoHub la declenche apres choix du dossier.
    reconcileRoots();
    // Redemarrage APRES la reponse HTTP, uniquement si morfphoto.json a change :
    // le client doit voir le service recharger vraiment la racine. Si la config
    // etait deja correcte, on evite un redemarrage inutile.
    if (src.value(QStringLiteral("restart_needed")).toBool()) {
        QTimer::singleShot(1500, this, [this]() {
            m_sourceManager.scheduleServiceRestart();
        });
    }
    if (out) *out = src;
    return true;
}

QJsonArray PhotoModule::listSources() const {
    // `mounted` ne dit que « le point de montage existe » : un montage soft survit a la
    // mort de la machine source. `reachable` ajoute une sonde BORNEE (m_probeTimeoutMs,
    // jamais un statvfs nu qui figerait ~180 s) pour reperer une source eteinte ou dont
    // l'adresse a change, et laisser PhotoHub proposer de reconfigurer l'acces.
    QJsonArray out;
    for (const QJsonValue& v : m_sourceManager.listSources()) {
        QJsonObject o = v.toObject();
        const QString mp = o.value(QStringLiteral("mountpoint")).toString();
        o[QStringLiteral("reachable")] = o.value(QStringLiteral("mounted")).toBool()
            && !mp.isEmpty() && probeAccessible(mp, m_probeTimeoutMs);
        out.append(o);
    }
    return out;
}

bool PhotoModule::helperReady(QJsonObject* out, QString* error) const {
    return m_sourceManager.helperReady(out, error);
}

bool PhotoModule::addFolder(const QString& path, const QVariant& label, bool recursive,
                            bool removable, const QVariant& volumeLabel,
                            QJsonObject* out, QString* error) {
    // Validation « sous racine » : règle de sécurité, portée par le métier, donc
    // valable quelle que soit la porte (y compris une requête HTTP forgée).
    const QString root = matchingRoot(path);
    if (root.isEmpty()) {
        if (error) *error = QStringLiteral("le dossier %1 n'est sous aucune racine autorisee").arg(path);
        return false;
    }
    if (!m_readRepo) { if (error) *error = QStringLiteral("base non ouverte"); return false; }

    // Le chemin est UNIQUE. S'il est déjà connu, ne pas échouer bêtement sur la
    // contrainte : un chemin retiré se restaure, un chemin déjà surveillé est
    // signalé tel quel (message clair plutôt qu'« insertion impossible »).
    bool deleted = false;
    const int existing = m_readRepo->folderIdByPath(path, &deleted);
    if (existing >= 0) {
        if (!deleted) {
            if (error) *error = QStringLiteral("le dossier %1 est deja surveille").arg(path);
            return false;
        }
        // Ré-ajout d'un chemin retiré : le restaurer, puis réappliquer les réglages
        // de support demandés (l'utilisateur peut le re-déclarer amovible et nommer
        // son volume au passage).
        if (!restoreFolder(existing, out))
            return false;
        m_readRepo->setFolderMedia(existing, removable, volumeLabel);
        m_writeEpoch.fetch_add(1, std::memory_order_release);
        if (out) *out = findById(m_readRepo->listFoldersDetail(), existing);
        refreshWatcher();
        return true;
    }

    const int id = m_readRepo->addFolder(path, root, label, recursive, removable, volumeLabel, nowIso());
    if (id < 0) { if (error) *error = QStringLiteral("insertion impossible"); return false; }
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    if (out) *out = findById(m_readRepo->listFoldersDetail(), id);
    refreshWatcher();
    return true;
}

bool PhotoModule::setFolderEnabled(int folderId, bool enabled, QJsonObject* out) {
    if (!m_readRepo || !m_readRepo->getFolder(folderId))
        return false;
    m_readRepo->setFolderEnabled(folderId, enabled);
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    if (out) *out = findById(m_readRepo->listFoldersDetail(), folderId);
    refreshWatcher();
    return true;
}

bool PhotoModule::setFolderMedia(int folderId, bool removable, const QVariant& volumeLabel,
                                 QJsonObject* out) {
    if (!m_readRepo || !m_readRepo->getFolder(folderId))
        return false;
    m_readRepo->setFolderMedia(folderId, removable, volumeLabel);
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    if (out) *out = findById(m_readRepo->listFoldersDetail(), folderId);
    return true;
}

bool PhotoModule::setFolderAnalyticsExcluded(int folderId, bool excluded, QJsonObject* out) {
    if (!m_readRepo || !m_readRepo->getFolder(folderId))
        return false;
    m_readRepo->setFolderAnalyticsExcluded(folderId, excluded);
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    if (out) *out = findById(m_readRepo->listFoldersDetail(), folderId);
    return true;
}

QJsonObject PhotoModule::purge(const QString& scope, const QVariant& value) {
    QJsonObject o;
    o["scope"] = scope;
    if (!m_readRepo) {
        o["error"] = QStringLiteral("base non ouverte");
        return o;
    }
    // Une passe pourrait écrire pendant qu'on efface : refuser la purge tant qu'une
    // indexation tourne (garde simple, cohérente avec « une seule passe à la fois »).
    {
        QMutexLocker lock(&m_stateMutex);
        if (m_indexing) {
            o["error"] = QStringLiteral("indexation en cours, reessayer apres la passe");
            return o;
        }
    }
    int deleted = 0;
    if (scope == QLatin1String("folder")) {
        bool ok = false;
        const int id = value.toInt(&ok);
        if (!ok) { o["error"] = QStringLiteral("id de dossier invalide"); return o; }
        deleted = m_readRepo->purgeFolder(id);
    } else if (scope == QLatin1String("year")) {
        bool ok = false;
        const int year = value.toInt(&ok);
        if (!ok) { o["error"] = QStringLiteral("annee invalide"); return o; }
        deleted = m_readRepo->purgeByYear(year);
    } else if (scope == QLatin1String("camera")) {
        const QString cam = value.toString();
        if (cam.isEmpty()) { o["error"] = QStringLiteral("boitier vide"); return o; }
        deleted = m_readRepo->purgeByCamera(cam);
    } else if (scope == QLatin1String("all")) {
        deleted = m_readRepo->purgeAll();
    } else {
        o["error"] = QStringLiteral("portee inconnue: %1").arg(scope);
        return o;
    }
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    o["deleted"] = deleted;
    refreshWatcher();
    return o;
}

bool PhotoModule::removeFolder(int folderId) {
    if (!m_readRepo || !m_readRepo->getFolder(folderId))
        return false;
    // Retrait DOUX : historique conservé, sélection désactivée (voir contrat).
    m_readRepo->softDeleteFolder(folderId, nowIso());
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    refreshWatcher();
    return true;
}

bool PhotoModule::restoreFolder(int folderId, QJsonObject* out) {
    if (!m_readRepo || !m_readRepo->getFolder(folderId))
        return false;
    m_readRepo->restoreFolder(folderId);
    m_writeEpoch.fetch_add(1, std::memory_order_release);
    refreshWatcher();
    if (out) *out = findById(m_readRepo->listFoldersDetail(), folderId);
    // Raviver les fichiers tout de suite plutôt que d'attendre la passe périodique.
    triggerIndex(IndexMode::Incremental, {folderId}, QStringLiteral("restore"));
    return true;
}

void PhotoModule::reconcileRoots() {
    if (!m_readRepo)
        return;
    QStringList roots;
    {
        QMutexLocker lock(&m_stateMutex);
        roots = m_roots;
    }
    const QStringList normalizedRoots = normalizeRoots(roots);
    bool changed = false;
    const QJsonArray folders = m_readRepo->listFoldersDetail();
    for (const QJsonValue& v : folders) {
        const QJsonObject f = v.toObject();
        const int id = f.value(QStringLiteral("id")).toInt();
        const QString path = f.value(QStringLiteral("path")).toString();
        const bool enabled = f.value(QStringLiteral("enabled")).toInt() == 1;
        const bool autoDisabled = f.value(QStringLiteral("auto_disabled")).toInt() == 1;
        const bool covered = isPathWithinNormalizedRoots(normalizePath(path), normalizedRoots);
        if (!covered && enabled) {
            m_readRepo->setFolderAutoDisabled(id, true);
            changed = true;
        } else if (covered && autoDisabled) {
            m_readRepo->setFolderAutoDisabled(id, false);
            changed = true;
        }
    }
    if (changed)
        m_writeEpoch.fetch_add(1, std::memory_order_release);
}

// --- /modules ---------------------------------------------------------------

QJsonObject PhotoModule::statusJson() const {
    QJsonObject o = observableState();
    PhotoRepository* repo = readRepo();
    if (repo && repo->isOpen()) {
        const QJsonObject s = repo->statusCounts();
        o["files_present"]  = s.value(QStringLiteral("files_present"));
        o["files_missing"]  = s.value(QStringLiteral("files_missing"));
        o["folders_active"] = s.value(QStringLiteral("folders_active"));

        // Verdict de la dernière passe, en compact : done|interrupted|null. Permet à
        // morfMonitor de distinguer une indexation terminée normalement d'une passe
        // interrompue par une source indisponible, sans parser tout `last_run`.
        bool found = false;
        const QJsonObject run = repo->latestRun(&found);
        o["last_index_state"] = found ? run.value(QStringLiteral("state"))
                                      : QJsonValue(QJsonValue::Null);
    }
    return o;
}

} // namespace morfphoto
