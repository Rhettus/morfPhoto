/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/FolderWatcher.h"
#include "morfphoto/ContextFile.h"
#include "morfphoto/LibraryMetadata.h"
#include "morfphoto/PhotoScanner.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutexLocker>
#include <QSocketNotifier>
#include <QTimer>

#ifdef Q_OS_LINUX
#include <cerrno>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#endif

namespace morfphoto {

namespace {
// Un import continu ne doit pas repousser indefiniment la mise a jour.
constexpr int kMaxDebounceFactor = 10;
// Une racine disparue ou remontee est retrouvee a ce rythme.
constexpr int kRearmIntervalMs = 60000;

#ifdef Q_OS_LINUX
// IN_CLOSE_WRITE plutot que IN_CREATE pour les fichiers : une photo n'est lue
// qu'une fois sa copie terminee.
constexpr quint32 kWatchMask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE
                             | IN_CREATE | IN_MOVE_SELF | IN_ONLYDIR;

// Sur un montage reseau, inotify ignore ce que les autres machines modifient.
bool isRemoteFilesystem(const QString& path) {
    struct statfs fs {};
    if (statfs(QFile::encodeName(path).constData(), &fs) != 0)
        return false;
    const auto type = static_cast<unsigned long>(fs.f_type);
    return type == 0xFF534D42UL   // CIFS
        || type == 0xFE534D42UL   // SMB2
        || type == 0x517BUL       // SMB
        || type == 0x6969UL;      // NFS
}

bool isRelevantFile(const QString& name) {
    if (name == ContextFile::fileName())
        return true;
    // Le scanner ignore les fichiers caches : inutile de declencher une passe pour eux.
    if (name.startsWith(QLatin1Char('.')))
        return false;
    const QString extension = QLatin1Char('.') + QFileInfo(name).suffix().toLower();
    return fileTypeFor(extension) != QLatin1String("other") || extension == QLatin1String(".xmp")
        || isExtendedImageExtension(extension);
}

bool isCoveredByTargets(const QString& dir, const QVector<WatchTarget>& targets) {
    for (const WatchTarget& target : targets) {
        if (dir == target.path)
            return true;
        if (target.recursive && isSubpathOf(dir, target.path))
            return true;
    }
    return false;
}
#endif
} // namespace

bool FolderWatcher::isIgnoredDirectoryName(const QString& name) {
    if (name.startsWith(QLatin1Char('.')))
        return true;
    static const QSet<QString> kExactIgnored = {
        QStringLiteral("@eaDir"),
        QStringLiteral("@Recycle"),
        QStringLiteral("@tmp"),
        QStringLiteral("#recycle"),
        QStringLiteral("#snapshot"),
        QStringLiteral("lost+found"),
    };
    if (kExactIgnored.contains(name))
        return true;
    return name.compare(QStringLiteral("$RECYCLE.BIN"), Qt::CaseInsensitive) == 0
        || name.compare(QStringLiteral("System Volume Information"), Qt::CaseInsensitive) == 0;
}

FolderWatcher::FolderWatcher(int debounceMs, int probeTimeoutMs, QObject* parent)
    : QObject(parent),
      m_debounceMs(debounceMs),
      m_probeTimeoutMs(probeTimeoutMs),
      m_debounce(new QTimer(this)),
      m_rearm(new QTimer(this)) {
    qRegisterMetaType<morfphoto::IndexScope>();
    qRegisterMetaType<QVector<morfphoto::IndexScope>>();
    m_debounce->setSingleShot(true);
    connect(m_debounce, &QTimer::timeout, this, &FolderWatcher::flush);
    m_rearm->setInterval(kRearmIntervalMs);
    connect(m_rearm, &QTimer::timeout, this, &FolderWatcher::rearm);
#ifndef Q_OS_LINUX
    m_state = QStringLiteral("unsupported");
#endif
}

FolderWatcher::~FolderWatcher() {
#ifdef Q_OS_LINUX
    delete m_notifier;
    if (m_fd >= 0)
        ::close(m_fd);
#endif
}

QJsonObject FolderWatcher::statusJson() const {
    QMutexLocker lock(&m_statusMutex);
    QJsonObject o;
    o["state"]   = m_state;
    o["watches"] = m_watchCount;
    o["detail"]  = m_detail.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(m_detail);
    return o;
}

void FolderWatcher::publishStatus() {
    QStringList notes;
    if (m_limitReached)
        notes << QStringLiteral("limite fs.inotify.max_user_watches atteinte : surveillance partielle");
    if (!m_skipped.isEmpty())
        notes << QStringLiteral("montage reseau non surveille : %1")
                     .arg(QStringList(m_skipped.values()).join(QStringLiteral(", ")));

    QMutexLocker lock(&m_statusMutex);
    m_watchCount = m_wdToPath.size();
    m_state  = m_fd < 0 ? QStringLiteral("error")
             : m_limitReached ? QStringLiteral("limit_reached")
                              : QStringLiteral("active");
    m_detail = notes.join(QStringLiteral(" ; "));
}

#ifdef Q_OS_LINUX

void FolderWatcher::setTargets(const QVector<WatchTarget>& targets) {
    if (m_fd < 0) {
        m_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (m_fd < 0) {
            publishStatus();
            return;
        }
        m_notifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
        connect(m_notifier, &QSocketNotifier::activated, this, &FolderWatcher::onReadable);
    }

    QVector<WatchTarget> cleaned = targets;
    for (WatchTarget& target : cleaned)
        target.path = QDir::cleanPath(target.path);

    using TargetKey = QPair<QString, bool>;
    QSet<TargetKey> oldKeys;
    oldKeys.reserve(m_targets.size());
    for (const WatchTarget& t : std::as_const(m_targets))
        oldKeys.insert(qMakePair(t.path, t.recursive));

    QSet<TargetKey> newKeys;
    newKeys.reserve(cleaned.size());
    for (const WatchTarget& t : std::as_const(cleaned))
        newKeys.insert(qMakePair(t.path, t.recursive));

    if (oldKeys == newKeys && !m_limitReached) {
        m_targets = std::move(cleaned);
        if (!m_rearm->isActive())
            m_rearm->start();
        publishStatus();
        return;
    }

    QHash<QString, bool> oldByPath;
    for (const WatchTarget& t : std::as_const(m_targets))
        oldByPath[t.path] = oldByPath.value(t.path, false) || t.recursive;

    QHash<QString, bool> newByPath;
    for (const WatchTarget& t : std::as_const(cleaned))
        newByPath[t.path] = newByPath.value(t.path, false) || t.recursive;

    bool hasRemovalsOrDowngrades = false;
    for (auto it = oldByPath.constBegin(); it != oldByPath.constEnd(); ++it) {
        const auto newIt = newByPath.constFind(it.key());
        if (newIt == newByPath.constEnd() || (it.value() && !newIt.value())) {
            hasRemovalsOrDowngrades = true;
            break;
        }
    }

    const bool hadLimitReached = m_limitReached;
    m_targets = std::move(cleaned);

    if (hasRemovalsOrDowngrades) {
        bool removedAnyWatch = false;
        const QStringList known = m_pathToWd.keys();
        for (const QString& dir : known) {
            if (!isCoveredByTargets(dir, m_targets)) {
                const int wd = m_pathToWd.take(dir);
                m_wdToPath.remove(wd);
                inotify_rm_watch(m_fd, wd);
                removedAnyWatch = true;
            }
        }
        for (auto it = m_rootIds.begin(); it != m_rootIds.end();) {
            if (!newByPath.contains(it.key()))
                it = m_rootIds.erase(it);
            else
                ++it;
        }
        for (auto it = m_skipped.begin(); it != m_skipped.end();) {
            if (!newByPath.contains(*it))
                it = m_skipped.erase(it);
            else
                ++it;
        }
        if (removedAnyWatch)
            m_limitReached = false;
    }

    for (const WatchTarget& target : std::as_const(m_targets)) {
        const bool wasKnown = oldByPath.contains(target.path);
        const bool wasRecursive = oldByPath.value(target.path, false);
        const bool isUpgraded = wasKnown && !wasRecursive && target.recursive;
        const bool isMissed = !m_pathToWd.contains(target.path) && !m_skipped.contains(target.path);
        const bool retryPartialAfterLimit = hadLimitReached && !m_limitReached && target.recursive;
        if (!wasKnown || isUpgraded || isMissed || retryPartialAfterLimit)
            armTarget(target);
    }

    if (!m_rearm->isActive())
        m_rearm->start();
    publishStatus();
}

void FolderWatcher::armTarget(const WatchTarget& target) {
    // Sonde bornee d'abord : un statfs nu resterait fige sur un montage mort.
    if (!probeAccessible(target.path, m_probeTimeoutMs))
        return;
    if (isRemoteFilesystem(target.path)) {
        m_skipped.insert(target.path);
        return;
    }
    struct stat st {};
    if (stat(QFile::encodeName(target.path).constData(), &st) != 0)
        return;
    m_rootIds.insert(target.path, qMakePair(quint64(st.st_dev), quint64(st.st_ino)));
    addTree(target.path, target.recursive);
}

void FolderWatcher::rearm() {
    for (const WatchTarget& target : std::as_const(m_targets)) {
        if (m_skipped.contains(target.path) || !probeAccessible(target.path, m_probeTimeoutMs))
            continue;
        struct stat st {};
        if (stat(QFile::encodeName(target.path).constData(), &st) != 0)
            continue;
        const auto id = qMakePair(quint64(st.st_dev), quint64(st.st_ino));
        if (m_pathToWd.contains(target.path) && m_rootIds.value(target.path) == id)
            continue;
        // Racine revenue ou remontee. Surtout PAS de passe ici : un point de montage
        // vide ferait marquer disparue toute la phototheque.
        removeTree(target.path);
        armTarget(target);
    }
    publishStatus();
}

bool FolderWatcher::addWatch(const QString& path) {
    if (m_pathToWd.contains(path))
        return true;
    if (m_limitReached)
        return false;
    const int wd = inotify_add_watch(m_fd, QFile::encodeName(path).constData(), kWatchMask);
    if (wd < 0) {
        if (errno == ENOSPC)
            m_limitReached = true;
        return false;
    }
    m_wdToPath.insert(wd, path);
    m_pathToWd.insert(path, wd);
    return true;
}

void FolderWatcher::addTree(const QString& path, bool recursive) {
    if (!addWatch(path) || !recursive)
        return;
    QStringList stack{path};
    while (!stack.isEmpty() && !m_stop && !m_limitReached) {
        const QString cur = stack.takeLast();
        const QFileInfoList entries = QDir(cur).entryInfoList(
            QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks);
        for (const QFileInfo& entry : entries) {
            if (m_stop || m_limitReached)
                return;
            if (isIgnoredDirectoryName(entry.fileName()))
                continue;
            const QString child = entry.filePath();
            if (addWatch(child))
                stack.push_back(child);
        }
    }
}

void FolderWatcher::removeTree(const QString& path) {
    const QString prefix = path + QLatin1Char('/');
    const QStringList known = m_pathToWd.keys();
    for (const QString& candidate : known) {
        if (candidate != path && !candidate.startsWith(prefix))
            continue;
        const int wd = m_pathToWd.take(candidate);
        m_wdToPath.remove(wd);
        inotify_rm_watch(m_fd, wd);
    }
}

void FolderWatcher::onReadable() {
    alignas(struct inotify_event) char buffer[64 * 1024];
    for (;;) {
        const ssize_t size = ::read(m_fd, buffer, sizeof(buffer));
        if (size <= 0)
            break;
        for (char* p = buffer; p < buffer + size;) {
            const auto* event = reinterpret_cast<const struct inotify_event*>(p);
            handleEvent(event->wd, event->mask,
                        event->len ? QFile::decodeName(event->name) : QString());
            p += sizeof(struct inotify_event) + event->len;
        }
    }
    publishStatus();
}

void FolderWatcher::handleEvent(int wd, quint32 mask, const QString& name) {
    if (mask & IN_Q_OVERFLOW) {
        // Des evenements sont perdus : seule une passe sur tout le perimetre est sure.
        QVector<IndexScope> all;
        all.reserve(m_targets.size());
        for (const WatchTarget& target : std::as_const(m_targets))
            all.push_back({target.folderId, target.path, target.recursive});
        markDirty(all);
        return;
    }
    if (mask & IN_IGNORED) {
        const QString path = m_wdToPath.take(wd);
        if (!path.isEmpty() && m_pathToWd.value(path) == wd)
            m_pathToWd.remove(path);
        return;
    }
    // Un demontage n'est pas une suppression : il ne declenche jamais de passe.
    if (mask & IN_UNMOUNT)
        return;

    const QString directory = m_wdToPath.value(wd);
    if (directory.isEmpty())
        return;
    if (mask & IN_MOVE_SELF) {
        // Le parent signale deja un sous-dossier deplace ; reste le cas d'une racine.
        for (const WatchTarget& target : std::as_const(m_targets))
            if (target.path == directory)
                removeTree(directory);
        return;
    }

    if (mask & IN_ISDIR) {
        if (name.isEmpty() || isIgnoredDirectoryName(name))
            return;
        const QVector<int> folders = foldersFor(directory, /*recursiveOnly=*/true);
        if (folders.isEmpty())
            return;
        const QString path = directory == QLatin1String("/")
            ? (QLatin1Char('/') + name)
            : (directory + QLatin1Char('/') + name);
        if (mask & (IN_MOVED_FROM | IN_DELETE))
            removeTree(path);
        else if (mask & (IN_CREATE | IN_MOVED_TO))
            addTree(path, true);
        QVector<IndexScope> scopes;
        scopes.reserve(folders.size());
        for (int id : folders)
            scopes.push_back({id, path, /*recursive=*/true});
        markDirty(scopes);
        return;
    }

    if ((mask & IN_CREATE) || !isRelevantFile(name))
        return;
    const QVector<int> folders = foldersFor(directory, /*recursiveOnly=*/false);
    QVector<IndexScope> scopes;
    scopes.reserve(folders.size());
    for (int id : folders)
        scopes.push_back({id, directory, /*recursive=*/false});
    markDirty(scopes);
}

#else

void FolderWatcher::setTargets(const QVector<WatchTarget>&) {}
void FolderWatcher::armTarget(const WatchTarget&) {}
void FolderWatcher::rearm() {}
bool FolderWatcher::addWatch(const QString&) { return false; }
void FolderWatcher::addTree(const QString&, bool) {}
void FolderWatcher::removeTree(const QString&) {}
void FolderWatcher::onReadable() {}
void FolderWatcher::handleEvent(int, quint32, const QString&) {}

#endif

QVector<int> FolderWatcher::foldersFor(const QString& directory, bool recursiveOnly) const {
    QVector<int> ids;
    for (const WatchTarget& target : m_targets) {
        const bool below = directory.startsWith(target.path + QLatin1Char('/'));
        if (target.recursive ? (directory == target.path || below)
                             : (!recursiveOnly && directory == target.path))
            ids << target.folderId;
    }
    return ids;
}

void FolderWatcher::markDirty(const QVector<IndexScope>& scopes) {
    if (scopes.isEmpty())
        return;
    for (const IndexScope& scope : scopes)
        mergeScope(m_dirty, scope);
    if (!m_firstDirty.isValid())
        m_firstDirty.start();
    if (m_firstDirty.elapsed() >= qint64(m_debounceMs) * kMaxDebounceFactor)
        flush();
    else
        m_debounce->start(m_debounceMs);
}

void FolderWatcher::flush() {
    m_debounce->stop();
    m_firstDirty.invalidate();
    if (m_dirty.isEmpty())
        return;
    const QVector<IndexScope> scopes = m_dirty;
    m_dirty.clear();
    emit scopesChanged(scopes);
}

} // namespace morfphoto
