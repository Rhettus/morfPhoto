/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once
#include "morfphoto/PhotoTypes.h"

#include <QObject>
#include <QElapsedTimer>
#include <QHash>
#include <QJsonObject>
#include <QMutex>
#include <QPair>
#include <QSet>
#include <QString>
#include <QVector>

#include <atomic>

class QSocketNotifier;
class QTimer;

// -----------------------------------------------------------------------------
// FolderWatcher : signale, via inotify, les selections dont le contenu a change.
//
// Il ne touche ni a la base ni a l'indexation : il dit seulement QUELLES selections
// meritent une passe, et PhotoModule declenche la passe incrementale habituelle.
//
// Prevu pour vivre sur son propre QThread : poser les watches sur une grande
// arborescence prend du temps et ne doit pas figer le thread HTTP.
// Linux uniquement ; ailleurs, l'objet reste inerte (etat "unsupported").
// -----------------------------------------------------------------------------
namespace morfphoto {

struct WatchTarget {
    int     folderId  = 0;
    QString path;
    bool    recursive = true;
};

class FolderWatcher : public QObject {
    Q_OBJECT
public:
    FolderWatcher(int debounceMs, int probeTimeoutMs, QObject* parent = nullptr);
    ~FolderWatcher() override;

    // Remplace les selections surveillees. A appeler dans le thread du watcher.
    void setTargets(const QVector<WatchTarget>& targets);

    // Repertoires ignores (caches `.` ou metadonnees NAS/OS).
    static bool isIgnoredDirectoryName(const QString& name);

    // Interrompt un parcours en cours. Appelable depuis n'importe quel thread.
    void requestStop() { m_stop = true; }

    // { state, watches, detail }. Appelable depuis n'importe quel thread.
    QJsonObject statusJson() const;

signals:
    void scopesChanged(const QVector<IndexScope>& scopes);

private:
    void onReadable();
    void handleEvent(int wd, quint32 mask, const QString& name);
    void armTarget(const WatchTarget& target);
    void rearm();
    void addTree(const QString& path, bool recursive);
    bool addWatch(const QString& path);
    void removeTree(const QString& path);
    QVector<int> foldersFor(const QString& directory, bool recursiveOnly) const;
    void markDirty(const QVector<IndexScope>& scopes);
    void flush();
    void publishStatus();

    int m_debounceMs;
    int m_probeTimeoutMs;
    int m_fd = -1;
    std::atomic_bool m_stop{false};

    QSocketNotifier* m_notifier = nullptr;
    QTimer*          m_debounce = nullptr;
    QTimer*          m_rearm    = nullptr;

    QVector<WatchTarget>  m_targets;
    QHash<int, QString>   m_wdToPath;
    QHash<QString, int>   m_pathToWd;
    QHash<QString, QPair<quint64, quint64>> m_rootIds;   // (device, inode) de chaque racine armee
    QSet<QString>         m_skipped;                     // montages reseau : inotify n'y voit rien
    bool                  m_limitReached = false;

    QVector<IndexScope> m_dirty;
    QElapsedTimer m_firstDirty;

    mutable QMutex m_statusMutex;
    QString m_state = QStringLiteral("idle");
    QString m_detail;
    int     m_watchCount = 0;
};

} // namespace morfphoto
