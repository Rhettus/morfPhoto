/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once
#include <QObject>
#include <QElapsedTimer>
#include <QByteArray>
#include <QThreadPool>
#include "morfphoto/ServiceConfig.h"

class QTcpServer;
class QTcpSocket;
class QNetworkAccessManager;

namespace morfphoto {

class ModuleRegistry;

// -----------------------------------------------------------------------------
// HttpServer : serveur HTTP/1.1 minimal, gerant GET *et* POST (avec corps).
//
// Routes fournies (a ADAPTER selon votre metier) :
//   GET  /status        -> compatible morfBeacon (app, version, uptime, metrics)
//   GET  /healthz       -> { "status": "ok" }
//   GET  /modules       -> etat de tous les modules
//   GET  /modules/{id}  -> etat d'un module
// -----------------------------------------------------------------------------
class HttpServer : public QObject {
    Q_OBJECT
public:
    HttpServer(ServiceConfig config, ModuleRegistry* registry, QObject* parent = nullptr);
    ~HttpServer() override;

    bool start();
    void stop();
    bool isListening() const;
    quint16 port() const;

private:
    void onNewConnection();
    void onSocketReadyRead(QTcpSocket* sock);
    void handleRequest(QTcpSocket* sock, const QByteArray& method,
                       const QByteArray& path, const QByteArray& body);
    void serveThumbnail(QTcpSocket* sock, const QByteArray& method,
                        const QString& queryString, bool requireCache);
    QByteArray buildStatusJson() const;
    void reply(QTcpSocket* sock, int code, const QByteArray& reason, const QByteArray& body,
               const QByteArray& contentType = QByteArrayLiteral("application/json; charset=utf-8"),
               bool allowCors = false, const QByteArray& extraHeaders = {});

    ServiceConfig          m_config;
    QByteArray             m_apiKey;
    ModuleRegistry*        m_registry;
    QTcpServer*            m_server;
    QNetworkAccessManager* m_proxyManager = nullptr;
    QElapsedTimer          m_uptime;
    QThreadPool            m_apiReadPool;
    QThreadPool            m_thumbnailPool;
    int                    m_thumbnailRequests = 0;
    QThreadPool            m_cachedThumbnailPool;
    int                    m_cachedThumbnailRequests = 0;
    int                    m_semanticRequests = 0;
};

} // namespace morfphoto
