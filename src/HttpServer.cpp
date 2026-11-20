/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/HttpServer.h"
#include "morfphoto/ApiAuth.h"
#include "morfphoto/OriginCheck.h"
#include "morfphoto/ModuleRegistry.h"
#include "morfphoto/SelfDescription.h"
#include "morfphoto/Version.h"
#include "morfphoto/PhotoApi.h"
#include "morfphoto/PhotoModule.h"

#include <QTcpServer>
#include <QTimer>
#include <QTcpSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QDateTime>
#include <QUrl>
#include <QUrlQuery>
#include <QFutureWatcher>
#include <QPointer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkProxy>
#include <QtConcurrent>

#include <utility>

namespace morfphoto {

namespace {
constexpr int kMaxRequestBytes = 65536;

QByteArray toJson(const QJsonObject& o) {
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

int contentLength(const QByteArray& headerBlock) {
    for (const QByteArray& line : headerBlock.split('\n')) {
        const QByteArray l = line.trimmed();
        if (l.toLower().startsWith("content-length:"))
            return l.mid(l.indexOf(':') + 1).trimmed().toInt();
    }
    return 0;
}

// Libellé HTTP pour les codes que l'API photo peut renvoyer (au-delà de 200/404).
QByteArray reasonFor(int code) {
    switch (code) {
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default:  return "OK";
    }
}
} // namespace

HttpServer::HttpServer(ServiceConfig config, ModuleRegistry* registry, QObject* parent)
    : QObject(parent),
      m_config(std::move(config)),
      m_registry(registry),
      m_server(new QTcpServer(this)) {
    connect(m_server, &QTcpServer::newConnection, this, &HttpServer::onNewConnection);
    // L'environnement prime : un secret de conteneur n'a pas a vivre dans un fichier.
    m_thumbnailPool.setMaxThreadCount(2);
    const QString envKey = qEnvironmentVariable("MORFPHOTO_API_KEY").trimmed();
    m_apiKey = (envKey.isEmpty() ? m_config.apiKey.trimmed() : envKey).toUtf8();
}

HttpServer::~HttpServer() = default;

bool HttpServer::start() {
    if (m_config.httpPort == 0)
        return false;
    m_uptime.start();
    QHostAddress addr(m_config.bindAddress);
    if (addr.isNull())
        addr = QHostAddress(QHostAddress::AnyIPv4);
    return m_server->listen(addr, m_config.httpPort);
}

void HttpServer::stop()            { m_server->close(); }
bool HttpServer::isListening() const { return m_server->isListening(); }
quint16 HttpServer::port() const   { return m_server->isListening() ? m_server->serverPort() : 0; }

void HttpServer::onNewConnection() {
    while (m_server->hasPendingConnections()) {
        QTcpSocket* sock = m_server->nextPendingConnection();
        connect(sock, &QTcpSocket::readyRead, this, [this, sock]() { onSocketReadyRead(sock); });
        connect(sock, &QTcpSocket::disconnected, sock, &QObject::deleteLater);
    }
}

void HttpServer::onSocketReadyRead(QTcpSocket* sock) {
    QByteArray buf = sock->property("buf").toByteArray();
    buf += sock->readAll();

    const int headerEnd = buf.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        if (buf.size() > kMaxRequestBytes) { sock->abort(); return; }
        sock->setProperty("buf", buf);
        return;
    }

    const QByteArray headerBlock = buf.left(headerEnd);
    const int needed = contentLength(headerBlock);
    const int bodyStart = headerEnd + 4;
    if (buf.size() - bodyStart < needed) {
        if (buf.size() > kMaxRequestBytes) { sock->abort(); return; }
        sock->setProperty("buf", buf);
        return;
    }

    const int lineEnd = buf.indexOf("\r\n");
    const QList<QByteArray> parts = buf.left(lineEnd).split(' ');
    const QByteArray method = parts.value(0);
    if (qEnvironmentVariableIntValue("MORFPHOTO_HTTP_DEBUG") == 1) {
        const QByteArray path = parts.value(1).split('?').value(0);
        const char* route = "other";
        if (path == "/healthz")
            route = "health";
        else if (path == "/api/v1/library/subfolders")
            route = "subfolders";
        else if (path == "/api/v1/library" || path.startsWith("/api/v1/library/"))
            route = "catalog";
        else if (path.startsWith("/api/v1/thumbnail"))
            route = "thumbnail";
        else if (path == "/api/v1/search/semantic")
            route = "semantic";
        else if (path == "/api/v1/index/status")
            route = "index-status";
        sock->setProperty("httpLogRoute", QString::fromLatin1(route));
        sock->setProperty("httpLogStartMs", m_uptime.elapsed());
    }


    // Anti-CSRF : une ecriture portant un Origin different de Host vient d'une page tierce.
    if (isCrossOriginWrite(method, headerValue(headerBlock, "Origin"),
                           headerValue(headerBlock, "Host"))) {
        sock->setProperty("buf", QByteArray());
        reply(sock, 403, reasonFor(403), "{\"error\":\"cross_origin_forbidden\"}",
              QByteArrayLiteral("application/json; charset=utf-8"), false);
        return;
    }
    const QByteArray path   = parts.value(1);
    const QByteArray body   = buf.mid(bodyStart, needed);

    sock->setProperty("buf", QByteArray());

    // Meme decoupe que handleRequest : la garde et le routage voient le meme chemin.
    const int query = path.indexOf('?');
    if (isApiPath(query < 0 ? path : path.left(query))
        && !isAuthorized(headerValue(headerBlock, "Authorization"), m_apiKey)) {
        reply(sock, 401, reasonFor(401), "{\"error\":\"unauthorized\"}",
              QByteArrayLiteral("application/json; charset=utf-8"), false,
              QByteArrayLiteral("WWW-Authenticate: Bearer\r\n"));
        return;
    }
    handleRequest(sock, method, path, body);
}

void HttpServer::handleRequest(QTcpSocket* sock, const QByteArray& method,
                               const QByteArray& rawPath, const QByteArray& body) {
    const int qpos = rawPath.indexOf('?');
    const QByteArray path = qpos < 0 ? rawPath : rawPath.left(qpos);
    const QString queryString = qpos < 0 ? QString() : QString::fromUtf8(rawPath.mid(qpos + 1));
    int        code   = 200;
    QByteArray reason = "OK";
    QByteArray out;

    if (path == "/api/v1/thumbnail" || path == "/api/v1/thumbnail/" ||
        path == "/api/v1/thumbnail/cached" || path == "/api/v1/thumbnail/cached/") {
        serveThumbnail(sock, method, queryString, path.contains("/cached"));
        return;
    }

    if (path == "/api/v1/search/semantic") {
        if (method != "POST") {
            reply(sock, 405, reasonFor(405), "{\"error\":\"method_not_allowed\"}");
            return;
        }
        if (qEnvironmentVariableIsEmpty("MORFPHOTO_CLIP_DIR")) {
            reply(sock, 404, reasonFor(404), "{\"error\":\"semantic_search_disabled\"}");
            return;
        }
        if (m_semanticRequests >= 2) {
            reply(sock, 503, reasonFor(503), "{\"error\":\"semantic_search_busy\"}");
            return;
        }
        ++m_semanticRequests;
        connect(sock, &QObject::destroyed, this, [this] { --m_semanticRequests; });
        disconnect(sock, &QTcpSocket::readyRead, this, nullptr);
        auto* manager = new QNetworkAccessManager(sock);
        manager->setProxy(QNetworkProxy::NoProxy);
        QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:8794/search")));
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
        request.setTransferTimeout(8000);
        auto* result = manager->post(request, body);
        connect(result, &QNetworkReply::finished, sock, [this, sock, result] {
            const int status = result->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const int code = status ? status : 503;
            const QByteArray payload = status ? result->readAll() :
                QByteArrayLiteral("{\"error\":\"semantic_search_unavailable\"}");
            reply(sock, code, reasonFor(code), payload);
        });
        return;
    }

    // ---- API metier /api/v1 : deleguee au domaine photo (PhotoApi) ----
    if (path.startsWith("/api/")) {
        IModule* mod = m_registry ? m_registry->firstOfType(QStringLiteral("photo")) : nullptr;
        PhotoApi api(qobject_cast<PhotoModule*>(mod));
        QElapsedTimer timer;
        timer.start();
        const PhotoApi::Result r = api.handle(method, QString::fromUtf8(path), queryString, body);
        const qint64 elapsedMs = timer.elapsed();
        if (method == "GET" &&
            (path == "/api/v1/library" || path.startsWith("/api/v1/library/")) &&
            elapsedMs >= 500) {
            qWarning() << "morfPhoto slow library request:" << elapsedMs << "ms, HTTP" << r.code;
        }
        reply(sock, r.code, reasonFor(r.code), r.body, r.contentType, method == "GET");
        return;
    }

    // ---- Routes GET ------------------------------------------------------
    if (method != "GET") {
        code = 405; reason = "Method Not Allowed";
        out = "{\"error\":\"method not allowed\"}";
    } else if (path == "/healthz") {
        out = "{\"status\":\"ok\"}";
    } else if (path == "/status") {
        out = buildStatusJson();
    } else if (path == "/modules") {
        QJsonObject o;
        o["modules"] = m_registry ? m_registry->modulesJson() : QJsonArray{};
        o["count"]   = m_registry ? m_registry->count() : 0;
        o["ts"]      = static_cast<double>(QDateTime::currentSecsSinceEpoch());
        out = toJson(o);
    } else if (path.startsWith("/modules/")) {
        const QString id = QUrl::fromPercentEncoding(path.mid(9));
        bool found = false;
        const QJsonObject o = m_registry ? m_registry->moduleJson(id, &found) : QJsonObject{};
        if (found) { out = toJson(o); }
        else { code = 404; reason = "Not Found"; out = "{\"error\":\"module not found\"}"; }
    } else {
        code = 404; reason = "Not Found";
        out = "{\"error\":\"not found\"}";
    }

    reply(sock, code, reason, out, QByteArrayLiteral("application/json; charset=utf-8"),
          method == "GET");
}

void HttpServer::serveThumbnail(QTcpSocket* sock, const QByteArray& method,
                                const QString& queryString, bool requireCache) {
    if (method != "GET") {
        reply(sock, 405, reasonFor(405), "{\"error\":\"method_not_allowed\"}");
        return;
    }
    const QString path = QUrlQuery(queryString).queryItemValue(QStringLiteral("path"), QUrl::FullyDecoded);
    if (path.isEmpty()) {
        reply(sock, 400, reasonFor(400), "{\"error\":\"missing_path\"}");
        return;
    }
    IModule* mod = m_registry ? m_registry->firstOfType(QStringLiteral("photo")) : nullptr;
    const auto* photos = qobject_cast<PhotoModule*>(mod);
    if (!photos || m_thumbnailRequests >= 8) {
        reply(sock, 503, reasonFor(503), "{\"error\":\"thumbnail_unavailable\"}");
        return;
    }

    // Le travail ne retient ni le module ni la socket. Le thread HTTP seul
    // installe et retire les demandes et publie les réponses.
    disconnect(sock, &QTcpSocket::readyRead, this, nullptr);
    ++m_thumbnailRequests;
    auto* watcher = new QFutureWatcher<QByteArray>(this);
    connect(watcher, &QFutureWatcher<QByteArray>::finished, this,
            [this, socket = QPointer<QTcpSocket>(sock), watcher] {
        --m_thumbnailRequests;
        const QByteArray jpeg = watcher->result();
        watcher->deleteLater();
        if (!socket)
            return;
        if (jpeg.isEmpty())
            reply(socket, 404, reasonFor(404), "{\"error\":\"thumbnail_not_found\"}");
        else
            reply(socket, 200, reasonFor(200), jpeg, "image/jpeg", true);
    });
    watcher->setFuture(QtConcurrent::run(&m_thumbnailPool, photos->thumbnailReader(requireCache), path));
}

QByteArray HttpServer::buildStatusJson() const {
    QJsonObject o;
    o["app"]      = m_config.appName;
    o["host"]     = QHostInfo::localHostName();
    o["version"]  = morfphoto::version();
    o["proto"]    = QString::fromLatin1(morfphoto::kProtocol);
    o["state"]    = m_registry ? m_registry->state() : QStringLiteral("ok");
    o["uptime_s"] = static_cast<double>(m_uptime.isValid() ? m_uptime.elapsed() / 1000 : 0);
    o["ts"]       = static_cast<double>(QDateTime::currentSecsSinceEpoch());
    o["metrics"]  = m_registry ? m_registry->metrics() : QJsonObject{};

    // Activite EN COURS (contrat generique `activity/1`) : champ OPTIONNEL, present
    // seulement quand un module travaille. morfMonitor le lit en temps reel. Jamais
    // dans le heartbeat beacon. Voir morfSystem/docs/CONTRAT-ACTIVITE.md.
    const QJsonObject activity = m_registry ? m_registry->activity() : QJsonObject{};
    if (!activity.isEmpty())
        o["activity"] = activity;

    // Detail annonce (API) depuis le point UNIQUE. Tout service
    // morfSystem se decrit ainsi. describeService n'emet `web_ui` que si une
    // interface est declaree dans fillAnnouncedDetail ; morfPhoto etant
    // sans interface, seul le bloc `api` apparait.
    morfbeacon::PresenceConfig self;
    fillAnnouncedDetail(self);
    const QJsonObject detail = morfbeacon::describeService(self, port());
    for (auto it = detail.constBegin(); it != detail.constEnd(); ++it)
        o[it.key()] = it.value();

    return toJson(o);
}

void HttpServer::reply(QTcpSocket* sock, int code, const QByteArray& reason, const QByteArray& body,
                       const QByteArray& contentType, bool allowCors,
                       const QByteArray& extraHeaders) {
    const auto route = sock->property("httpLogRoute");
    if (route.isValid()) {
        qInfo().noquote() << "morfPhoto HTTP" << route.toString() << "status" << code
                          << "handler_ms" << m_uptime.elapsed() - sock->property("httpLogStartMs").toLongLong()
                          << "bytes" << body.size();
    }
    QByteArray resp;
    resp += "HTTP/1.1 " + QByteArray::number(code) + " " + reason + "\r\n";
    resp += "Content-Type: " + contentType + "\r\n";
    resp += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    // CORS ouvert en lecture seule uniquement : jamais sur une ecriture (CSRF).
    if (allowCors)
        resp += "Access-Control-Allow-Origin: *\r\n";
    resp += extraHeaders;
    resp += "Connection: close\r\n\r\n";
    resp += body;
    disconnect(sock, &QTcpSocket::readyRead, this, nullptr);
    if (sock->write(resp) < 0) {
        sock->abort();
        return;
    }
    // Qt drains queued bytes before closing. Bound the drain for clients that stop reading.
    QTimer::singleShot(10000, sock, [sock, route] {
        if (route.isValid())
            qWarning().noquote() << "morfPhoto HTTP drain timed out" << route.toString()
                                 << "queued_bytes" << sock->bytesToWrite();
        sock->abort();
    });
    sock->disconnectFromHost();
}

} // namespace morfphoto
