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
#include <QCryptographicHash>
#include <QThread>
#include <QtConcurrent>

#ifdef MORFPHOTO_HAS_ZLIB
#include <zlib.h>
#endif

#include <atomic>
#include <memory>
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
        case 304: return "Not Modified";
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

bool etagMatches(const QByteArray& ifNoneMatch, const QByteArray& etag) {
    if (ifNoneMatch.isEmpty())
        return false;
    for (const QByteArray& raw : ifNoneMatch.split(',')) {
        QByteArray token = raw.trimmed();
        if (token.startsWith("W/"))
            token = token.mid(2).trimmed();
        if (token == etag)
            return true;
    }
    return false;
}

#ifdef MORFPHOTO_HAS_ZLIB
QByteArray gzipCompress(const QByteArray& input) {
    if (input.isEmpty())
        return {};
    z_stream zs{};
    if (deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};
    zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.constData()));
    zs.avail_in = static_cast<uInt>(input.size());

    QByteArray out;
    out.resize(static_cast<qsizetype>(deflateBound(&zs, zs.avail_in)) + 32);
    int rc = Z_OK;
    do {
        if (static_cast<qsizetype>(zs.total_out) >= out.size())
            out.resize(out.size() + 16384);
        zs.next_out = reinterpret_cast<Bytef*>(out.data() + zs.total_out);
        zs.avail_out = static_cast<uInt>(out.size() - static_cast<qsizetype>(zs.total_out));
        rc = deflate(&zs, Z_FINISH);
    } while (rc == Z_OK);

    const auto totalOut = static_cast<qsizetype>(zs.total_out);
    deflateEnd(&zs);
    if (rc != Z_STREAM_END)
        return {};
    out.resize(totalOut);
    return out;
}
#endif
} // namespace

HttpServer::HttpServer(ServiceConfig config, ModuleRegistry* registry, QObject* parent)
    : QObject(parent),
      m_config(std::move(config)),
      m_registry(registry),
      m_server(new QTcpServer(this)),
      m_proxyManager(new QNetworkAccessManager(this)) {
    connect(m_server, &QTcpServer::newConnection, this, &HttpServer::onNewConnection);
    m_proxyManager->setProxy(QNetworkProxy::NoProxy);
    // L'environnement prime : un secret de conteneur n'a pas a vivre dans un fichier.
    m_apiReadPool.setMaxThreadCount(qBound(2, QThread::idealThreadCount(), 4));
    m_thumbnailPool.setMaxThreadCount(qBound(4, QThread::idealThreadCount(), 8));
    m_cachedThumbnailPool.setMaxThreadCount(8);
    const QString envKey = qEnvironmentVariable("MORFPHOTO_API_KEY").trimmed();
    m_apiKey = (envKey.isEmpty() ? m_config.apiKey.trimmed() : envKey).toUtf8();
}

HttpServer::~HttpServer() {
    stop();
}

bool HttpServer::start() {
    if (m_config.httpPort == 0)
        return false;
    m_uptime.start();
    QHostAddress addr(m_config.bindAddress);
    if (addr.isNull())
        addr = QHostAddress(QHostAddress::AnyIPv4);
    return m_server->listen(addr, m_config.httpPort);
}

void HttpServer::stop() {
    if (m_server)
        m_server->close();
    m_apiReadPool.waitForDone();
    m_thumbnailPool.waitForDone();
    m_cachedThumbnailPool.waitForDone();
}
bool HttpServer::isListening() const { return m_server->isListening(); }
quint16 HttpServer::port() const   { return m_server->isListening() ? m_server->serverPort() : 0; }

void HttpServer::onNewConnection() {
    while (m_server->hasPendingConnections()) {
        QTcpSocket* sock = m_server->nextPendingConnection();
        sock->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        connect(sock, &QTcpSocket::readyRead, this, [this, sock]() { onSocketReadyRead(sock); });
        connect(sock, &QTcpSocket::disconnected, sock, &QObject::deleteLater);
    }
}

void HttpServer::onSocketReadyRead(QTcpSocket* sock) {
    QByteArray buf = sock->property("buf").toByteArray();
    buf += sock->readAll();

    if (sock->property("inFlight").toBool()) {
        if (buf.size() > kMaxRequestBytes * 2) { sock->abort(); return; }
        sock->setProperty("buf", buf);
        return;
    }

    const int headerEnd = buf.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        if (buf.size() > kMaxRequestBytes) { sock->abort(); return; }
        sock->setProperty("buf", buf);
        return;
    }

    const QByteArray headerBlock = buf.left(headerEnd);
    const int needed = qMax(0, contentLength(headerBlock));
    const int bodyStart = headerEnd + 4;
    if (buf.size() - bodyStart < needed) {
        if (buf.size() > kMaxRequestBytes) { sock->abort(); return; }
        sock->setProperty("buf", buf);
        return;
    }

    const int lineEnd = buf.indexOf("\r\n");
    const QList<QByteArray> parts = buf.left(lineEnd).split(' ');
    const QByteArray method = parts.value(0);
    const QByteArray path = parts.value(1);
    const QByteArray httpVersion = parts.value(2);
    const QByteArray body = buf.mid(bodyStart, needed);

    const QByteArray connHdr = headerValue(headerBlock, "Connection").toLower();
    const bool keepAlive = (httpVersion == "HTTP/1.0")
        ? connHdr.contains("keep-alive")
        : !connHdr.contains("close");
    const bool acceptsGzip = headerValue(headerBlock, "Accept-Encoding").toLower().contains("gzip");
    const QByteArray ifNoneMatch = headerValue(headerBlock, "If-None-Match");

    sock->setProperty("keepAlive", keepAlive);
    sock->setProperty("acceptsGzip", acceptsGzip);
    sock->setProperty("ifNoneMatch", ifNoneMatch);
    sock->setProperty("inFlight", true);

    if (auto* idleTimer = sock->findChild<QTimer*>(QStringLiteral("idleTimer")))
        idleTimer->stop();

    buf.remove(0, bodyStart + needed);
    sock->setProperty("buf", buf);

    if (qEnvironmentVariableIntValue("MORFPHOTO_HTTP_DEBUG") == 1) {
        const QByteArray logPath = path.split('?').value(0);
        const char* route = "other";
        if (logPath == "/healthz")
            route = "health";
        else if (logPath == "/api/v1/library/subfolders")
            route = "subfolders";
        else if (logPath == "/api/v1/library" || logPath.startsWith("/api/v1/library/"))
            route = "catalog";
        else if (logPath.startsWith("/api/v1/thumbnail"))
            route = "thumbnail";
        else if (logPath == "/api/v1/search/semantic")
            route = "semantic";
        else if (logPath == "/api/v1/index/status")
            route = "index-status";
        sock->setProperty("httpLogRoute", QString::fromLatin1(route));
        sock->setProperty("httpLogStartMs", m_uptime.elapsed());
    }

    // Anti-CSRF : une ecriture portant un Origin different de Host vient d'une page tierce.
    if (isCrossOriginWrite(method, headerValue(headerBlock, "Origin"),
                           headerValue(headerBlock, "Host"))) {
        reply(sock, 403, reasonFor(403), "{\"error\":\"cross_origin_forbidden\"}",
              QByteArrayLiteral("application/json; charset=utf-8"), false);
        return;
    }

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
        if (m_semanticRequests >= 4) {
            reply(sock, 503, reasonFor(503), "{\"error\":\"semantic_search_busy\"}");
            return;
        }
        ++m_semanticRequests;
        auto released = std::make_shared<std::atomic_bool>(false);
        auto release = [this, released]() {
            if (!released->exchange(true))
                --m_semanticRequests;
        };
        QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:8794/search")));
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
        request.setTransferTimeout(20000);
        auto* result = m_proxyManager->post(request, body);
        auto abortOnClose = [release, resultPtr = QPointer<QNetworkReply>(result)]() {
            release();
            if (resultPtr) {
                resultPtr->abort();
                resultPtr->deleteLater();
            }
        };
        connect(sock, &QTcpSocket::disconnected, result, abortOnClose);
        connect(sock, &QObject::destroyed, result, abortOnClose);
        connect(result, &QNetworkReply::finished, this,
                [this, sp = QPointer<QTcpSocket>(sock), result, release] {
            release();
            const int status = result->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray payload = status ? result->readAll() :
                QByteArrayLiteral("{\"error\":\"semantic_search_unavailable\"}");
            result->deleteLater();
            if (!sp || sp->state() == QAbstractSocket::UnconnectedState)
                return;
            const int code = status ? status : 503;
            reply(sp, code, reasonFor(code), payload);
        });
        return;
    }

    // ---- API metier /api/v1 : deleguee au domaine photo (PhotoApi) ----
    if (path.startsWith("/api/")) {
        IModule* mod = m_registry ? m_registry->firstOfType(QStringLiteral("photo")) : nullptr;
        auto* photos = qobject_cast<PhotoModule*>(mod);
        const bool isOffloadableRead = (method == "GET") &&
            (path == "/api/v1/library" || path.startsWith("/api/v1/library/") ||
             path == "/api/v1/photos" || path.startsWith("/api/v1/photos/") ||
             path == "/api/v1/contexts" || path == "/api/v1/context");
        const QString pathStr = QString::fromUtf8(path);
        const bool isLibraryPath = (method == "GET") &&
            (path == "/api/v1/library" || path.startsWith("/api/v1/library/"));

        if (isOffloadableRead && photos != nullptr) {
            QElapsedTimer timer;
            timer.start();
            struct ApiReadResult {
                PhotoApi::Result api;
                QByteArray extraHeaders;
            };
            const QByteArray ifNoneMatch = isLibraryPath
                ? sock->property("ifNoneMatch").toByteArray()
                : QByteArray();
            auto* watcher = new QFutureWatcher<ApiReadResult>(this);
            connect(watcher, &QFutureWatcher<ApiReadResult>::finished, this,
                    [this, sp = QPointer<QTcpSocket>(sock), watcher, timer, isLibraryPath] {
                const ApiReadResult r = watcher->result();
                watcher->deleteLater();
                const qint64 elapsedMs = timer.elapsed();
                if (isLibraryPath && elapsedMs >= 500) {
                    qWarning() << "morfPhoto slow library request:" << elapsedMs << "ms, HTTP" << r.api.code;
                }
                if (!sp || sp->state() == QAbstractSocket::UnconnectedState)
                    return;
                reply(sp, r.api.code, reasonFor(r.api.code), r.api.body,
                      r.api.contentType, true, r.extraHeaders);
            });
            watcher->setFuture(QtConcurrent::run(&m_apiReadPool,
                [photos, method, pathStr, queryString, body, isLibraryPath, ifNoneMatch]() -> ApiReadResult {
                    QByteArray extraHeaders;
                    if (isLibraryPath && photos->libraryEnabled()) {
                        const QByteArray rev = photos->catalogRevision().toLatin1();
                        if (!rev.isEmpty()) {
                            const QByteArray etag = "\"cat-" + rev + "\"";
                            extraHeaders = "Cache-Control: private, no-cache\r\nETag: " + etag
                                + "\r\nX-Catalog-Revision: " + rev + "\r\n";
                            if (etagMatches(ifNoneMatch, etag)) {
                                return {{304, QByteArray(), QByteArrayLiteral("application/json; charset=utf-8")},
                                        extraHeaders};
                            }
                        }
                    }
                    PhotoApi::Result res = PhotoApi(photos).handle(method, pathStr, queryString, body);
                    return {std::move(res), res.code == 200 ? extraHeaders : QByteArray()};
                }));
            return;
        }

        PhotoApi api(photos);
        QElapsedTimer timer;
        timer.start();
        const PhotoApi::Result r = api.handle(method, pathStr, queryString, body);
        const qint64 elapsedMs = timer.elapsed();
        if (isLibraryPath && elapsedMs >= 500) {
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
    int& requests = requireCache ? m_cachedThumbnailRequests : m_thumbnailRequests;
    const int maxInFlight = requireCache ? 128 : 64;
    if (!photos || requests >= maxInFlight) {
        reply(sock, 503, reasonFor(503), "{\"error\":\"thumbnail_unavailable\"}");
        return;
    }

    // Le travail ne retient ni le module ni la socket. Le thread HTTP seul
    // installe et retire les demandes et publie les réponses.
    ++requests;
    struct ThumbnailResult {
        QByteArray jpeg;
        qint64 queueMs;
        qint64 readMs;
    };
    QElapsedTimer queued;
    queued.start();
    const bool logCached = requireCache && sock->property("httpLogRoute").isValid();
    auto* watcher = new QFutureWatcher<ThumbnailResult>(this);
    connect(watcher, &QFutureWatcher<ThumbnailResult>::finished, this,
            [this, socket = QPointer<QTcpSocket>(sock), watcher, logCached, requireCache] {
        --(requireCache ? m_cachedThumbnailRequests : m_thumbnailRequests);
        const auto result = watcher->result();
        const auto& jpeg = result.jpeg;
        watcher->deleteLater();
        if (logCached) {
            qInfo().noquote() << "morfPhoto HTTP thumbnail cache" << (jpeg.isEmpty() ? "miss" : "hit")
                              << "queue_ms" << result.queueMs << "read_ms" << result.readMs;
        }
        if (!socket || socket->state() == QAbstractSocket::UnconnectedState)
            return;
        if (jpeg.isEmpty()) {
            reply(socket, 404, reasonFor(404), "{\"error\":\"thumbnail_not_found\"}");
            return;
        }
        const QByteArray etag = "\"" + QCryptographicHash::hash(jpeg, QCryptographicHash::Md5).toHex() + "\"";
        const QByteArray cacheHeaders = "Cache-Control: public, max-age=86400\r\nETag: " + etag + "\r\n";
        const QByteArray ifNoneMatch = socket->property("ifNoneMatch").toByteArray();
        if (etagMatches(ifNoneMatch, etag))
            reply(socket, 304, reasonFor(304), "", "image/jpeg", true, cacheHeaders);
        else
            reply(socket, 200, reasonFor(200), jpeg, "image/jpeg", true, cacheHeaders);
    });
    auto* pool = requireCache ? &m_cachedThumbnailPool : &m_thumbnailPool;
    watcher->setFuture(QtConcurrent::run(pool,
        [read = photos->thumbnailReader(requireCache), path, queued] {
            const qint64 queueMs = queued.elapsed();
            auto jpeg = read(path);
            return ThumbnailResult{std::move(jpeg), queueMs, queued.elapsed() - queueMs};
        }));
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
    const bool keepAlive = sock->property("keepAlive").toBool();
    QByteArray payload = body;
    QByteArray gzipHeaders;
#ifdef MORFPHOTO_HAS_ZLIB
    const bool acceptsGzip = sock->property("acceptsGzip").toBool();
    if (acceptsGzip && body.size() >= 1024 && contentType.startsWith("application/json")
        && !extraHeaders.contains("Content-Encoding:")) {
        QByteArray compressed = gzipCompress(body);
        if (!compressed.isEmpty() && compressed.size() < body.size()) {
            payload = std::move(compressed);
            gzipHeaders = QByteArrayLiteral("Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
        }
    }
#endif

    const auto route = sock->property("httpLogRoute");
    if (route.isValid()) {
        qInfo().noquote() << "morfPhoto HTTP" << route.toString() << "status" << code
                          << "handler_ms" << m_uptime.elapsed() - sock->property("httpLogStartMs").toLongLong()
                          << "bytes" << payload.size();
    }

    QByteArray header;
    header.reserve(256 + extraHeaders.size() + gzipHeaders.size());
    header += "HTTP/1.1 " + QByteArray::number(code) + " " + reason + "\r\n";
    header += "Content-Type: " + contentType + "\r\n";
    header += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n";
    // CORS ouvert en lecture seule uniquement : jamais sur une ecriture (CSRF).
    if (allowCors)
        header += "Access-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: ETag, X-Catalog-Revision\r\n";
    header += extraHeaders;
    header += gzipHeaders;
    if (keepAlive)
        header += "Connection: keep-alive\r\nKeep-Alive: timeout=30\r\n\r\n";
    else
        header += "Connection: close\r\n\r\n";

    if (!keepAlive)
        disconnect(sock, &QTcpSocket::readyRead, this, nullptr);

    if (sock->write(header) < 0 || (!payload.isEmpty() && sock->write(payload) < 0)) {
        sock->abort();
        return;
    }

    if (keepAlive) {
        sock->setProperty("inFlight", false);
        sock->setProperty("httpLogRoute", QVariant());
        auto* idleTimer = sock->findChild<QTimer*>(QStringLiteral("idleTimer"));
        if (!idleTimer) {
            idleTimer = new QTimer(sock);
            idleTimer->setObjectName(QStringLiteral("idleTimer"));
            idleTimer->setSingleShot(true);
            connect(idleTimer, &QTimer::timeout, sock, &QTcpSocket::disconnectFromHost);
        }
        idleTimer->start(30000);
        if (!sock->property("buf").toByteArray().isEmpty()) {
            QMetaObject::invokeMethod(this, [this, sp = QPointer<QTcpSocket>(sock)] {
                if (sp)
                    onSocketReadyRead(sp);
            }, Qt::QueuedConnection);
        }
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
