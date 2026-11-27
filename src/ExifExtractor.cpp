/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/ExifExtractor.h"

#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QJsonDocument>
#include <limits>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>

#include <future>
#include <utility>
#include <vector>

namespace morfphoto {

namespace {

// Tags demandés à ExifTool, un par ligne (protocole argfile). Le suffixe `#`
// force la valeur NUMÉRIQUE brute (pas la conversion lisible). Plusieurs alias
// d'objectif et de date : tous les boîtiers ne les nomment pas pareil.
const char* const kTags[] = {
    "-DateTimeOriginal", "-CreateDate", "-Make", "-Model",
    "-LensModel", "-LensID", "-Lens",
    "-FocalLength#", "-FocalLengthIn35mmFormat#", "-FNumber#",
    "-ExposureTime#",          // vitesse numérique en secondes -> shutter_speed_s
    "-ShutterSpeed",           // vitesse lisible « 1/250 » -> shutter_speed
    // ISO : tag EXIF standard explicite. Un « -ISO# » nu laisse exiftool choisir parmi
    // les doublons, et sur les Ricoh/Pentax il renvoie le code d'index brut des notes
    // constructeur (9 pour ISO 200) au lieu de la vraie valeur.
    "-ExifIFD:ISO#", "-ExposureCompensation#", "-Rating#",
    "-GPSLatitude#", "-GPSLongitude#",
};

// Champs de la bibliotheque, demandes seulement quand elle est activee : sans elle,
// raw_exif garde exactement son contenu habituel.
const char* const kLibraryTags[] = {
    "-Subject", "-HierarchicalSubject", "-Label", "-Title", "-Description", "-Creator",
    "-Rights", "-XMP-dc:Publisher", "-XMP-acdsee:Notes", "-ExifIFD:SerialNumber",
    "-ImageWidth#", "-ImageHeight#", "-RawImageWidth#", "-RawImageHeight#",
    "-ExifIFD:ExifImageWidth#", "-ExifIFD:ExifImageHeight#",
};

// Format de date ISO imposé : « 2024-06-15 14:23:01 ». SQLite sait le lire, et
// la colonne calculée `taken_year` peut en extraire l'année.
const char* const kDateFormat = "%Y-%m-%d %H:%M:%S";
constexpr int kTimeoutMs = 15000;

// Sonde de disponibilité (« -ver ») : plus courte, elle ne lit pas de fichier.
constexpr int kProbeTimeoutMs = 5000;

// Assemble le bloc d'arguments commun (JSON, charset, format de date, tags).
QStringList argBlock(bool libraryTags) {
    QStringList args;
    args << QStringLiteral("-fast")
         << QStringLiteral("-json")
         << QStringLiteral("-charset") << QStringLiteral("filename=UTF8")
         << QStringLiteral("-d") << QString::fromLatin1(kDateFormat);
    for (const char* t : kTags)
        args << QString::fromLatin1(t);
    if (libraryTags)
        for (const char* t : kLibraryTags)
            args << QString::fromLatin1(t);
    return args;
}

// Premier alias texte présent et non vide (objectif, date...).
QVariant firstStr(const QJsonObject& o, std::initializer_list<const char*> keys) {
    for (const char* k : keys) {
        const QString s = o.value(QLatin1String(k)).toString().trimmed();
        if (!s.isEmpty())
            return s;
    }
    return {};
}

QVariant strVar(const QJsonObject& o, const char* key) {
    const QString s = o.value(QLatin1String(key)).toString().trimmed();
    return s.isEmpty() ? QVariant() : QVariant(s);
}

// Valeur numérique tolérante : nombre JSON, ou chaîne convertible, sinon NULL.
QVariant numVar(const QJsonObject& o, const char* key) {
    const QJsonValue v = o.value(QLatin1String(key));
    if (v.isDouble()) return v.toDouble();
    if (v.isString()) {
        bool ok = false;
        const double d = v.toString().toDouble(&ok);
        if (ok) return d;
    }
    return {};
}

QVariant intVar(const QJsonObject& o, const char* key) {
    const QVariant n = numVar(o, key);
    return n.isNull() ? QVariant() : QVariant(qRound(n.toDouble()));
}

} // namespace

int ExifExtractor::markerPos(const QByteArray& buf, const QByteArray& marker) {
    int from = 0;
    while ((from = buf.indexOf(marker, from)) >= 0) {
        const bool lineStart = from == 0 || buf.at(from - 1) == '\n';
        const int end = from + marker.size();
        const bool lineEnd = end < buf.size() && (buf.at(end) == '\n' || buf.at(end) == '\r');
        if (lineStart && lineEnd)
            return from;
        ++from;
    }
    return -1;
}

bool ExifExtractor::probe(const QString& binary, QString* detail) {
    QProcess proc;
    proc.start(binary, {QStringLiteral("-ver")});
    // Binaire absent du PATH, ou droits manquants : le process ne démarre même pas.
    if (!proc.waitForStarted(kProbeTimeoutMs)) {
        if (detail)
            *detail = QStringLiteral("binaire introuvable ou non demarrable : %1").arg(binary);
        return false;
    }
    if (!proc.waitForFinished(kProbeTimeoutMs)) {
        proc.kill();
        proc.waitForFinished(kProbeTimeoutMs);
        if (detail)
            *detail = QStringLiteral("pas de reponse a « %1 -ver »").arg(binary);
        return false;
    }
    // « -ver » n'écrit que le numéro de version sur stdout et sort avec 0.
    const QString ver = QString::fromUtf8(proc.readAllStandardOutput()).trimmed();
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0 || ver.isEmpty()) {
        if (detail)
            *detail = QStringLiteral("« %1 -ver » a echoue").arg(binary);
        return false;
    }
    if (detail)
        *detail = QStringLiteral("ExifTool %1").arg(ver);
    return true;
}

ExifExtractor::ExifExtractor(QString binary, bool stayOpen)
    : m_binary(std::move(binary)), m_stayOpen(stayOpen) {}

ExifExtractor::~ExifExtractor() {
    close();
}

void ExifExtractor::setLibraryTags(bool enabled) {
    m_libraryTags = enabled;
    for (const auto& worker : m_batchWorkers)
        worker->setLibraryTags(enabled);
}

void ExifExtractor::open() {
    if (!m_stayOpen || m_proc)
        return;
    // `-@ -` : ExifTool lit ses arguments sur stdin, jusqu'à un `-execute`.
    m_proc = new QProcess();
    m_proc->setProcessChannelMode(QProcess::SeparateChannels);
    m_proc->start(m_binary, {QStringLiteral("-stay_open"), QStringLiteral("True"),
                             QStringLiteral("-@"), QStringLiteral("-")});
    if (!m_proc->waitForStarted(kTimeoutMs)) {
        delete m_proc;
        m_proc = nullptr;
    }
}

void ExifExtractor::closeProc() {
    if (!m_proc)
        return;
    if (m_proc->state() == QProcess::Running) {
        m_proc->write("-stay_open\nFalse\n");
        m_proc->waitForBytesWritten(kTimeoutMs);
        if (!m_proc->waitForFinished(kTimeoutMs)) {
            m_proc->kill();
            m_proc->waitForFinished(kTimeoutMs);
        }
    }
    delete m_proc;
    m_proc = nullptr;
}

void ExifExtractor::restartProc() {
    closeProc();
    open();
}

void ExifExtractor::close() {
    closeProc();
    for (const auto& worker : m_batchWorkers)
        worker->close();
    m_batchWorkers.clear();
}

ExifData ExifExtractor::extract(const QString& path, QString* error) {
    QString localError;
    QString* err = error ? error : &localError;
    err->clear();
    const bool persistent = m_stayOpen && m_proc;
    const QString file = (persistent && !QDir::isAbsolutePath(path))
        ? QFileInfo(path).absoluteFilePath()
        : path;

    // Le protocole argfile est ligne par ligne : un \n ou \r dans le nom injecterait des
    // arguments ExifTool arbitraires (ex. « -overwrite_original »). Fichier refuse.
    if (file.contains(QLatin1Char('\n')) || file.contains(QLatin1Char('\r'))) {
        *err = QStringLiteral("ExifTool: nom de fichier avec saut de ligne refuse");
        return {};
    }

    const QString json = persistent ? readPersistent(file, err) : readOnce(file, err);
    if (!err->isEmpty())
        return {};
    return mapTags(json, err);
}

QHash<QString, QPair<ExifData, QString>> ExifExtractor::extractBatch(const QStringList& paths,
                                                                   int workers) {
    using Results = QHash<QString, QPair<ExifData, QString>>;
    if (paths.isEmpty())
        return {};
    const qsizetype lanes = qMin<qsizetype>(qMax(1, workers), paths.size());
    auto readLane = [&paths, lanes](ExifExtractor& extractor, qsizetype first) {
        Results results;
        for (qsizetype i = first; i < paths.size(); i += lanes) {
            QString error;
            ExifData data = extractor.extract(paths.at(i), &error);
            results.insert(paths.at(i), {std::move(data), std::move(error)});
        }
        return results;
    };

    const auto neededWorkers = static_cast<size_t>(lanes - 1);
    while (m_batchWorkers.size() < neededWorkers) {
        auto worker = std::make_unique<ExifExtractor>(m_binary, m_stayOpen);
        worker->setLibraryTags(m_libraryTags);
        worker->open();
        m_batchWorkers.push_back(std::move(worker));
    }

    // Chaque voie réutilise son QProcess persistant. Les résultats sont réunis
    // avant de reprendre les écritures SQLite dans le thread de la passe.
    std::vector<std::future<Results>> workersInFlight;
    workersInFlight.reserve(neededWorkers);
    for (qsizetype lane = 1; lane < lanes; ++lane) {
        ExifExtractor* worker = m_batchWorkers[static_cast<size_t>(lane - 1)].get();
        workersInFlight.push_back(std::async(std::launch::async | std::launch::deferred, [&, worker, lane] {
            return readLane(*worker, lane);
        }));
    }
    auto results = readLane(*this, 0);
    for (auto& worker : workersInFlight)
        results.insert(worker.get());
    return results;
}

QString ExifExtractor::readPersistent(const QString& path, QString* error) {
    if (!m_proc || m_proc->state() != QProcess::Running)
        restartProc();
    if (!m_proc || m_proc->state() != QProcess::Running) {
        *error = QStringLiteral("ExifTool: process indisponible pour %1").arg(path);
        return {};
    }

    ++m_counter;
    const QByteArray marker = "{ready" + QByteArray::number(m_counter) + "}";

    // Pousser le bloc d'arguments, un par ligne, puis l'ordre d'exécution numéroté.
    QByteArray payload;
    for (const QString& a : argBlock(m_libraryTags))
        payload += a.toUtf8() + "\n";
    // Un chemin absolu ne peut pas être pris pour une option. Dans le flux
    // persistant, « -- » ferait aussi passer « -executeN » pour un fichier.
    payload += path.toUtf8() + "\n";
    payload += "-execute" + QByteArray::number(m_counter) + "\n";
    m_proc->write(payload);
    m_proc->waitForBytesWritten(kTimeoutMs);

    // Lire jusqu'au marqueur {readyN} (exclu de la sortie). Le marqueur n'est reconnu
    // qu'en DEBUT de ligne et suivi d'un saut de ligne : un nom de fichier contenant
    // « {readyN} » apparait dans le JSON (SourceFile) au milieu d'une ligne et ne doit
    // pas couper la lecture, sous peine de desynchroniser tout le flux suivant.
    QByteArray buf;
    int at = -1;
    while ((at = markerPos(buf, marker)) < 0) {
        if (!m_proc->waitForReadyRead(kTimeoutMs)) {
            *error = QStringLiteral("ExifTool: pas de reponse pour %1").arg(path);
            restartProc();
            return {};
        }
        buf += m_proc->readAllStandardOutput();
    }
    return QString::fromUtf8(buf.left(at));
}

QString ExifExtractor::readOnce(const QString& path, QString* error) {
    QProcess proc;
    proc.start(m_binary, argBlock(m_libraryTags) << QStringLiteral("--") << path);
    if (!proc.waitForFinished(kTimeoutMs)) {
        *error = QStringLiteral("ExifTool: delai depasse pour %1").arg(path);
        return {};
    }
    const QByteArray out = proc.readAllStandardOutput();
    if (out.trimmed().isEmpty()) {
        *error = QStringLiteral("ExifTool: %1").arg(QString::fromUtf8(proc.readAllStandardError()).trimmed());
        return {};
    }
    return QString::fromUtf8(out);
}

ExifData ExifExtractor::mapTags(const QString& json, QString* error) {
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray() || doc.array().isEmpty()) {
        *error = QStringLiteral("ExifTool: sortie illisible");
        return {};
    }
    const QJsonObject o = doc.array().first().toObject();
    if (o.contains(QStringLiteral("Error"))) {
        *error = QStringLiteral("ExifTool: %1").arg(o.value(QStringLiteral("Error")).toString());
        return {};
    }

    ExifData d;
    d.ok                   = true;
    d.takenAt              = firstStr(o, {"DateTimeOriginal", "CreateDate"});
    d.make                 = strVar(o, "Make");
    d.cameraModel          = strVar(o, "Model");
    d.lens                 = firstStr(o, {"LensModel", "LensID", "Lens"});
    d.focalLength          = numVar(o, "FocalLength");
    d.focalLength35mm      = numVar(o, "FocalLengthIn35mmFormat");
    d.aperture             = numVar(o, "FNumber");
    d.shutterSpeed         = strVar(o, "ShutterSpeed");
    d.shutterSpeedS        = numVar(o, "ExposureTime");
    d.iso                  = intVar(o, "ISO");
    d.exposureCompensation = numVar(o, "ExposureCompensation");
    d.rating               = intVar(o, "Rating");
    d.latitude             = numVar(o, "GPSLatitude");
    d.longitude            = numVar(o, "GPSLongitude");

    // raw_exif : tags renvoyés, hors SourceFile, pour extension future.
    QJsonObject raw = o;
    raw.remove(QStringLiteral("SourceFile"));
    d.raw = raw;
    return d;
}

QSize ExifExtractor::originalSize(const QJsonObject& tags, bool raw) {
    const auto dimension = [&tags](const char* key) {
        const double value = numVar(tags, key).toDouble();
        if (value >= 1 && value <= std::numeric_limits<int>::max()
            && value == static_cast<int>(value))
            return static_cast<int>(value);
        return 0;
    };
    const auto size = [&dimension](const char* width, const char* height) {
        return QSize(dimension(width), dimension(height));
    };
    if (!raw)
        return size("ImageWidth", "ImageHeight");

    // Un RAW peut annoncer les dimensions du JPEG d'aperçu dans les tags génériques.
    const QSize exif = size("ExifImageWidth", "ExifImageHeight");
    return exif.isEmpty() ? size("RawImageWidth", "RawImageHeight") : exif;
}

} // namespace morfphoto
