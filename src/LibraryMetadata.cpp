/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include "morfphoto/LibraryMetadata.h"

#include <QCryptographicHash>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QXmlStreamReader>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace morfphoto {

namespace {

// Change si l'interpretation evolue : chaque photo est alors relue une fois.
const char* const kFormat = "library1";

const QLatin1String kRdf("http://www.w3.org/1999/02/22-rdf-syntax-ns#");

QString prefixFor(QStringView uri) {
    static const QHash<QString, QString> prefixes = {
        {QStringLiteral("http://ns.adobe.com/xap/1.0/"), QStringLiteral("xmp")},
        {QStringLiteral("http://purl.org/dc/elements/1.1/"), QStringLiteral("dc")},
        {QStringLiteral("http://ns.adobe.com/lightroom/1.0/"), QStringLiteral("lr")},
        {QStringLiteral("http://ns.acdsee.com/iptc/1.0/"), QStringLiteral("acdsee")},
        {QStringLiteral("http://darktable.sf.net/"), QStringLiteral("darktable")},
        {QStringLiteral("http://ns.adobe.com/exif/1.0/"), QStringLiteral("exif")},
        {QStringLiteral("http://ns.adobe.com/camera-raw-settings/1.0/"), QStringLiteral("crs")},
        {QStringLiteral("https://github.com/Rhettus/immage/ns/1.0/"), QStringLiteral("immage")},
    };
    return prefixes.value(uri.toString());
}

// L'historique d'edition est volumineux et n'apporte rien a un filtre.
bool isEditPayload(const QString& key) {
    return key == QLatin1String("darktable:history") || key == QLatin1String("darktable:masks_history");
}

QString firstOf(const SidecarData* sidecar, const char* key) {
    return sidecar ? sidecar->properties.value(QLatin1String(key)).value(0).trimmed() : QString();
}

QStringList rawStrings(const QJsonObject& raw, const char* key) {
    const QJsonValue value = raw.value(QLatin1String(key));
    QStringList out;
    if (value.isArray()) {
        for (const QJsonValue& item : value.toArray())
            out << item.toVariant().toString().trimmed();
    } else if (!value.isUndefined() && !value.isNull()) {
        out << value.toVariant().toString().trimmed();
    }
    out.removeAll(QString());
    return out;
}

int labelBit(const QString& name) {
    const QString label = name.trimmed().toLower();
    if (label == QLatin1String("red"))    return 1;
    if (label == QLatin1String("yellow")) return 2;
    if (label == QLatin1String("green"))  return 4;
    if (label == QLatin1String("blue"))   return 8;
    if (label == QLatin1String("purple")) return 16;
    return 0;
}

QVariant textOr(const QString& value, const QJsonObject& raw, const char* rawKey, bool authoritative) {
    if (!value.isEmpty())
        return value;
    if (authoritative)
        return {};
    const QStringList embedded = rawStrings(raw, rawKey);
    return embedded.isEmpty() ? QVariant() : QVariant(embedded.join(QStringLiteral(", ")));
}

// « 2023:02:19 17:52:53.000 » ou « 2023-02-19T17:52:53 » => « 2023-02-19 17:52:53 ».
QString normalizedDate(const QString& value) {
    static const QRegularExpression pattern(
        QStringLiteral("^(\\d{4})[:-](\\d{2})[:-](\\d{2})(?:[ T](\\d{2}:\\d{2}:\\d{2}))?"));
    const QRegularExpressionMatch match = pattern.match(value.trimmed());
    if (!match.hasMatch())
        return {};
    const QString day = match.captured(1) + QLatin1Char('-') + match.captured(2)
                      + QLatin1Char('-') + match.captured(3);
    return match.captured(4).isEmpty() ? day : day + QLatin1Char(' ') + match.captured(4);
}

// Formats ecrits par darktable : decimal, « DDD,MM.mmN » ou « DDD,MM,SSN ».
QVariant gpsValue(const QString& text) {
    QString value = text.trimmed();
    if (value.isEmpty())
        return {};
    double sign = 1.0;
    const QChar direction = value.back().toUpper();
    if (direction.isLetter()) {
        if (direction == QLatin1Char('S') || direction == QLatin1Char('W'))
            sign = -1.0;
        value.chop(1);
    }
    const QStringList parts = value.split(QLatin1Char(','));
    bool ok = true;
    double result = 0.0;
    double divisor = 1.0;
    for (const QString& part : parts) {
        bool partOk = false;
        result += part.toDouble(&partOk) / divisor;
        ok = ok && partOk;
        divisor *= 60.0;
    }
    return (ok && parts.size() <= 3) ? QVariant(sign * result) : QVariant();
}

} // namespace

bool isExtendedImageExtension(const QString& extension) {
    static const QSet<QString> extended = {
        ".ari", ".bay", ".crw", ".dcs", ".fff", ".k25", ".mdc", ".ori", ".sr2", ".srf",
        ".avif", ".bmp", ".exr", ".gif", ".hif", ".j2k", ".jp2", ".jxl", ".pfm", ".pgm",
        ".pnm", ".ppm", ".qoi",
    };
    return extended.contains(extension.toLower());
}

void assignSidecars(QVector<FileInfo>& files, const QHash<QString, QVector<SidecarRef>>& byDirectory) {
    static const QRegularExpression duplicate(QStringLiteral("^(.+)_(\\d{2,})(\\.[^.]+)$"));

    QHash<QString, QHash<QString, int>> names;
    QHash<QString, QHash<QString, QVector<int>>> stems;
    for (int i = 0; i < files.size(); ++i) {
        names[files[i].directory].insert(files[i].filename, i);
        stems[files[i].directory][QFileInfo(files[i].filename).completeBaseName()] << i;
    }

    for (auto dir = byDirectory.constBegin(); dir != byDirectory.constEnd(); ++dir) {
        const QHash<QString, int> images = names.value(dir.key());
        QVector<QPair<QString, SidecarRef>> shared;   // photo.xmp, commun a photo.NEF et photo.JPG
        for (SidecarRef ref : dir.value()) {
            const QString base = QFileInfo(ref.path).fileName().chopped(4);
            if (images.contains(base)) {
                ref.version = 0;
                files[images.value(base)].sidecars << ref;
                continue;
            }
            const QRegularExpressionMatch match = duplicate.match(base);
            bool versionOk = false;
            const int version = match.hasMatch() ? match.captured(2).toInt(&versionOk) : 0;
            const QString original = match.captured(1) + match.captured(3);
            if (versionOk && images.contains(original)) {
                ref.version = version;
                files[images.value(original)].sidecars << ref;
            } else {
                shared.push_back({base, ref});
            }
        }
        // Passe separee : `photo.NEF.xmp` l'emporte toujours sur `photo.xmp`.
        for (const auto& entry : shared) {
            for (int index : stems.value(dir.key()).value(entry.first)) {
                const auto& known = files[index].sidecars;
                const bool hasPrimary = std::any_of(known.begin(), known.end(),
                    [](const SidecarRef& r) { return r.version == 0; });
                if (!hasPrimary)
                    files[index].sidecars << entry.second;
            }
        }
    }

    for (FileInfo& file : files) {
        std::sort(file.sidecars.begin(), file.sidecars.end(),
                  [](const SidecarRef& a, const SidecarRef& b) { return a.version < b.version; });
        QCryptographicHash hash(QCryptographicHash::Md5);
        hash.addData(QByteArray(kFormat));
        for (const SidecarRef& ref : file.sidecars)
            hash.addData(QStringLiteral("|%1:%2:%3:%4").arg(ref.version).arg(ref.path)
                             .arg(ref.size).arg(ref.mtime).toUtf8());
        file.sidecarFingerprint = QString::fromLatin1(hash.result().toHex());
    }
}

SidecarData parseSidecar(const QByteArray& bytes) {
    SidecarData data;
    QXmlStreamReader xml(bytes);
    while (!xml.atEnd()) {
        xml.readNext();
        if (!xml.isStartElement())
            continue;
        if (xml.namespaceUri() == kRdf && xml.name() == QLatin1String("Description")) {
            for (const QXmlStreamAttribute& attribute : xml.attributes()) {
                const QString prefix = prefixFor(attribute.namespaceUri());
                if (!prefix.isEmpty())
                    data.properties.insert(prefix + QLatin1Char(':') + attribute.name().toString(),
                                           {attribute.value().toString()});
            }
            continue;
        }
        const QString prefix = prefixFor(xml.namespaceUri());
        if (prefix.isEmpty())
            continue;
        const QString key = prefix + QLatin1Char(':') + xml.name().toString();
        if (isEditPayload(key)) {
            xml.skipCurrentElement();
            continue;
        }
        QStringList values;
        QString text;
        int depth = 1;
        while (depth > 0 && !xml.atEnd()) {
            xml.readNext();
            if (xml.isStartElement()) {
                ++depth;
                text.clear();
            } else if (xml.isCharacters()) {
                text += xml.text();
            } else if (xml.isEndElement()) {
                --depth;
                if (depth > 0 && xml.name() == QLatin1String("li") && xml.namespaceUri() == kRdf) {
                    values << text.trimmed();
                    text.clear();
                }
            }
        }
        if (values.isEmpty() && !text.trimmed().isEmpty())
            values << text.trimmed();
        data.properties.insert(key, values);
    }
    data.ok = !xml.hasError();
    return data;
}

LibraryVersion mergeVersion(int version, const QString& sidecarPath, const SidecarData* sidecar,
                            const ExifData& base) {
    LibraryVersion out;
    out.version = version;
    out.sidecar = sidecar ? sidecarPath : QString();

    // Un sidecar darktable fait foi : un mot-cle retire ne doit pas revenir depuis l'image.
    const bool authoritative = sidecar && sidecar->properties.contains(QStringLiteral("darktable:xmp_version"));
    const QJsonObject& raw = base.raw;

    bool ratingOk = false;
    const int sidecarRating = firstOf(sidecar, "xmp:Rating").toInt(&ratingOk);
    const int rating = ratingOk ? sidecarRating : base.rating.toInt();
    out.rejected = rating < 0;
    out.rating = out.rejected ? 0 : qBound(0, rating, 5);

    // Meme ordre que darktable : xmp:Label, puis ses propres etiquettes.
    const QString label = firstOf(sidecar, "xmp:Label");
    const QStringList colors = sidecar ? sidecar->properties.value(QStringLiteral("darktable:colorlabels"))
                                       : QStringList();
    if (!label.isEmpty()) {
        out.labels = labelBit(label);
    } else if (!colors.isEmpty()) {
        for (const QString& color : colors) {
            const int index = color.toInt();
            if (index >= 0 && index <= 4)
                out.labels |= 1 << index;
        }
    } else if (!authoritative) {
        out.labels = labelBit(rawStrings(raw, "Label").value(0));
    }

    QStringList keywords;
    if (sidecar) {
        keywords = sidecar->properties.value(QStringLiteral("lr:hierarchicalSubject"));
        if (keywords.isEmpty())
            keywords = sidecar->properties.value(QStringLiteral("dc:subject"));
    }
    if (keywords.isEmpty() && !authoritative) {
        keywords = rawStrings(raw, "HierarchicalSubject");
        if (keywords.isEmpty())
            keywords = rawStrings(raw, "Subject");
    }
    // Les etiquettes « darktable|... » sont sa comptabilite interne, pas des mots-cles.
    for (const QString& keyword : keywords) {
        const QString value = keyword.trimmed();
        if (!value.isEmpty() && value != QLatin1String("darktable")
            && !value.startsWith(QLatin1String("darktable|")) && !out.keywords.contains(value))
            out.keywords << value;
    }
    std::sort(out.keywords.begin(), out.keywords.end());

    // Meme test que dt_image_altered : un historique long ne prouve pas une retouche.
    const QString current = firstOf(sidecar, "darktable:history_current_hash");
    if (!sidecar) {
        out.edited = false;
    } else if (!current.isEmpty()) {
        out.edited = current != firstOf(sidecar, "darktable:history_basic_hash")
                  && current != firstOf(sidecar, "darktable:history_auto_hash");
    } else if (firstOf(sidecar, "crs:HasSettings").compare(QLatin1String("true"), Qt::CaseInsensitive) == 0) {
        out.edited = true;
    }

    const QString date = normalizedDate(firstOf(sidecar, "exif:DateTimeOriginal"));
    out.takenAt = date.isEmpty() ? base.takenAt : QVariant(date);

    // locationManaged : une position absente du sidecar a ete retiree volontairement.
    const bool managed = firstOf(sidecar, "immage:locationManaged").compare(QLatin1String("true"), Qt::CaseInsensitive) == 0;
    const QVariant latitude = gpsValue(firstOf(sidecar, "exif:GPSLatitude"));
    const QVariant longitude = gpsValue(firstOf(sidecar, "exif:GPSLongitude"));
    const bool hasPosition = latitude.isValid() && longitude.isValid();
    out.latitude = hasPosition ? latitude : (managed ? QVariant() : base.latitude);
    out.longitude = hasPosition ? longitude : (managed ? QVariant() : base.longitude);

    out.title = textOr(firstOf(sidecar, "dc:title"), raw, "Title", authoritative);
    out.description = textOr(firstOf(sidecar, "dc:description"), raw, "Description", authoritative);
    out.creator = textOr(firstOf(sidecar, "dc:creator"), raw, "Creator", authoritative);
    out.rights = textOr(firstOf(sidecar, "dc:rights"), raw, "Rights", authoritative);
    out.publisher = textOr(firstOf(sidecar, "dc:publisher"), raw, "Publisher", authoritative);
    if (sidecar && sidecar->properties.contains(QStringLiteral("acdsee:notes"))) {
        const QString notes = firstOf(sidecar, "acdsee:notes");
        out.notes = notes.isEmpty() ? QVariant() : QVariant(notes);
    } else {
        out.notes = textOr(firstOf(sidecar, "darktable:notes"), raw, "Notes", authoritative);
    }
    const QString versionName = firstOf(sidecar, "darktable:version_name");
    out.versionName = versionName.isEmpty() ? QVariant() : QVariant(versionName);

    if (sidecar) {
        for (auto it = sidecar->properties.constBegin(); it != sidecar->properties.constEnd(); ++it)
            out.rawXmp.insert(it.key(), it.value().size() == 1 ? QJsonValue(it.value().first())
                                                               : QJsonValue(QJsonArray::fromStringList(it.value())));
    }
    return out;
}

QString decimalLabel(double value, int places) {
    if (!std::isfinite(value) || value <= 0.0 || value > 1e9)
        return {};
    // Valeur binaire exacte : 2,25 donne 2,3 alors que printf l'arrondirait au pair (2,2).
    quint64 bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const int exponent = int((bits >> 52) & 2047) - 1023 - 52;
    const quint64 scale = places == 1 ? 10 : 1;
    const quint64 significand = ((bits & ((quint64(1) << 52) - 1)) | (quint64(1) << 52)) * scale;
    quint64 rounded = 0;
    if (exponent >= 0) {
        rounded = significand << exponent;
    } else if (-exponent < 64) {
        const int shift = -exponent;
        rounded = (significand >> shift)
                + ((significand & ((quint64(1) << shift) - 1)) >= (quint64(1) << (shift - 1)) ? 1 : 0);
    }
    const quint64 whole = rounded / scale;
    const quint64 fraction = rounded % scale;
    return fraction == 0 ? QString::number(whole)
                         : QStringLiteral("%1.%2").arg(whole).arg(fraction);
}

QString shutterLabel(double seconds) {
    if (!std::isfinite(seconds) || seconds <= 0.0)
        return {};
    if (seconds >= 0.3)
        return decimalLabel(seconds, 1) + QLatin1Char('s');
    return QStringLiteral("1/%1").arg(qint64(std::floor(1.0 / seconds + 0.5)));
}

LibraryFileLabels fileLabels(const QString& filename, const ExifData& base) {
    static const QHash<QString, QString> notRaw = {
        {"jpg", "JPEG"}, {"jpeg", "JPEG"}, {"jpe", "JPEG"}, {"tif", "TIFF"}, {"tiff", "TIFF"},
        {"heic", "HEIF"}, {"heif", "HEIF"}, {"hif", "HEIF"}, {"png", "PNG"}, {"avif", "AVIF"},
        {"webp", "WEBP"}, {"jxl", "JXL"}, {"exr", "EXR"}, {"pfm", "PFM"}, {"ppm", "PNM"},
        {"pgm", "PNM"}, {"pnm", "PNM"}, {"gif", "GIF"}, {"j2k", "JPEG 2000"}, {"jp2", "JPEG 2000"},
        {"qoi", "QOI"}, {"bmp", "BMP"},
    };
    LibraryFileLabels labels;
    const QString suffix = QFileInfo(filename).suffix();
    labels.kind = notRaw.value(suffix.toLower(), QStringLiteral("RAW"));
    const QString upper = suffix.toUpper();
    labels.extension = (upper == QLatin1String("JPEG") || upper == QLatin1String("JPE")) ? QStringLiteral("JPG")
                     : upper == QLatin1String("TIF") ? QStringLiteral("TIFF") : upper;

    const QString make = base.make.toString();
    const QString model = base.cameraModel.toString();
    labels.camera = (make + QLatin1Char(' ') + model).trimmed();
    labels.bodySerial = rawStrings(base.raw, "SerialNumber").value(0);
    if (!labels.bodySerial.isEmpty())
        labels.bodyKey = QString::fromUtf8(QJsonDocument(QJsonArray{make, model, labels.bodySerial})
                                               .toJson(QJsonDocument::Compact));

    const double iso = base.iso.toDouble();
    if (std::isfinite(iso) && iso > 0.0)
        labels.iso = QString::number(qint64(std::floor(iso + 0.5)));
    const QString aperture = decimalLabel(base.aperture.toDouble(), 1);
    if (!aperture.isEmpty())
        labels.aperture = QStringLiteral("f/") + aperture;
    const QString focal = decimalLabel(base.focalLength.toDouble(), 0);
    if (!focal.isEmpty())
        labels.focal = focal + QStringLiteral(" mm");
    labels.shutter = shutterLabel(base.shutterSpeedS.toDouble());
    return labels;
}

} // namespace morfphoto
