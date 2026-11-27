/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once
#include <QHash>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVariant>
#include <QVector>

#include "morfphoto/PhotoTypes.h"

// -----------------------------------------------------------------------------
// Metadonnees de bibliotheque : EXIF et XMP reunis pour chaque version d'une photo.
//
// Une photo porte une ou plusieurs VERSIONS (copies virtuelles darktable), chacune
// avec son propre sidecar `.xmp`. morfPhoto les LIT seulement, sans jamais les ecrire.
// Fonctions pures, sans base ni disque, pour rester testables.
// -----------------------------------------------------------------------------
namespace morfphoto {

// Proprietes d'un sidecar, cle = « prefixe:nom » (dc:subject, xmp:Rating...).
struct SidecarData {
    bool ok = false;
    QHash<QString, QStringList> properties;
};

// Une version d'une photo, une fois EXIF et XMP fusionnes.
struct LibraryVersion {
    int         version = 0;
    bool        copy = false;
    QString     sidecar;              // chemin du sidecar, vide s'il n'y en a pas
    int         rating = 0;           // 0 a 5 ; 0 si rejetee
    bool        rejected = false;
    int         labels = 0;           // rouge 1, jaune 2, vert 4, bleu 8, violet 16
    QVariant    edited;               // bool, ou vide si inconnu
    QVariant    takenAt;
    QVariant    latitude;
    QVariant    longitude;
    QVariant    title;
    QVariant    description;
    QVariant    creator;
    QVariant    rights;
    QVariant    versionName;
    QVariant    publisher;
    QVariant    notes;
    QStringList keywords;             // niveaux separes par « | »
    QJsonObject rawXmp;
};

// Libelles d'un fichier, identiques a ceux que propose le client.
struct LibraryFileLabels {
    QString kind;
    QString extension;
    QString camera;
    QString bodyKey;
    QString bodySerial;
    QString iso;
    QString aperture;
    QString focal;
    QString shutter;
};

// Criteres de GET /api/v1/library. Listes vides = pas de filtre.
struct LibraryFilter {
    int         minRating = 0;
    QString     rejected;             // "" | all | hide | only
    QString     edited;               // "" | all | edited | unedited
    int         labels = 0;
    bool        unlabeled = false;
    QStringList kinds, cameras, bodies, lenses, keywords, iso, aperture, focal, shutter;
    QString     takenFrom, takenTo;   // AAAA-MM-JJ
    QString     folderPath;
    bool        recursive = false;
    QString     filename;
};

// Extensions lues seulement quand la bibliotheque est activee.
bool isExtendedImageExtension(const QString& extension);

// Rattache les sidecars d'un dossier a ses images et calcule leur empreinte.
void assignSidecars(QVector<FileInfo>& files, const QHash<QString, QVector<SidecarRef>>& byDirectory);

SidecarData parseSidecar(const QByteArray& bytes);

// Fusionne un sidecar (ou aucun) avec ce que le fichier image contient.
LibraryVersion mergeVersion(int version, const QString& sidecarPath, const SidecarData* sidecar,
                            const ExifData& base);

LibraryFileLabels fileLabels(const QString& filename, const ExifData& base);

// Arrondi decimal identique au client : demi superieur sur la valeur binaire exacte.
QString decimalLabel(double value, int places);
QString shutterLabel(double seconds);

} // namespace morfphoto
