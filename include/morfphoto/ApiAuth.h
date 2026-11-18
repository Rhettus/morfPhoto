/*
 * morfPhoto
 * Copyright (C) 2026 morfredus
 * SPDX-License-Identifier: GPL-3.0-only
 */

#pragma once
#include <QByteArray>
#include <QCryptographicHash>

namespace morfphoto {

// -----------------------------------------------------------------------------
// Cle d'API partagee (`Authorization: Bearer <cle>`), optionnelle : sans cle
// configuree, tout passe, pour ne casser aucun client existant du parc.
// -----------------------------------------------------------------------------

// Vrai pour les routes metier, les seules protegees : /healthz, /status et /modules
// restent ouverts pour que la supervision du parc continue de fonctionner.
inline bool isApiPath(const QByteArray& path) {
    return path.startsWith("/api/");
}

// Vrai si l'en-tete `Authorization` porte la cle attendue. On compare des empreintes
// sur toute leur longueur : le temps de reponse ne renseigne ni sur la cle ni sur sa taille.
inline bool isAuthorized(const QByteArray& authorization, const QByteArray& apiKey) {
    if (apiKey.isEmpty())
        return true;
    const QByteArray value = authorization.trimmed();
    if (value.left(7).toLower() != "bearer ")
        return false;
    const QByteArray given = QCryptographicHash::hash(value.mid(7).trimmed(), QCryptographicHash::Sha256);
    const QByteArray expected = QCryptographicHash::hash(apiKey, QCryptographicHash::Sha256);
    char diff = 0;
    for (int i = 0; i < expected.size(); ++i)
        diff |= given.at(i) ^ expected.at(i);
    return diff == 0;
}

} // namespace morfphoto
