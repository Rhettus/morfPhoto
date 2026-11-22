/*
 * morfPhoto - test de fumée headless (aucun réseau, aucun ExifTool).
 *
 * Vérifie les invariants du domaine : classification des types, garde-fou de
 * périmètre, souveraineté du mapping EXIF (sur un JSON figé), et tout le cycle
 * d'indexation (verdict incrémental via (path,size,mtime), disparu marqué puis
 * ravivé, sélection hors racine refusée, retrait doux préservant l'historique).
 *
 * L'indexeur est éprouvé avec un extracteur NUL : la logique de réconciliation ne
 * dépend pas des valeurs EXIF, ce qui rend le test portable et déterministe.
 * Compilé via l'option CMake MORFPHOTO_BUILD_SMOKE. Retourne 0 si tout passe.
 */

#include <cstdio>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QImage>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QVariantMap>
#include <QEventLoop>
#include <QTimer>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QUrl>
#include <QTcpServer>
#include <QTcpSocket>

#include "morfphoto/PhotoScanner.h"
#include "morfphoto/PhotoModule.h"
#include "morfphoto/HttpServer.h"
#include "morfphoto/ModuleRegistry.h"
#include "morfphoto/FolderWatcher.h"
#include "morfphoto/PhotoRepository.h"
#include "morfphoto/ExifExtractor.h"
#include "morfphoto/LibraryMetadata.h"
#include "morfphoto/Indexer.h"
#include "morfphoto/ContextFile.h"
#include "morfphoto/SmbSourceNaming.h"
#include "morfphoto/OriginCheck.h"
#include "morfphoto/ApiAuth.h"

using namespace morfphoto;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
                              else { std::printf("ok  : %s\n", msg); } } while (0)

static QString nowIso() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODate); }

static void writeBytes(const QString& path, int n) {
    QFile f(path);
    if (f.open(QIODevice::WriteOnly)) {
        f.write(QByteArray(n, 'x'));
        f.close();
    }
}

static int lastRunInt(PhotoRepository& repo, const char* key) {
    return repo.latestRun(nullptr).value(QLatin1String(key)).toInt();
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);

    const QString base = QDir::tempPath() + QStringLiteral("/morfphoto_smoke_%1")
                             .arg(QDateTime::currentMSecsSinceEpoch());
    QDir().mkpath(base + QStringLiteral("/photos/2024"));
    const QString photos = base + QStringLiteral("/photos");

    // --- 1) Scanner : classification et périmètre ---
    CHECK(fileTypeFor(QStringLiteral(".ARW")) == QLatin1String("raw"), "type .ARW -> raw (insensible casse)");
    CHECK(fileTypeFor(QStringLiteral(".jpg")) == QLatin1String("jpeg"), "type .jpg -> jpeg");
    CHECK(fileTypeFor(QStringLiteral(".xyz")) == QLatin1String("other"), "type inconnu -> other");
    CHECK(isWithinRoots(photos + QStringLiteral("/2024/x.jpg"), {photos}), "sous racine -> autorise");
    CHECK(!isWithinRoots(base + QStringLiteral("/autre/x.jpg"), {photos}), "hors racine -> refuse");
    CHECK(!isWithinRoots(photos + QStringLiteral("/../evasion.jpg"), {photos}), "'..' ne s'echappe pas");

    writeBytes(photos + QStringLiteral("/2024/a.jpg"), 100);
    writeBytes(photos + QStringLiteral("/2024/b.arw"), 200);
    writeBytes(photos + QStringLiteral("/2024/notes.txt"), 50);
    bool countDone = false;
    const qint64 nImg = countImageFiles(photos, true, {}, &countDone);
    CHECK(countDone && nImg == 2, "precomptage: 2 images, notes.txt ignore");

    // Identite canonique des sources SMB (hostname -> slug -> montage / creds).
    CHECK(hostnameSlug(QStringLiteral("ASUS-DEV")) == QLatin1String("asus-dev"),
          "slug ASUS-DEV -> asus-dev");
    CHECK(hostnameSlug(QStringLiteral("PC-FRED")) == QLatin1String("pc-fred"),
          "slug PC-FRED -> pc-fred");
    CHECK(mountpointForSlug(QStringLiteral("asus-dev"))
              == QLatin1String("/mnt/photos_asus-dev"),
          "montage /mnt/photos_<slug>");
    CHECK(credentialsPathForSlug(QStringLiteral("pc-fred"))
              == QLatin1String("/etc/morfsystem/smb-photos-pc-fred.cred"),
          "creds par machine");
    CHECK(looksLikeIpv4(QStringLiteral("192.168.1.39")), "IPv4 reconnue");
    CHECK(!looksLikeIpv4(QStringLiteral("ASUS-DEV")), "hostname n'est pas une IPv4");
    CHECK(isNewConventionMountpoint(QStringLiteral("/mnt/photos_asus-dev")),
          "nouvelle convention photos_");
    CHECK(!isNewConventionMountpoint(QStringLiteral("/mnt/photos")),
          "/mnt/photos generique refuse pour une nouvelle source");

    // Sonde d'accessibilité bornée : un dossier présent répond, un chemin absent est
    // déclaré indisponible sans attendre (déterministe, hors réseau).
    CHECK(probeAccessible(photos, 1000), "probe: dossier existant -> accessible");
    CHECK(!probeAccessible(base + QStringLiteral("/inexistant"), 200),
          "probe: chemin absent -> indisponible");

    // --- 2) Mapping EXIF (souveraineté), sur un JSON figé ---
    const QString json = QStringLiteral(
        "[{\"SourceFile\":\"x\",\"DateTimeOriginal\":\"2017-02-11 22:18:38\","
        "\"Make\":\"NIKON\",\"Model\":\"NIKON D7200\",\"LensModel\":\"18-105\","
        "\"FocalLength\":30.0,\"FNumber\":7.1,\"ExposureTime\":0.0166,"
        "\"ShutterSpeed\":\"1/60\",\"ISO\":3200}]");
    QString mapErr;
    const ExifData d = ExifExtractor::mapTags(json, &mapErr);
    CHECK(mapErr.isEmpty() && d.ok, "mapTags: succes");
    CHECK(d.focalLength.toDouble() == 30.0, "focale brute preservee (30)");
    CHECK(d.shutterSpeed.toString() == QLatin1String("1/60"), "vitesse lisible conservee");
    CHECK(d.shutterSpeedS.toDouble() == 0.0166, "vitesse numerique conservee");
    CHECK(d.cameraModel.toString() == QLatin1String("NIKON D7200"), "boitier mappe");
    CHECK(!d.raw.contains(QStringLiteral("SourceFile")), "raw_exif exclut SourceFile");
    QString errCase;
    const ExifData de = ExifExtractor::mapTags(
        QStringLiteral("[{\"SourceFile\":\"x\",\"Error\":\"boom\"}]"), &errCase);
    CHECK(!de.ok && !errCase.isEmpty(), "mapTags: Error -> ok=false, message");

    // --- 3) Cycle d'indexation (extracteur nul) ---

    PhotoRepository repo(QStringLiteral("smoke:main"));
    CHECK(repo.open(base + QStringLiteral("/db.sqlite")), "ouverture base + migrations");
    const int fid = repo.addFolder(photos, photos, QVariant(), true, false, QVariant(), nowIso());
    CHECK(fid > 0, "addFolder");

    Indexer idx(&repo, nullptr, {photos});
    IndexProgress lastProg;
    idx.setProgressCallback([&](const IndexProgress& p) { lastProg = p; });
    CHECK(idx.run(IndexMode::Full, {}, QStringLiteral("cli")) > 0, "passe full");
    CHECK(lastProg.filesTotal == 2, "progression: files_total = fichiers listes");
    CHECK(lastProg.filesSeen == 2, "progression: files_seen = corpus");
    CHECK(lastProg.filesTotalFinal, "progression: total clos en fin de passe");
    CHECK(lastProg.phase == QLatin1String("indexing"), "progression: phase indexing en fin");
    CHECK(repo.summary().value(QStringLiteral("files_present")).toInt() == 2,
          "2 fichiers indexes (notes.txt ignore)");

    idx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "files_new") == 0 && lastRunInt(repo, "files_updated") == 0,
          "incremental inchange: rien a faire");

    writeBytes(photos + QStringLiteral("/2024/a.jpg"), 250);   // taille differente
    idx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "files_updated") == 1, "fichier modifie -> 1 update");

    QFile::remove(photos + QStringLiteral("/2024/b.arw"));
    idx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "files_missing") == 1, "fichier disparu -> missing");
    QVariantMap fMissing; fMissing["state"] = QStringLiteral("missing");
    CHECK(repo.listPhotos(fMissing, 1, 10).value(QStringLiteral("total")).toInt() == 1,
          "un fichier en etat missing (jamais supprime)");

    writeBytes(photos + QStringLiteral("/2024/b.arw"), 200);   // reapparait a l'identique
    idx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
    CHECK(repo.summary().value(QStringLiteral("files_present")).toInt() == 2,
          "fichier revenu -> ravive present");

    // Sélection hors racine : refusée et journalisée, rien indexé.
    QDir().mkpath(base + QStringLiteral("/autre"));
    writeBytes(base + QStringLiteral("/autre/secret.jpg"), 100);
    const int fidBad = repo.addFolder(base + QStringLiteral("/autre"), photos, QVariant(), true, false, QVariant(), nowIso());
    idx.run(IndexMode::Full, {fidBad}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "errors_count") >= 1, "selection hors racine -> erreur journalisee");
    CHECK(repo.summary().value(QStringLiteral("files_present")).toInt() == 2,
          "rien indexe hors racine");

    // Retrait doux : les fichiers passent 'deleted', l'historique reste.
    repo.softDeleteFolder(fid, nowIso());
    CHECK(repo.summary().value(QStringLiteral("files_present")).toInt() == 0,
          "retrait doux -> plus aucun present");
    CHECK(repo.summary().value(QStringLiteral("files_total")).toInt() >= 2,
          "retrait doux -> historique conserve (lignes toujours la)");

    // deleted_at classe le dossier comme retiré (visible dans le détail JSON).
    bool wasDeleted = false;
    (void)repo.folderIdByPath(photos, &wasDeleted);
    CHECK(wasDeleted, "retrait doux -> deleted_at renseigne");

    // Restauration : le dossier redevient surveillé, une passe ravive les fichiers.
    repo.restoreFolder(fid);
    bool stillDeleted = true;
    (void)repo.folderIdByPath(photos, &stillDeleted);
    CHECK(!stillDeleted, "restauration -> deleted_at efface");
    idx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
    CHECK(repo.summary().value(QStringLiteral("files_present")).toInt() == 2,
          "restauration -> fichiers ravives (present)");

    // --- 3b) Export compact pour l'analyse (colonnaire + dictionnaires) ---
    {
        const QJsonObject ds = repo.photoDataset();
        CHECK(ds.value(QStringLiteral("count")).toInt() == 2,
              "dataset: 2 photos presentes exportees");
        const QJsonObject cols = ds.value(QStringLiteral("columns")).toObject();
        CHECK(cols.value(QStringLiteral("taken_at")).toArray().size() == 2,
              "dataset: colonne taken_at alignee sur count");
        CHECK(cols.value(QStringLiteral("folder_id")).toArray().size() == 2,
              "dataset: colonne folder_id alignee sur count");
        // Extracteur nul : aucune donnee EXIF => les colonnes EXIF sont NULL (jamais 0),
        // et les dictionnaires de chaines restent vides (pas d'index bidon).
        CHECK(cols.value(QStringLiteral("iso")).toArray().at(0).isNull(),
              "dataset: EXIF absent -> null preserve (pas de 0 trompeur)");
        CHECK(cols.value(QStringLiteral("camera")).toArray().at(0).isNull(),
              "dataset: boitier absent -> index null");
        CHECK(ds.value(QStringLiteral("dictionaries")).toObject()
                .value(QStringLiteral("camera")).toArray().isEmpty(),
              "dataset: dictionnaire boitiers vide sans EXIF");
        // file_type est connu par le scan (pas besoin d'EXIF) : il doit s'interner.
        CHECK(!cols.value(QStringLiteral("file_type")).toArray().at(0).isNull(),
              "dataset: file_type present -> index non null");
        // Table des dossiers : id -> libelle (pour filtrer/etiqueter par dossier).
        const QJsonObject folders = ds.value(QStringLiteral("folders")).toObject();
        CHECK(folders.value(QString::number(fid)).toString() == photos,
              "dataset: folders mappe l'id du dossier vers son chemin");

        // Empreinte de dedup : une par photo, alignee, non vide, et DISTINCTE pour
        // deux fichiers differents (a.jpg 250o vs b.arw 200o). C'est la cle qui permet
        // a l'analyse multi-sources de ne pas compter deux fois le meme fichier.
        const QJsonArray fp = cols.value(QStringLiteral("fingerprint")).toArray();
        CHECK(fp.size() == 2, "dataset: colonne fingerprint alignee sur count");
        CHECK(!fp.at(0).toString().isEmpty() && !fp.at(1).toString().isEmpty(),
              "dataset: empreintes non vides");
        CHECK(fp.at(0).toString() != fp.at(1).toString(),
              "dataset: deux fichiers differents -> empreintes distinctes");
    }

    // --- 4) Source distante perdue en cours de vie : ne pas confondre indisponible
    //         et supprimé. Une racine à part (montage réseau simulé) est indexée,
    //         puis rendue inaccessible : la passe suivante doit interrompre proprement
    //         SANS marquer aucun fichier disparu.
    const QString net = base + QStringLiteral("/net");   // racine « réseau » simulée
    QDir().mkpath(net);
    writeBytes(net + QStringLiteral("/x.jpg"), 100);
    writeBytes(net + QStringLiteral("/y.jpg"), 100);
    const int netFid = repo.addFolder(net, net, QVariant(), true, false, QVariant(), nowIso());
    // Indexeur dédié à cette racine ; timeout de sonde court (test déterministe).
    Indexer netIdx(&repo, nullptr, {net}, 300);
    netIdx.run(IndexMode::Full, {netFid}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "files_new") == 2, "source: 2 fichiers indexes au depart");
    CHECK(repo.latestRun(nullptr).value(QStringLiteral("state")).toString()
              == QLatin1String("done"), "source: premiere passe terminee (done)");

    // La racine disparaît (l'hote du partage s'endort / le montage tombe).
    QDir(net).removeRecursively();
    netIdx.run(IndexMode::Incremental, {netFid}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "files_missing") == 0,
          "source perdue -> AUCUN fichier marque disparu");
    CHECK(lastRunInt(repo, "files_unavailable") >= 1,
          "source perdue -> selection comptee indisponible");
    CHECK(repo.latestRun(nullptr).value(QStringLiteral("state")).toString()
              == QLatin1String("interrupted"),
          "source perdue -> passe interrompue (interrupted != done)");
    QVariantMap fNet; fNet["folder"] = netFid; fNet["state"] = QStringLiteral("present");
    CHECK(repo.listPhotos(fNet, 1, 10).value(QStringLiteral("total")).toInt() == 2,
          "source perdue -> fichiers deja acquis restent present");

    // Retour de la source : une passe ultérieure reprend normalement.
    QDir().mkpath(net);
    writeBytes(net + QStringLiteral("/x.jpg"), 100);
    writeBytes(net + QStringLiteral("/y.jpg"), 100);
    netIdx.run(IndexMode::Incremental, {netFid}, QStringLiteral("cli"));
    CHECK(repo.latestRun(nullptr).value(QStringLiteral("state")).toString()
              == QLatin1String("done"), "source revenue -> passe de nouveau normale (done)");

    // --- 5) Support AMOVIBLE (CD/DVD, archive) : le retrait du support ne vaut
    //         JAMAIS suppression. On indexe un « CD », puis on le « retire » en
    //         laissant le point de montage présent mais VIDE (cas qui, sans la
    //         protection removable, ferait marquer disparue toute l'archive et la
    //         sortirait de morfAnalytics). Les fichiers doivent rester 'present'.
    const QString cd = base + QStringLiteral("/cd");   // « point de montage » du CD
    QDir().mkpath(cd);
    writeBytes(cd + QStringLiteral("/p1.jpg"), 100);
    writeBytes(cd + QStringLiteral("/p2.arw"), 100);
    // Racine du CD = le point de montage lui-même ; sélection déclarée AMOVIBLE.
    const int cdFid = repo.addFolder(cd, cd, QVariant(QStringLiteral("Archive CD")),
                                     true, true, QVariant(QStringLiteral("PHOTOS-2015")), nowIso());
    CHECK(cdFid > 0, "addFolder amovible (CD)");
    Indexer cdIdx(&repo, nullptr, {cd}, 300);
    cdIdx.run(IndexMode::Full, {cdFid}, QStringLiteral("cli"));
    QVariantMap fCdPresent; fCdPresent["folder"] = cdFid; fCdPresent["state"] = QStringLiteral("present");
    CHECK(repo.listPhotos(fCdPresent, 1, 10).value(QStringLiteral("total")).toInt() == 2,
          "CD present -> 2 photos indexees");

    // Le libellé de volume est bien porté par la sélection (retrouver le disque).
    {
        bool foundCd = false;
        const QJsonArray fdet = repo.listFoldersDetail();
        for (const QJsonValue& v : fdet) {
            const QJsonObject o = v.toObject();
            if (o.value(QStringLiteral("id")).toInt() == cdFid) {
                foundCd = o.value(QStringLiteral("removable")).toInt() == 1 &&
                          o.value(QStringLiteral("volume_label")).toString() == QLatin1String("PHOTOS-2015");
            }
        }
        CHECK(foundCd, "CD: detail expose removable=1 et volume_label");
    }

    // ÉJECTION : le point de montage reste là mais devient VIDE (fichiers retirés).
    QFile::remove(cd + QStringLiteral("/p1.jpg"));
    QFile::remove(cd + QStringLiteral("/p2.arw"));
    cdIdx.run(IndexMode::Incremental, {cdFid}, QStringLiteral("cli"));
    CHECK(lastRunInt(repo, "files_missing") == 0,
          "CD retire (montage vide) -> AUCUN fichier marque disparu");
    CHECK(repo.listPhotos(fCdPresent, 1, 10).value(QStringLiteral("total")).toInt() == 2,
          "CD retire -> les 2 photos restent 'present' (persistance morfAnalytics)");

    // Persistance à travers un « reboot » : fermer puis rouvrir la base (le fichier
    // SQLite survit ; morfAnalytics re-lira ces photos). Support toujours absent.
    repo.close();
    PhotoRepository repo2(QStringLiteral("smoke:reboot"));
    CHECK(repo2.open(base + QStringLiteral("/db.sqlite")), "reouverture base (simulation reboot)");
    CHECK(repo2.listPhotos(fCdPresent, 1, 10).value(QStringLiteral("total")).toInt() == 2,
          "apres reboot -> photos du CD toujours presentes en base");

    // --- 6) Exclusion des ANALYSES sans effacer les donnees ---
    const int dsBefore = repo2.photoDataset().value(QStringLiteral("count")).toInt();
    repo2.setFolderAnalyticsExcluded(cdFid, true);
    const int dsExcluded = repo2.photoDataset().value(QStringLiteral("count")).toInt();
    CHECK(dsExcluded == dsBefore - 2,
          "exclusion analytique -> dataset perd les 2 photos du CD");
    CHECK(repo2.listPhotos(fCdPresent, 1, 10).value(QStringLiteral("total")).toInt() == 2,
          "exclusion analytique -> donnees CONSERVEES en base (non destructif)");
    repo2.setFolderAnalyticsExcluded(cdFid, false);
    CHECK(repo2.photoDataset().value(QStringLiteral("count")).toInt() == dsBefore,
          "reintegration analytique -> dataset revenu a l'identique");

    // --- 7) Purge DEFINITIVE (irreversible) ---
    const int purged = repo2.purgeFolder(cdFid);
    CHECK(purged == 2, "purge du dossier CD -> 2 fichiers effaces");
    CHECK(repo2.listPhotos(fCdPresent, 1, 10).value(QStringLiteral("total")).toInt() == 0,
          "purge -> plus aucune ligne pour ce dossier (suppression reelle)");
    {
        bool cdGone = true;
        (void)repo2.folderIdByPath(cd, nullptr);
        for (const QJsonValue& v : repo2.listFoldersDetail())
            if (v.toObject().value(QStringLiteral("id")).toInt() == cdFid) cdGone = false;
        CHECK(cdGone, "purge du dossier -> la selection elle-meme est retiree");
    }
    // Purge totale : remise a zero complete du domaine.
    repo2.purgeAll();
    CHECK(repo2.summary().value(QStringLiteral("files_total")).toInt() == 0 &&
          repo2.listFoldersDetail().isEmpty(),
          "purge totale -> base videe (fichiers + selections)");

    // --- 8) CONTEXTE photographique par dossier (contrat morfphoto-context/2) ---
    //   Parseur tolerant + les 4 cas de reference + decouverte bout-en-bout + jointure
    //   dataset (null vs INCONNU distincts) + idempotence par mtime.
    {
        auto parseCtx = [](const char* json) { return ContextFile::parse(QByteArray(json)); };

        // 8a) Les quatre cas de reference qui valident le modele a deux dimensions.
        const FolderContext zoo = parseCtx(
            "{\"schema\":2,\"context\":\"LIBRE\",\"subject\":\"ANIMAUX\",\"motif\":\"Zoo\"}");
        CHECK(zoo.status == QLatin1String("ok")
              && zoo.context.toString() == QLatin1String("LIBRE")
              && zoo.subject.toString() == QLatin1String("ANIMAUX"),
              "contexte: zoo -> LIBRE + ANIMAUX (jamais SPECIALISEE)");

        const FolderContext cig = parseCtx(
            "{\"schema\":2,\"context\":\"SPECIALISEE\",\"subject\":\"ANIMAUX\",\"motif\":\"Cigognes\"}");
        CHECK(cig.status == QLatin1String("ok")
              && cig.context.toString() == QLatin1String("SPECIALISEE")
              && cig.subject.toString() == QLatin1String("ANIMAUX"),
              "contexte: cigognes -> SPECIALISEE + ANIMAUX (distinct du zoo)");

        const FolderContext mar = parseCtx(
            "{\"schema\":2,\"context\":\"EVENEMENT\",\"subject\":\"PERSONNES\","
            "\"motif\":\"Demande en mariage\"}");
        CHECK(mar.status == QLatin1String("ok")
              && mar.context.toString() == QLatin1String("EVENEMENT")
              && mar.subject.toString() == QLatin1String("PERSONNES"),
              "contexte: demande en mariage -> EVENEMENT + PERSONNES");

        const FolderContext bal = parseCtx(
            "{\"schema\":2,\"context\":\"DECOUVERTE\",\"subject\":\"GENERAL\"}");
        CHECK(bal.status == QLatin1String("ok")
              && bal.context.toString() == QLatin1String("DECOUVERTE")
              && bal.subject.toString() == QLatin1String("GENERAL"),
              "contexte: balade -> DECOUVERTE + GENERAL");

        // INCONNU est une VALEUR valide (qualifie mais non tranche), jamais un defaut.
        const FolderContext inc = parseCtx(
            "{\"schema\":2,\"context\":\"INCONNU\",\"subject\":\"GENERAL\"}");
        CHECK(inc.status == QLatin1String("ok")
              && inc.context.toString() == QLatin1String("INCONNU"),
              "contexte: INCONNU est une valeur qualifiee (distinct de non qualifie)");

        // Invalides : jamais bloquant, toujours diagnostiquable.
        CHECK(parseCtx("{ pas du json").status == QLatin1String("invalid"),
              "contexte: json casse -> invalid");
        CHECK(parseCtx("{\"context\":\"LIBRE\",\"subject\":\"GENERAL\"}").status
                  == QLatin1String("invalid"),
              "contexte: schema absent -> invalid");
        CHECK(parseCtx("{\"schema\":2,\"context\":\"LIBRE\"}").status == QLatin1String("invalid"),
              "contexte: subject manquant en schema 2 -> invalid");

        // Valeur hors vocabulaire : conservee + signalee, jamais convertie.
        const FolderContext unk = parseCtx(
            "{\"schema\":2,\"context\":\"FETE\",\"subject\":\"GENERAL\"}");
        CHECK(unk.status == QLatin1String("ok")
              && unk.context.toString() == QLatin1String("FETE")
              && unk.warnings.contains(QStringLiteral("context_unknown")),
              "contexte: valeur hors vocabulaire conservee + signalee");

        // Casse et espaces normalises en majuscule.
        const FolderContext low = parseCtx(
            "{\"schema\":2,\"context\":\" decouverte \",\"subject\":\"paysage\"}");
        CHECK(low.context.toString() == QLatin1String("DECOUVERTE")
              && low.subject.toString() == QLatin1String("PAYSAGE"),
              "contexte: trim + majuscule a la lecture");

        // 8b) Decouverte bout-en-bout : deux dossiers, un qualifie, un non.
        const QString cbase = base + QStringLiteral("/ctx");
        const QString evDir  = cbase + QStringLiteral("/2026-09-01-demande");
        const QString zooDir = cbase + QStringLiteral("/2026-09-05-zoo");
        QDir().mkpath(evDir);
        QDir().mkpath(zooDir);
        writeBytes(evDir + QStringLiteral("/e1.jpg"), 100);
        writeBytes(zooDir + QStringLiteral("/z1.jpg"), 100);
        {
            QFile f(evDir + QStringLiteral("/.morfphoto.json"));
            if (f.open(QIODevice::WriteOnly)) {
                f.write("{\"schema\":2,\"context\":\"EVENEMENT\",\"subject\":\"PERSONNES\"}");
                f.close();
            }
        }
        // Le dossier zoo reste sans `.morfphoto.json` : non qualifie.

        PhotoRepository crepo(QStringLiteral("smoke:ctx"));
        CHECK(crepo.open(cbase + QStringLiteral("/db.sqlite")),
              "contexte: base ouverte (migrations jusqu'a v5)");
        (void)crepo.addFolder(cbase, cbase, QVariant(), true, false, QVariant(), nowIso());
        Indexer cidx(&crepo, nullptr, {cbase});
        cidx.run(IndexMode::Full, {}, QStringLiteral("cli"));

        CHECK(crepo.getContext(evDir).value(QStringLiteral("status")).toString()
                  == QLatin1String("qualified"),
              "contexte: dossier avec json -> qualified");
        CHECK(crepo.getContext(evDir).value(QStringLiteral("context")).toString()
                  == QLatin1String("EVENEMENT"),
              "contexte: valeur lue depuis le disque");
        CHECK(crepo.getContext(zooDir).value(QStringLiteral("status")).toString()
                  == QLatin1String("unqualified"),
              "contexte: dossier sans json -> unqualified (indexation jamais bloquee)");

        // Dataset : colonne context alignee ; 1 EVENEMENT interne, 1 null (distinct d'INCONNU).
        const QJsonObject cds  = crepo.photoDataset();
        const QJsonObject cc   = cds.value(QStringLiteral("columns")).toObject();
        const QJsonArray ctxCol = cc.value(QStringLiteral("context")).toArray();
        CHECK(ctxCol.size() == 2, "contexte: colonne context alignee sur les 2 photos");
        int nNull = 0, nSet = 0;
        for (const QJsonValue& v : ctxCol) { if (v.isNull()) ++nNull; else ++nSet; }
        const QJsonArray ctxDict = cds.value(QStringLiteral("dictionaries")).toObject()
                                      .value(QStringLiteral("context")).toArray();
        CHECK(nNull == 1 && nSet == 1
              && ctxDict.contains(QJsonValue(QStringLiteral("EVENEMENT"))),
              "contexte: dataset -> 1 qualifiee (EVENEMENT), 1 null (non qualifiee)");

        // listContexts : 2 dossiers ; filtre unqualified -> le zoo.
        CHECK(crepo.listContexts(QString()).size() == 2,
              "contexte: listContexts -> 2 dossiers de photos");
        const QJsonArray unq = crepo.listContexts(QStringLiteral("unqualified"));
        CHECK(unq.size() == 1
              && unq.at(0).toObject().value(QStringLiteral("label")).toString()
                  == QLatin1String("2026-09-05-zoo"),
              "contexte: filtre unqualified -> le zoo");

        // Idempotence par mtime, puis retrait du json -> le dossier redevient non qualifie.
        cidx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
        CHECK(crepo.getContext(evDir).value(QStringLiteral("status")).toString()
                  == QLatin1String("qualified"),
              "contexte: 2e passe idempotente, contexte conserve");
        QFile::remove(evDir + QStringLiteral("/.morfphoto.json"));
        cidx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
        CHECK(crepo.getContext(evDir).value(QStringLiteral("status")).toString()
                  == QLatin1String("unqualified"),
              "contexte: json retire -> dossier redevient non qualifie");
        crepo.close();
    }

#ifdef Q_OS_LINUX
    // --- 9) Surveillance inotify : portees ciblees par repertoire / sous-arbre ---
    {
        const QString wdir = QDir::cleanPath(base + QStringLiteral("/watch"));
        const QString flat = QDir::cleanPath(base + QStringLiteral("/watch-flat"));
        QDir().mkpath(wdir + QStringLiteral("/old"));
        QDir().mkpath(flat + QStringLiteral("/sub"));
        FolderWatcher watcher(50, 1000);
        QVector<IndexScope> changed;
        QEventLoop loop;
        QObject::connect(&watcher, &FolderWatcher::scopesChanged, &loop,
                         [&](const QVector<IndexScope>& scopes) { changed = scopes; loop.quit(); });
        // Attend un signal (ou le delai) puis rend les portees signalees.
        auto waitChange = [&](int ms) {
            changed.clear();
            QTimer::singleShot(ms, &loop, &QEventLoop::quit);
            loop.exec();
            return changed;
        };
        watcher.setTargets({{7, wdir, true}, {8, flat, false}});
        CHECK(watcher.statusJson().value(QStringLiteral("state")).toString() == QLatin1String("active"),
              "inotify: surveillance active");

        writeBytes(wdir + QStringLiteral("/n.jpg"), 10);
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir, false}}),
              "inotify: nouvelle photo -> portee non recursive du dossier");
        writeBytes(wdir + QStringLiteral("/notes.txt"), 10);
        CHECK(waitChange(300).isEmpty(), "inotify: fichier non image ignore");
        QFile::rename(wdir + QStringLiteral("/n.jpg"), wdir + QStringLiteral("/m.jpg"));
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir, false}}),
              "inotify: renommage -> portee du dossier");
        QFile::remove(wdir + QStringLiteral("/m.jpg"));
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir, false}}),
              "inotify: suppression -> portee du dossier");

        QDir().mkpath(wdir + QStringLiteral("/new"));
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir + QStringLiteral("/new"), true}}),
              "inotify: nouveau dossier -> portee recursive du sous-dossier");
        writeBytes(wdir + QStringLiteral("/new/p.jpg"), 10);
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir + QStringLiteral("/new"), false}}),
              "inotify: photo dans un nouveau dossier -> portee du sous-dossier");

        QDir(wdir).rename(QStringLiteral("old"), QStringLiteral("renamed"));
        const QVector<IndexScope> renameScopes = waitChange(2000);
        CHECK(renameScopes.size() == 2
              && renameScopes.contains(IndexScope{7, wdir + QStringLiteral("/old"), true})
              && renameScopes.contains(IndexScope{7, wdir + QStringLiteral("/renamed"), true}),
              "inotify: dossier renomme -> ancienne et nouvelle portees recursives");
        writeBytes(wdir + QStringLiteral("/renamed/q.jpg"), 10);
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir + QStringLiteral("/renamed"), false}}),
              "inotify: photo dans un dossier renomme -> portee du sous-dossier");

        QFile::remove(wdir + QStringLiteral("/renamed/q.jpg"));
        QDir(wdir).rmdir(QStringLiteral("renamed"));
        CHECK(waitChange(2000) == (QVector<IndexScope>{{7, wdir + QStringLiteral("/renamed"), true}}),
              "inotify: sous-dossier supprime -> portee recursive du sous-dossier");

        writeBytes(flat + QStringLiteral("/sub/x.jpg"), 10);
        CHECK(waitChange(300).isEmpty(), "inotify: selection non recursive ignore ses sous-dossiers");
        writeBytes(flat + QStringLiteral("/y.jpg"), 10);
        CHECK(waitChange(2000) == (QVector<IndexScope>{{8, flat, false}}),
              "inotify: selection non recursive voit son dossier");
    }
#endif

    // --- Revue C++ 2026-11-07 : fonctions pures de securite ---
    // `$` Qt accepte un NL final : les controles ancres doivent le refuser.
    CHECK(isValidSourceSlug(QStringLiteral("asus-dev")), "slug valide accepte");
    CHECK(!isValidSourceSlug(QStringLiteral("asus-dev\n")), "slug avec NL final refuse");
    CHECK(!isManagedMountpoint(QStringLiteral("/mnt/photos_asus\n")),
          "point de montage avec NL final refuse");
    CHECK(isManagedMountpoint(QStringLiteral("/mnt/photos_asus")), "point de montage gere accepte");
    CHECK(!isNewConventionMountpoint(QStringLiteral("/mnt/photos_a\n")),
          "point de montage (nouvelle convention) avec NL final refuse");

    // Marqueur stay_open : reconnu seulement seul sur sa ligne.
    {
        const QByteArray m = "{ready3}";
        CHECK(ExifExtractor::markerPos("[{}]\n{ready3}\n", m) == 5, "marqueur seul sur sa ligne reconnu");
        CHECK(ExifExtractor::markerPos("[{\"SourceFile\":\"/x/{ready3}.jpg\"}]\n", m) < 0,
              "marqueur dans un nom de fichier ignore");
        CHECK(ExifExtractor::markerPos("x\n{ready3}", m) < 0, "marqueur sans fin de ligne: attendre");
        CHECK(ExifExtractor::markerPos("{ready3}\r\n", m) == 0, "marqueur CRLF reconnu");
    }

    // --- 10) Bibliotheque : EXIF + XMP reunis ---
    {
        const QString baseDir = base;
        CHECK(decimalLabel(2.55, 1) == QLatin1String("2.5"), "libelle: 2.55 -> 2.5 (valeur binaire)");
        CHECK(decimalLabel(2.25, 1) == QLatin1String("2.3"), "libelle: 2.25 -> 2.3 (demi superieur)");
        CHECK(decimalLabel(35.0, 0) == QLatin1String("35"), "libelle: 35 mm entier");
        CHECK(decimalLabel(2.0, 1) == QLatin1String("2"), "libelle: f/2 sans decimale");
        CHECK(shutterLabel(0.004) == QLatin1String("1/250"), "libelle: vitesse rapide en fraction");
        CHECK(shutterLabel(0.5) == QLatin1String("0.5s"), "libelle: vitesse lente en secondes");

        const QByteArray ns =
            "xmlns:x=\"adobe:ns:meta/\" xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" "
            "xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
            "xmlns:lr=\"http://ns.adobe.com/lightroom/1.0/\" xmlns:darktable=\"http://darktable.sf.net/\" "
            "xmlns:exif=\"http://ns.adobe.com/exif/1.0/\" xmlns:immage=\"https://github.com/Rhettus/immage/ns/1.0/\"";
        auto xmp = [&ns](const QByteArray& attributes, const QByteArray& body) {
            return "<x:xmpmeta " + ns + "><rdf:RDF><rdf:Description rdf:about=\"\" " + attributes + ">"
                   + body + "</rdf:Description></rdf:RDF></x:xmpmeta>";
        };
        const QByteArray bag =
            "<darktable:history><rdf:Seq><rdf:li darktable:num=\"0\"/></rdf:Seq></darktable:history>"
            "<darktable:colorlabels><rdf:Seq><rdf:li>0</rdf:li><rdf:li>3</rdf:li></rdf:Seq></darktable:colorlabels>"
            "<dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Titre</rdf:li></rdf:Alt></dc:title>"
            "<dc:subject><rdf:Bag><rdf:li>japan</rdf:li></rdf:Bag></dc:subject>"
            "<lr:hierarchicalSubject><rdf:Bag><rdf:li>travel|japan</rdf:li>"
            "<rdf:li>darktable|format|orf</rdf:li></rdf:Bag></lr:hierarchicalSubject>";
        const QByteArray edited = xmp(
            "xmp:Rating=\"4\" darktable:xmp_version=\"5\" darktable:history_auto_hash=\"a\" "
            "darktable:history_basic_hash=\"b\" darktable:history_current_hash=\"c\" "
            "exif:DateTimeOriginal=\"2023:02:19 17:52:53.000\" exif:GPSLatitude=\"48,30.0S\" "
            "exif:GPSLongitude=\"2,15.0E\"", bag);

        ExifData exifBase;
        exifBase.takenAt = QStringLiteral("2020-01-01 00:00:00");
        exifBase.rating = 1;
        exifBase.latitude = 10.0;
        exifBase.longitude = 20.0;
        exifBase.raw[QStringLiteral("Subject")] = QStringLiteral("embedded");

        const SidecarData data = parseSidecar(edited);
        CHECK(data.ok && !data.properties.contains(QStringLiteral("darktable:history")),
              "xmp: sidecar lu, historique d'edition ignore");
        const LibraryVersion v = mergeVersion(0, QStringLiteral("/x.xmp"), &data, exifBase);
        CHECK(v.rating == 4 && !v.rejected, "xmp: la note du sidecar l'emporte");
        CHECK(v.labels == (1 | 8), "xmp: etiquettes darktable en bits");
        CHECK(v.edited.toBool(), "xmp: empreinte differente de auto et basic -> retouchee");
        CHECK(v.keywords == QStringList{QStringLiteral("travel|japan")},
              "xmp: hierarchie conservee, etiquettes darktable| exclues");
        CHECK(v.takenAt.toString() == QLatin1String("2023-02-19 17:52:53"), "xmp: date du sidecar prioritaire");
        CHECK(qFuzzyCompare(v.latitude.toDouble(), -48.5), "xmp: GPS sud converti");
        CHECK(v.title.toString() == QLatin1String("Titre"), "xmp: titre lu");

        const SidecarData autoOnly = parseSidecar(xmp(
            "darktable:xmp_version=\"5\" darktable:history_auto_hash=\"a\" "
            "darktable:history_current_hash=\"a\" xmp:Rating=\"-1\"", ""));
        const LibraryVersion av = mergeVersion(0, QStringLiteral("/x.xmp"), &autoOnly, exifBase);
        CHECK(av.edited.isValid() && !av.edited.toBool(), "xmp: reglages automatiques seuls -> non retouchee");
        CHECK(av.rejected && av.rating == 0, "xmp: note -1 -> rejetee");
        CHECK(av.keywords.isEmpty(), "xmp: sidecar darktable sans mot-cle fait foi");

        const SidecarData managed = parseSidecar(xmp("immage:locationManaged=\"True\"", ""));
        CHECK(mergeVersion(0, QStringLiteral("/x.xmp"), &managed, exifBase).latitude.isNull(),
              "xmp: locationManaged -> GPS retire volontairement");
        const SidecarData foreign = parseSidecar(xmp("xmp:Label=\"Green\"", ""));
        const LibraryVersion fv = mergeVersion(0, QStringLiteral("/x.xmp"), &foreign, exifBase);
        CHECK(fv.labels == 4 && !fv.edited.isValid(), "xmp: autre logiciel -> etiquette lue, retouche inconnue");
        CHECK(fv.keywords == QStringList{QStringLiteral("embedded")}, "xmp: mots-cles embarques en repli");
        CHECK(!parseSidecar("<x:xmpmeta><broken").ok, "xmp: sidecar invalide signale");

        const LibraryFileLabels labels = fileLabels(QStringLiteral("a.jpeg"), exifBase);
        CHECK(labels.kind == QLatin1String("JPEG") && labels.extension == QLatin1String("JPG"),
              "xmp: type de fichier comme le client");
        CHECK(fileLabels(QStringLiteral("a.ORF"), exifBase).kind == QLatin1String("RAW"), "xmp: groupe RAW");

        // Cycle complet sur disque.
        const QString lib = baseDir + QStringLiteral("/library");
        QDir().mkpath(lib + QStringLiteral("/2024/sub"));
        auto put = [](const QString& path, const QByteArray& bytes) {
            QFile f(path);
            if (f.open(QIODevice::WriteOnly)) f.write(bytes);
        };
        writeBytes(lib + QStringLiteral("/2024/a.nef"), 100);
        writeBytes(lib + QStringLiteral("/2024/a_01.nef"), 110);       // vrai fichier, pas une copie
        writeBytes(lib + QStringLiteral("/2024/b.jpg"), 120);
        writeBytes(lib + QStringLiteral("/2024/sub/c.sr2"), 130);      // format supplementaire
        put(lib + QStringLiteral("/2024/a.nef.xmp"), edited);
        put(lib + QStringLiteral("/2024/a_02.nef.xmp"), xmp(
            "xmp:Rating=\"2\" darktable:xmp_version=\"5\"",
            "<dc:subject><rdf:Bag><rdf:li>copy-only</rdf:li></rdf:Bag></dc:subject>"));
        put(lib + QStringLiteral("/2024/a_01.nef.xmp"), xmp("xmp:Rating=\"5\"", ""));
        put(lib + QStringLiteral("/2024/b.xmp"), xmp("xmp:Rating=\"3\"", ""));

        PhotoRepository lrepo(QStringLiteral("smoke:library"));
        CHECK(lrepo.open(lib + QStringLiteral("/db.sqlite")), "bibliotheque: base ouverte (migration v7)");
        const int libFolder = lrepo.addFolder(lib, lib, QVariant(), true, false, QVariant(), nowIso());

        Indexer plain(&lrepo, nullptr, {lib});
        plain.run(IndexMode::Full, {}, QStringLiteral("cli"));
        CHECK(lrepo.summary().value(QStringLiteral("files_present")).toInt() == 3,
              "bibliotheque desactivee: formats supplementaires ignores");
        CHECK(lrepo.libraryList({}, 1, 50).value(QStringLiteral("total")).toInt() == 0,
              "bibliotheque desactivee: aucune donnee XMP");

        Indexer lidx(&lrepo, nullptr, {lib});
        lidx.setLibraryEnabled(true);
        lidx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
        const QJsonArray libraryTree = lrepo.librarySubfolders(lib).value("items").toArray();
        CHECK(libraryTree.size() == 1 &&
              libraryTree.first().toObject().value("path").toString() == lib + "/2024" &&
              libraryTree.first().toObject().value("has_children").toBool(),
              "library subfolders: immediate child with deeper descendants");
        const QJsonArray yearTree = lrepo.librarySubfolders(lib + "/2024").value("items").toArray();
        CHECK(yearTree.size() == 1 &&
              yearTree.first().toObject().value("path").toString() == lib + "/2024/sub" &&
              !yearTree.first().toObject().value("has_children").toBool(),
              "library subfolders: leaf and direct photos excluded");
        CHECK(lrepo.librarySubfolders(lib + "/202").value("items").toArray().isEmpty(),
              "library subfolders: reject sibling paths with similar prefixes");
        CHECK(lrepo.libraryList({}, 1, 50).value(QStringLiteral("total")).toInt() == 4,
              "bibliotheque: photos existantes relues + nouveau format");

        auto total = [&lrepo](const LibraryFilter& f) {
            return lrepo.libraryList(f, 1, 50).value(QStringLiteral("total")).toInt();
        };
        LibraryFilter parent; parent.keywords = {QStringLiteral("travel")};
        CHECK(total(parent) == 1, "filtre: un mot-cle parent couvre ses enfants");
        LibraryFilter partial; partial.keywords = {QStringLiteral("trav")};
        CHECK(total(partial) == 0, "filtre: un debut de mot n'est pas un parent");
        LibraryFilter sameVersion; sameVersion.keywords = {QStringLiteral("copy-only")}; sameVersion.minRating = 4;
        CHECK(total(sameVersion) == 0, "filtre: toutes les conditions sur la meme version");
        LibraryFilter copyOnly; copyOnly.keywords = {QStringLiteral("copy-only")}; copyOnly.minRating = 2;
        const QJsonObject copyPage = lrepo.libraryList(copyOnly, 1, 50);
        const QJsonObject item = copyPage.value(QStringLiteral("items")).toArray().at(0).toObject();
        CHECK(item.value(QStringLiteral("matched_versions")).toArray() == QJsonArray{2},
              "filtre: version correspondante indiquee");
        CHECK(item.value(QStringLiteral("versions")).toArray().size() == 2, "versions: copies imbriquees");
        CHECK(item.value(QStringLiteral("relative_path")).toString() == QLatin1String("2024/a.nef"),
              "versions: chemin relatif a la racine");
        LibraryFilter editedOnly; editedOnly.edited = QStringLiteral("edited");
        CHECK(total(editedOnly) == 1, "filtre: retouchees");
        LibraryFilter uneditedOnly; uneditedOnly.edited = QStringLiteral("unedited");
        CHECK(total(uneditedOnly) == 1, "filtre: sans sidecar -> non retouchee, inconnu exclu");
        LibraryFilter realFile; realFile.filename = QStringLiteral("a_01"); realFile.minRating = 5;
        CHECK(total(realFile) == 1, "sidecar: un vrai fichier a_01 garde le sien");
        LibraryFilter shared; shared.filename = QStringLiteral("b.jpg"); shared.minRating = 3;
        CHECK(total(shared) == 1, "sidecar: repli sur b.xmp");
        LibraryFilter kind; kind.kinds = {QStringLiteral("RAW")};
        CHECK(total(kind) == 3, "filtre: groupe RAW");
        LibraryFilter folder; folder.folderPath = lib + QStringLiteral("/2024");
        CHECK(total(folder) == 3, "filtre: dossier seul");
        folder.recursive = true;
        CHECK(total(folder) == 4, "filtre: dossier et sous-dossiers");

        const QJsonObject facets = lrepo.libraryFacets({});
        bool parentCounted = false;
        for (const QJsonValue& value : facets.value(QStringLiteral("keywords")).toArray())
            parentCounted = parentCounted || (value.toObject().value(QStringLiteral("value")).toString() == QLatin1String("travel")
                                              && value.toObject().value(QStringLiteral("count")).toInt() == 1);
        CHECK(parentCounted, "facettes: le niveau parent est compte");

        // Seul le sidecar change : detecte sans toucher a l'image.
        put(lib + QStringLiteral("/2024/b.xmp"), xmp("xmp:Rating=\"1\" dc:format=\"changed\"", ""));
        lidx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));
        LibraryFilter lowered; lowered.filename = QStringLiteral("b.jpg"); lowered.minRating = 2;
        CHECK(total(lowered) == 0, "sidecar modifie -> nouvelle note prise en compte");

        const QJsonArray allItems = lrepo.libraryList({}, 1, 50).value(QStringLiteral("items")).toArray();
        const int id1 = allItems.at(0).toObject().value(QStringLiteral("id")).toInt();
        const int id2 = allItems.at(1).toObject().value(QStringLiteral("id")).toInt();
        const QJsonArray batchRaw = lrepo.libraryPhotos({id2, id1, 999999}, true);
        CHECK(batchRaw.size() == 2
              && batchRaw.at(0).toObject().value(QStringLiteral("id")).toInt() == id2
              && batchRaw.at(1).toObject().value(QStringLiteral("id")).toInt() == id1,
              "libraryPhotos: ordre d'entree preserve et id inconnu ignore");
        CHECK(batchRaw.at(0).toObject().contains(QStringLiteral("raw_exif"))
              && batchRaw.at(1).toObject().contains(QStringLiteral("raw_exif")),
              "libraryPhotos: raw_exif inclus si withRaw=true");
        const QJsonArray batchNoRaw = lrepo.libraryPhotos({id2, id1}, false);
        CHECK(batchNoRaw.size() == 2
              && !batchNoRaw.at(0).toObject().contains(QStringLiteral("raw_exif"))
              && !batchNoRaw.at(1).toObject().contains(QStringLiteral("raw_exif")),
              "libraryPhotos: raw_exif omis si withRaw=false");

        lrepo.purgeFolder(libFolder);
        CHECK(lrepo.libraryList({}, 1, 50).value(QStringLiteral("total")).toInt() == 0,
              "purge: donnees XMP effacees avec le fichier");
        lrepo.close();
    }

    // Anti-CSRF : Origin different de Host sur une ecriture = refus.
    CHECK(!isCrossOriginWrite("POST", "", "pi:8791"), "sans Origin (client non navigateur): passe");
    CHECK(!isCrossOriginWrite("POST", "http://pi:8791", "pi:8791"), "meme origine: passe");
    CHECK(isCrossOriginWrite("POST", "http://evil.example", "pi:8791"), "origine tierce: refus");
    CHECK(isCrossOriginWrite("DELETE", "null", "pi:8791"), "Origin null: refus");
    CHECK(!isCrossOriginWrite("GET", "http://evil.example", "pi:8791"), "GET jamais bloque");

    // Cle d'API : optionnelle, exigee seulement sur /api/ quand elle est configuree.
    CHECK(isAuthorized("", ""), "cle: sans cle configuree, tout passe");
    CHECK(isAuthorized("Bearer s3cret", "s3cret"), "cle: bonne cle acceptee");
    CHECK(isAuthorized("bearer   s3cret ", "s3cret"), "cle: schema insensible a la casse");
    CHECK(!isAuthorized("", "s3cret"), "cle: en-tete absent refuse");
    CHECK(!isAuthorized("Bearer faux", "s3cret"), "cle: mauvaise cle refusee");
    CHECK(!isAuthorized("Bearer s3cret2", "s3cret"), "cle: cle plus longue refusee");
    CHECK(!isAuthorized("Basic s3cret", "s3cret"), "cle: autre schema refuse");
    CHECK(!isAuthorized("Bearer ", "s3cret"), "cle: valeur vide refusee");
    CHECK(isApiPath("/api/v1/photos"), "cle: /api/ protege");
    CHECK(!isApiPath("/healthz") && !isApiPath("/status"), "cle: supervision ouverte");

    repo2.close();
    {
        const QString jpegPath = base + QStringLiteral("/plain.JPG");
        QImage original(800, 600, QImage::Format_RGB32);
        original.fill(Qt::blue);
        CHECK(original.save(jpegPath, "JPEG"), "thumbnail: write fixture without an embedded preview");
        PhotoModule photos(QStringLiteral("smoke:thumbnails"), QJsonObject{{"roots", QJsonArray{base}}});
        const QImage thumbnail = QImage::fromData(photos.thumbnailReader(false)(jpegPath), "JPEG");
        CHECK(thumbnail.size() == QSize(400, 300),
              "thumbnail: scale the original JPEG without ExifTool and preserve its aspect ratio");
    }

    // --- 11) Fusion de portees et indexation ciblee (runScopes) ---
    {
        // 11a) Coalescence de mergeScope.
        {
            QVector<IndexScope> scopes;
            mergeScope(scopes, {1, QStringLiteral("/a"), false});
            mergeScope(scopes, {1, QStringLiteral("/a"), false});
            CHECK(scopes == (QVector<IndexScope>{{1, QStringLiteral("/a"), false}}),
                  "mergeScope: doublon exact ignore");

            mergeScope(scopes, {1, QStringLiteral("/a"), true});
            CHECK(scopes == (QVector<IndexScope>{{1, QStringLiteral("/a"), true}}),
                  "mergeScope: non recursif promu en recursif");

            mergeScope(scopes, {1, QStringLiteral("/a/b"), false});
            mergeScope(scopes, {1, QStringLiteral("/a/b/c"), true});
            CHECK(scopes == (QVector<IndexScope>{{1, QStringLiteral("/a"), true}}),
                  "mergeScope: ancetre recursif absorbe les descendants ajoutes ensuite");

            QVector<IndexScope> reverse;
            mergeScope(reverse, {1, QStringLiteral("/a/b"), false});
            mergeScope(reverse, {1, QStringLiteral("/a/b/c"), true});
            mergeScope(reverse, {1, QStringLiteral("/a"), true});
            CHECK(reverse == (QVector<IndexScope>{{1, QStringLiteral("/a"), true}}),
                  "mergeScope: ancetre recursif absorbe les descendants deja presents");

            mergeScope(reverse, {2, QStringLiteral("/a/b"), false});
            CHECK(reverse.size() == 2
                  && reverse.contains(IndexScope{1, QStringLiteral("/a"), true})
                  && reverse.contains(IndexScope{2, QStringLiteral("/a/b"), false}),
                  "mergeScope: folderId differents jamais fusionnes");
        }

        // 11b) Indexation ciblee + existingFilesInScope + contextes + lots > 500.
        const QString sroot = QDir::cleanPath(base + QStringLiteral("/scoped"));
        const QString subA = sroot + QStringLiteral("/subA");
        const QString subB = sroot + QStringLiteral("/subB");
        const QString subC = sroot + QStringLiteral("/subC");
        const QString subCNested = subC + QStringLiteral("/nested");
        QDir().mkpath(subA);
        QDir().mkpath(subB);
        QDir().mkpath(subCNested);

        writeBytes(subA + QStringLiteral("/a1.jpg"), 100);
        writeBytes(subA + QStringLiteral("/a2.jpg"), 120);
        writeBytes(subB + QStringLiteral("/b1.jpg"), 100);
        writeBytes(subC + QStringLiteral("/c1.jpg"), 100);
        writeBytes(subCNested + QStringLiteral("/cn1.jpg"), 100);

        auto writeCtx = [](const QString& dir, const QByteArray& json) {
            QFile f(dir + QStringLiteral("/.morfphoto.json"));
            if (f.open(QIODevice::WriteOnly)) {
                f.write(json);
                f.close();
            }
        };
        writeCtx(subA, "{\"schema\":2,\"context\":\"EVENEMENT\",\"subject\":\"PERSONNES\"}");
        writeCtx(subC, "{\"schema\":2,\"context\":\"DECOUVERTE\",\"subject\":\"PAYSAGE\"}");

        PhotoRepository srepo(QStringLiteral("smoke:scoped"));
        CHECK(srepo.open(sroot + QStringLiteral("/db.sqlite")), "scoped: base ouverte");
        const int folderId = srepo.addFolder(sroot, sroot, QVariant(), true, false, QVariant(), nowIso());
        Indexer sidx(&srepo, nullptr, {sroot});
        sidx.run(IndexMode::Incremental, {}, QStringLiteral("cli"));

        CHECK(srepo.summary().value(QStringLiteral("files_present")).toInt() == 5,
              "scoped: passe complete -> 5 photos presentes");
        CHECK(srepo.getContext(subA).value(QStringLiteral("status")).toString() == QLatin1String("qualified")
              && srepo.getContext(subC).value(QStringLiteral("status")).toString() == QLatin1String("qualified"),
              "scoped: contextes subA et subC qualifies");

        const KnownFiles cFlat = srepo.existingFilesInScope(folderId, subC, false);
        const KnownFiles cRec = srepo.existingFilesInScope(folderId, subC, true);
        const KnownFiles cNest = srepo.existingFilesInScope(folderId, subCNested, false);
        CHECK(cFlat.size() == 1 && cFlat.contains(subC + QStringLiteral("/c1.jpg"))
              && cRec.size() == 2 && cRec.contains(subCNested + QStringLiteral("/cn1.jpg"))
              && cNest.size() == 1 && cNest.contains(subCNested + QStringLiteral("/cn1.jpg")),
              "scoped: existingFilesInScope distingue non-recursif, recursif et sous-dossier");

        const QString sentinelScanAt = QStringLiteral("2020-01-01T00:00:00Z");
        srepo.setFolderScanned(folderId, sentinelScanAt);

        // Mutations dans subA + ajout silencieux dans subB (ne doit pas etre vu).
        writeBytes(subA + QStringLiteral("/a3.jpg"), 140);
        writeBytes(subA + QStringLiteral("/a1.jpg"), 250);
        QFile::remove(subA + QStringLiteral("/a2.jpg"));
        writeBytes(subB + QStringLiteral("/b2.jpg"), 110);

        sidx.runScopes(IndexMode::Incremental, {{folderId, subA, false}}, QStringLiteral("inotify"));
        CHECK(lastRunInt(srepo, "files_seen") == 2,
              "scoped: runScopes(subA) ne scanne que les 2 fichiers de subA");
        const KnownFiles afterA = srepo.existingFilesInFolder(folderId);
        CHECK(afterA.value(subA + QStringLiteral("/a3.jpg")).state == QLatin1String("present")
              && afterA.value(subA + QStringLiteral("/a1.jpg")).size == 250
              && afterA.value(subA + QStringLiteral("/a2.jpg")).state == QLatin1String("missing"),
              "scoped: subA ajoute, modifie et marque disparu");
        CHECK(!afterA.contains(subB + QStringLiteral("/b2.jpg"))
              && afterA.value(subB + QStringLiteral("/b1.jpg")).state == QLatin1String("present")
              && afterA.value(subC + QStringLiteral("/c1.jpg")).state == QLatin1String("present")
              && afterA.value(subCNested + QStringLiteral("/cn1.jpg")).state == QLatin1String("present"),
              "scoped: subB et subC intacts hors portee");

        QString recordedScanAt;
        const QJsonArray folderDetails = srepo.listFoldersDetail();
        for (const QJsonValue& val : folderDetails) {
            const QJsonObject obj = val.toObject();
            if (obj.value(QStringLiteral("id")).toInt() == folderId)
                recordedScanAt = obj.value(QStringLiteral("last_scan_at")).toString();
        }
        CHECK(recordedScanAt == sentinelScanAt,
              "scoped: passe partielle ne modifie pas folders.last_scan_at");

        QFile::remove(subA + QStringLiteral("/.morfphoto.json"));
        sidx.runScopes(IndexMode::Incremental, {{folderId, subA, false}}, QStringLiteral("inotify"));
        CHECK(srepo.getContext(subA).value(QStringLiteral("status")).toString() == QLatin1String("unqualified"),
              "scoped: retrait de .morfphoto.json dans subA -> unqualified");

        QDir(subC).removeRecursively();
        sidx.runScopes(IndexMode::Incremental, {{folderId, subC, true}}, QStringLiteral("inotify"));
        const KnownFiles afterC = srepo.existingFilesInFolder(folderId);
        CHECK(afterC.value(subC + QStringLiteral("/c1.jpg")).state == QLatin1String("missing")
              && afterC.value(subCNested + QStringLiteral("/cn1.jpg")).state == QLatin1String("missing"),
              "scoped: suppression recursive de subC marque subC et subC/nested missing");
        CHECK(srepo.getContext(subC).value(QStringLiteral("status")).toString() == QLatin1String("unqualified"),
              "scoped: contexte de subC supprime -> unqualified");
        CHECK(afterC.value(subA + QStringLiteral("/a1.jpg")).state == QLatin1String("present")
              && afterC.value(subA + QStringLiteral("/a3.jpg")).state == QLatin1String("present")
              && afterC.value(subB + QStringLiteral("/b1.jpg")).state == QLatin1String("present"),
              "scoped: fichiers de subA et subB toujours present");

        // 11c) Mise a jour par lots (> 500 IDs) pour markMissing et touchSeen.
        const QString batchDir = sroot + QStringLiteral("/batch");
        const int batchFolder = srepo.addFolder(batchDir, sroot, QVariant(), true, false, QVariant(), nowIso());
        QVector<int> batchIds;
        batchIds.reserve(550);
        const ExifData emptyExif;
        const QString ts0 = nowIso();
        for (int i = 0; i < 550; ++i) {
            FileInfo fi;
            fi.path = QStringLiteral("%1/img_%2.jpg").arg(batchDir).arg(i);
            fi.directory = batchDir;
            fi.filename = QStringLiteral("img_%1.jpg").arg(i);
            fi.extension = QStringLiteral(".jpg");
            fi.fileType = QStringLiteral("jpeg");
            fi.size = 100;
            fi.mtime = 1700000000;
            batchIds.push_back(srepo.insertFile(batchFolder, fi, emptyExif, false, ts0));
        }
        srepo.markMissing(batchIds, QStringLiteral("2026-01-01T00:00:00Z"));
        const KnownFiles afterMissing = srepo.existingFilesInFolder(batchFolder);
        int nMissing = 0;
        for (auto it = afterMissing.constBegin(); it != afterMissing.constEnd(); ++it)
            if (it->state == QLatin1String("missing"))
                ++nMissing;
        CHECK(nMissing == 550, "batch: markMissing sur 550 IDs (>500)");

        srepo.touchSeen(batchIds, QStringLiteral("2026-01-02T00:00:00Z"));
        const KnownFiles afterTouch = srepo.existingFilesInFolder(batchFolder);
        int nPresent = 0;
        for (auto it = afterTouch.constBegin(); it != afterTouch.constEnd(); ++it)
            if (it->state == QLatin1String("present"))
                ++nPresent;
        CHECK(nPresent == 550, "batch: touchSeen sur 550 IDs (>500)");

        // 12) Optimisations Phase 1 : schema v8, transactions, symlinks hors racine,
        //     touchSeen no-op sur present, filtres de dates sargables.
        {
            const QJsonArray batchTx = srepo.listFoldersDetail();
            Q_UNUSED(batchTx);
            CHECK(srepo.beginTransaction(), "tx: beginTransaction ouvre une transaction");
            CHECK(!srepo.beginTransaction(), "tx: double beginTransaction retourne false");
            FileInfo txFi;
            txFi.path = batchDir + QStringLiteral("/tx_rollback.jpg");
            txFi.directory = batchDir;
            txFi.filename = QStringLiteral("tx_rollback.jpg");
            txFi.extension = QStringLiteral(".jpg");
            txFi.fileType = QStringLiteral("jpeg");
            txFi.size = 42;
            txFi.mtime = 1700000042;
            srepo.insertFile(batchFolder, txFi, emptyExif, false, ts0);
            srepo.rollbackTransaction();
            CHECK(!srepo.existingFilesInFolder(batchFolder).contains(txFi.path),
                  "tx: rollbackTransaction annule insertFile");

            // Fichier inchange deja 'present' ne reecrit pas last_seen_at.
            const QString untouchedPath = subA + QStringLiteral("/a1.jpg");
            const int untouchedId = srepo.existingFilesInFolder(folderId).value(untouchedPath).id;
            const QString seenBefore = srepo.getPhoto(untouchedId, nullptr).value(QStringLiteral("last_seen_at")).toString();
            sidx.runScopes(IndexMode::Incremental, {{folderId, subA, false}}, QStringLiteral("inotify"));
            const QString seenAfter = srepo.getPhoto(untouchedId, nullptr).value(QStringLiteral("last_seen_at")).toString();
            CHECK(seenBefore == seenAfter,
                  "phase1: fichier present inchange ne reecrit pas last_seen_at");

            // Un fichier marque 'missing' qui reapparait est bien ravive en 'present'.
            srepo.markMissing({untouchedId}, QStringLiteral("2026-01-01T00:00:00Z"));
            CHECK(srepo.existingFilesInFolder(folderId).value(untouchedPath).state == QLatin1String("missing"),
                  "phase1: fichier marque missing avant reapparition");
            sidx.runScopes(IndexMode::Incremental, {{folderId, subA, false}}, QStringLiteral("inotify"));
            CHECK(srepo.existingFilesInFolder(folderId).value(untouchedPath).state == QLatin1String("present"),
                  "phase1: fichier missing reapparu ravive en present");

#ifdef Q_OS_UNIX
            // Lien symbolique pointant hors des racines est rejete meme avec le cache par dossier.
            const QString outsideDir = base + QStringLiteral("/outside_root");
            QDir().mkpath(outsideDir);
            const QString outsideFile = outsideDir + QStringLiteral("/secret.jpg");
            {
                QFile f(outsideFile);
                if (f.open(QIODevice::WriteOnly))
                    f.write("out");
            }
            const QString escapeLink = subA + QStringLiteral("/escape.jpg");
            QFile::link(outsideFile, escapeLink);
            sidx.runScopes(IndexMode::Incremental, {{folderId, subA, false}}, QStringLiteral("inotify"));
            CHECK(!srepo.existingFilesInFolder(folderId).contains(escapeLink),
                  "phase1: symlink pointant hors racine rejete par Indexer");
            QFile::remove(escapeLink);
#endif
        }

        srepo.close();

        // 13) Optimisations Phase 2 : open(readOnly), dataVersion, Keep-Alive,
        //     gzip JSON, offload m_apiReadPool, et thumbnail ETag/304.
        {
            // Creer un JPEG valide pour tester thumbnail ETag / 304 + Keep-Alive + gzip.
            const QString httpRoot = base + QStringLiteral("/http_root");
            QDir().mkpath(httpRoot);
            const QString jpgPath = httpRoot + QStringLiteral("/sample.jpg");
            QImage img(640, 480, QImage::Format_RGB32);
            img.fill(Qt::darkBlue);
            CHECK(img.save(jpgPath, "JPEG", 85), "phase2: JPEG test genere");

            const QString httpDb = base + QStringLiteral("/http_test.db");
            QJsonObject modParams;
            modParams[QStringLiteral("db_path")] = httpDb;
            modParams[QStringLiteral("roots")] = QJsonArray{httpRoot};
            modParams[QStringLiteral("xmp")] = QJsonObject{{QStringLiteral("enabled"), true}};
            modParams[QStringLiteral("watch")] = QJsonObject{
                {QStringLiteral("scan_on_startup"), false},
                {QStringLiteral("interval_ms"), 0},
                {QStringLiteral("realtime"), false},
            };

            ModuleRegistry reg;
            auto* mod = new PhotoModule(QStringLiteral("photo-http"), modParams, &reg);
            reg.add(mod);
            reg.startAll();

            // Inserer assez de fichiers pour depasser 1024 octets JSON (declenche gzip).
            QJsonObject addedFolder;
            QString addErr;
            CHECK(mod->addFolder(httpRoot, QVariant(), true, false, QVariant(), &addedFolder, &addErr),
                  "phase2: addFolder sur module HTTP");
            {
                PhotoRepository seedRepo(QStringLiteral("smoke-phase2-seed"));
                seedRepo.open(httpDb);
                const int fid = addedFolder.value(QStringLiteral("id")).toInt();
                seedRepo.beginTransaction();
                for (int i = 0; i < 15; ++i) {
                    FileInfo fi;
                    fi.path = QStringLiteral("%1/item_%2.jpg").arg(httpRoot).arg(i);
                    fi.directory = httpRoot;
                    fi.filename = QStringLiteral("item_%1.jpg").arg(i);
                    fi.extension = QStringLiteral(".jpg");
                    fi.fileType = QStringLiteral("jpeg");
                    fi.size = 1000 + i;
                    fi.mtime = 1700000000 + i;
                    ExifData ex;
                    ex.ok = true;
                    ex.takenAt = QStringLiteral("2026-05-%1 10:00:00").arg(i + 1, 2, 10, QLatin1Char('0'));
                    ex.cameraModel = QStringLiteral("Camera %1").arg(i % 3);
                    ex.iso = 100 * ((i % 4) + 1);
                    const int id = seedRepo.insertFile(fid, fi, ex, true, nowIso());
                    LibraryFileLabels lbl = fileLabels(fi.filename, ex);
                    QVector<LibraryVersion> vers = {mergeVersion(0, QString(), nullptr, ex)};
                    seedRepo.storeLibrary(id, QStringLiteral("fp"), lbl, vers);
                }
                seedRepo.commitTransaction();
                seedRepo.close();
            }

            PhotoRepository roRepo(QStringLiteral("smoke-phase2-ro"));
            CHECK(roRepo.open(httpDb, /*readOnly=*/true),
                  "phase2: open(readOnly=true) reussit");
            CHECK(roRepo.dataVersion() >= 0,
                  "phase2: PRAGMA data_version lisible sur connexion RO");
            roRepo.close();

            ServiceConfig cfg;
            cfg.bindAddress = QStringLiteral("127.0.0.1");
            cfg.httpPort = 0; // port ephemere via QTcpServer::listen(addr, 0) impossible si httpPort==0 -> utiliser port libre
            // Trouver un port libre temporaire.
            quint16 freePort = 0;
            {
                QTcpServer probe;
                if (probe.listen(QHostAddress::LocalHost, 0))
                    freePort = probe.serverPort();
            }
            cfg.httpPort = freePort;
            HttpServer server(cfg, &reg);
            CHECK(freePort > 0 && server.start(), "phase2: HttpServer demarre sur port loopback");

            auto readHttpResponse = [](QTcpSocket& sock, QByteArray& raw) -> bool {
                QElapsedTimer t;
                t.start();
                while (t.elapsed() < 5000) {
                    QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
                    raw += sock.readAll();
                    const int hdrEnd = raw.indexOf("\r\n\r\n");
                    if (hdrEnd >= 0) {
                        const QByteArray hdr = raw.left(hdrEnd);
                        int cl = 0;
                        for (const QByteArray& line : hdr.split('\n')) {
                            const QByteArray l = line.trimmed();
                            if (l.toLower().startsWith("content-length:"))
                                cl = l.mid(l.indexOf(':') + 1).trimmed().toInt();
                        }
                        if (raw.size() >= hdrEnd + 4 + cl)
                            return true;
                    }
                    sock.waitForReadyRead(20);
                }
                return false;
            };

            QTcpSocket client;
            client.connectToHost(QHostAddress::LocalHost, server.port());
            bool connected = false;
            for (int i = 0; i < 50 && !connected; ++i) {
                QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
                connected = (client.state() == QAbstractSocket::ConnectedState);
            }
            CHECK(connected, "phase2: client TCP connecte a HttpServer");

            // Requete 1 sur la socket : /healthz avec Keep-Alive
            client.write("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            client.flush();
            QByteArray r1;
            CHECK(readHttpResponse(client, r1) && r1.startsWith("HTTP/1.1 200 OK")
                  && r1.toLower().contains("connection: keep-alive"),
                  "phase2: Keep-Alive actif sur requete 1 (/healthz)");

            // Requete 2 sur LA MEME socket : /api/v1/library (offload thread pool + gzip + ETag)
            client.write("GET /api/v1/library?page_size=50 HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip\r\n\r\n");
            client.flush();
            QByteArray r2;
            const bool gotR2 = readHttpResponse(client, r2);
            QByteArray catEtag;
            QByteArray catRev;
            if (gotR2) {
                for (const QByteArray& line : r2.left(r2.indexOf("\r\n\r\n")).split('\n')) {
                    const QByteArray l = line.trimmed();
                    if (l.toLower().startsWith("etag:"))
                        catEtag = l.mid(l.indexOf(':') + 1).trimmed();
                    else if (l.toLower().startsWith("x-catalog-revision:"))
                        catRev = l.mid(l.indexOf(':') + 1).trimmed();
                }
            }
            CHECK(gotR2 && r2.startsWith("HTTP/1.1 200 OK")
                  && r2.toLower().contains("content-encoding: gzip")
                  && !catEtag.isEmpty() && !catRev.isEmpty(),
                  "phase2: requete 2 sur meme socket (/api/v1/library) servie en gzip avec ETag/X-Catalog-Revision");

            // Requete 2b : /api/v1/index/status expose le meme catalog_revision
            client.write("GET /api/v1/index/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            client.flush();
            QByteArray r2Status;
            const bool gotR2Status = readHttpResponse(client, r2Status);
            const QJsonObject idxStatusObj = gotR2Status
                ? QJsonDocument::fromJson(r2Status.mid(r2Status.indexOf("\r\n\r\n") + 4)).object()
                : QJsonObject();
            CHECK(gotR2Status && r2Status.startsWith("HTTP/1.1 200 OK")
                  && idxStatusObj.value(QStringLiteral("catalog_revision")).toString().toLatin1() == catRev,
                  "phase3: /api/v1/index/status expose le meme catalog_revision que /api/v1/library");

            // Requete 2c : /api/v1/library avec If-None-Match renvoie 304 Not Modified (0 octet)
            client.write("GET /api/v1/library?page_size=50 HTTP/1.1\r\nHost: 127.0.0.1\r\nIf-None-Match: " + catEtag + "\r\n\r\n");
            client.flush();
            QByteArray r2NotMod;
            const bool gotR2NotMod = readHttpResponse(client, r2NotMod);
            CHECK(gotR2NotMod && r2NotMod.startsWith("HTTP/1.1 304 Not Modified"),
                  "phase3: /api/v1/library avec If-None-Match renvoie 304 Not Modified");

            // Requete 3 sur LA MEME socket : /api/v1/library/facets (single-pass + cache)
            client.write("GET /api/v1/library/facets HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            client.flush();
            QByteArray r3;
            const bool gotR3 = readHttpResponse(client, r3);
            const QByteArray r3Body = gotR3 ? r3.mid(r3.indexOf("\r\n\r\n") + 4) : QByteArray();
            const QJsonObject facetsObj = QJsonDocument::fromJson(r3Body).object();
            CHECK(gotR3 && r3.startsWith("HTTP/1.1 200 OK")
                  && facetsObj.value(QStringLiteral("cameras")).toArray().size() == 3
                  && facetsObj.value(QStringLiteral("rejected")).toObject().value(QStringLiteral("all")).toInt() == 15,
                  "phase2: /api/v1/library/facets single-pass renvoie les bons compteurs");

            // Requete 4 & 5 sur LA MEME socket : thumbnail -> ETag + Cache-Control -> 304 Not Modified
            const QByteArray thumbReq = "GET /api/v1/thumbnail?path=" + QUrl::toPercentEncoding(jpgPath) +
                                        " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
            client.write(thumbReq);
            client.flush();
            QByteArray r4;
            const bool gotR4 = readHttpResponse(client, r4);
            QByteArray etag;
            if (gotR4) {
                for (const QByteArray& line : r4.left(r4.indexOf("\r\n\r\n")).split('\n')) {
                    const QByteArray l = line.trimmed();
                    if (l.toLower().startsWith("etag:"))
                        etag = l.mid(l.indexOf(':') + 1).trimmed();
                }
            }
            CHECK(gotR4 && r4.startsWith("HTTP/1.1 200 OK") && !etag.isEmpty()
                  && r4.toLower().contains("cache-control:"),
                  "phase2: /api/v1/thumbnail renvoie ETag et Cache-Control");

            const QByteArray thumb304Req = "GET /api/v1/thumbnail?path=" + QUrl::toPercentEncoding(jpgPath) +
                                           " HTTP/1.1\r\nHost: 127.0.0.1\r\nIf-None-Match: " + etag + "\r\nConnection: close\r\n\r\n";
            client.write(thumb304Req);
            client.flush();
            QByteArray r5;
            const bool gotR5 = readHttpResponse(client, r5);
            CHECK(gotR5 && r5.startsWith("HTTP/1.1 304 Not Modified"),
                  "phase2: /api/v1/thumbnail avec If-None-Match renvoie 304 Not Modified");

            client.close();
            server.stop();
            reg.stopAll();
        }

        // 14) Optimisations Phase 3 : Schema v9 FTS5 filename search, pagination
        //     keyset (cursor + skip_total), FolderWatcher skip NAS/hidden + diff
        //     incremental, et annulation cooperative de l'Indexer.
        {
            const QString p3Root = base + QStringLiteral("/phase3_root");
            QDir().mkpath(p3Root + QStringLiteral("/2026/sub"));
            QDir().mkpath(p3Root + QStringLiteral("/.git/objects"));
            QDir().mkpath(p3Root + QStringLiteral("/@eaDir/thumbs"));
            QDir().mkpath(p3Root + QStringLiteral("/#recycle/old"));
            const QString p3Root2 = base + QStringLiteral("/phase3_root2");
            QDir().mkpath(p3Root2 + QStringLiteral("/dirA"));

            // FolderWatcher : repertoires ignores et diff incremental
            CHECK(FolderWatcher::isIgnoredDirectoryName(QStringLiteral(".git")),
                  "phase3: .git ignore par FolderWatcher");
            CHECK(FolderWatcher::isIgnoredDirectoryName(QStringLiteral(".snapshots")),
                  "phase3: .snapshots ignore par FolderWatcher");
            CHECK(FolderWatcher::isIgnoredDirectoryName(QStringLiteral("@eaDir")),
                  "phase3: @eaDir ignore par FolderWatcher");
            CHECK(FolderWatcher::isIgnoredDirectoryName(QStringLiteral("#recycle")),
                  "phase3: #recycle ignore par FolderWatcher");
            CHECK(FolderWatcher::isIgnoredDirectoryName(QStringLiteral("$RECYCLE.BIN")),
                  "phase3: $RECYCLE.BIN ignore par FolderWatcher");
            CHECK(FolderWatcher::isIgnoredDirectoryName(QStringLiteral("System Volume Information")),
                  "phase3: System Volume Information ignore par FolderWatcher");
            CHECK(!FolderWatcher::isIgnoredDirectoryName(QStringLiteral("2026")),
                  "phase3: 2026 non ignore par FolderWatcher");

#ifdef Q_OS_LINUX
            {
                FolderWatcher watcher(50, 2000);
                watcher.setTargets({{1, p3Root, true}});
                // Attendu : p3Root, p3Root/2026, p3Root/2026/sub (3 watches ; .git/@eaDir/#recycle ignores)
                CHECK(watcher.statusJson().value(QStringLiteral("watches")).toInt() == 3,
                      "phase3: FolderWatcher ignore .git/@eaDir/#recycle (3 watches)");
                // Meme cible -> diff no-op conserve les 3 watches
                watcher.setTargets({{1, p3Root, true}});
                CHECK(watcher.statusJson().value(QStringLiteral("watches")).toInt() == 3,
                      "phase3: FolderWatcher setTargets identique conserve 3 watches");
                // Ajout 2e cible -> +2 watches (p3Root2 + dirA = 5)
                watcher.setTargets({{1, p3Root, true}, {2, p3Root2, true}});
                CHECK(watcher.statusJson().value(QStringLiteral("watches")).toInt() == 5,
                      "phase3: FolderWatcher ajout incremental -> 5 watches");
                // Retrait 1re cible -> ne reste que p3Root2 + dirA (2 watches)
                watcher.setTargets({{2, p3Root2, true}});
                CHECK(watcher.statusJson().value(QStringLiteral("watches")).toInt() == 2,
                      "phase3: FolderWatcher retrait incremental -> 2 watches");
            }
#endif

            // Schema v9 FTS5 + pagination keyset (avec doublons taken_at et NULL taken_at)
            const QString p3Db = base + QStringLiteral("/phase3.db");
            PhotoRepository p3Repo(QStringLiteral("smoke-phase3"));
            CHECK(p3Repo.open(p3Db), "phase3: ouverture base v9 (FTS5)");
            const int fId = p3Repo.addFolder(p3Root, p3Root, QVariant(), true, false, QVariant(), nowIso());

            struct SeedSpec { QString name; QVariant takenAt; };
            const QVector<SeedSpec> specs = {
                {QStringLiteral("IMG_2026_Sunset.jpg"), QStringLiteral("2026-05-01T10:00:00")},
                {QStringLiteral("IMG_2026_Sunrise.jpg"), QStringLiteral("2026-05-01T10:00:00")}, // meme taken_at
                {QStringLiteral("Portrait_Studio.ARW"), QStringLiteral("2026-05-02T12:00:00")},
                {QStringLiteral("ab.jpg"),              QStringLiteral("2026-05-03T12:00:00")},
                {QStringLiteral("quote\"test.jpg"),     QStringLiteral("2026-05-04T12:00:00")},
                {QStringLiteral("nodate_one.jpg"),      QVariant()}, // NULL taken_at
                {QStringLiteral("nodate_two.jpg"),      QVariant()}, // NULL taken_at
            };
            p3Repo.beginTransaction();
            for (int i = 0; i < specs.size(); ++i) {
                FileInfo fi;
                fi.path = p3Root + QLatin1Char('/') + specs[i].name;
                fi.directory = p3Root;
                fi.filename = specs[i].name;
                fi.extension = QStringLiteral(".jpg");
                fi.fileType = QStringLiteral("jpeg");
                fi.size = 500 + i;
                fi.mtime = 1700001000 + i;
                ExifData ex;
                ex.ok = true;
                ex.takenAt = specs[i].takenAt;
                ex.cameraModel = QStringLiteral("CamP3");
                const int id = p3Repo.insertFile(fId, fi, ex, true, nowIso());
                LibraryFileLabels lbl = fileLabels(fi.filename, ex);
                QVector<LibraryVersion> vers = {mergeVersion(0, QString(), nullptr, ex)};
                p3Repo.storeLibrary(id, QStringLiteral("fp3"), lbl, vers);
            }
            p3Repo.commitTransaction();

            // FTS5 trigram (>= 3 chars), fallback (< 3 chars), quote escaping
            {
                LibraryFilter fSun;
                fSun.filename = QStringLiteral("sunset");
                const QJsonObject rSun = p3Repo.libraryList(fSun, 1, 50);
                CHECK(rSun.value(QStringLiteral("total")).toInt() == 1
                      && rSun.value(QStringLiteral("items")).toArray().first().toObject()
                             .value(QStringLiteral("filename")).toString() == QLatin1String("IMG_2026_Sunset.jpg"),
                      "phase3: FTS5 trigram filename='sunset' trouve 1 match exact");

                LibraryFilter fShort;
                fShort.filename = QStringLiteral("ab");
                const QJsonObject rShort = p3Repo.libraryList(fShort, 1, 50);
                CHECK(rShort.value(QStringLiteral("total")).toInt() == 1,
                      "phase3: filename < 3 chars ('ab') bascule sur instr et trouve 1 match");

                LibraryFilter fQuote;
                fQuote.filename = QStringLiteral("quote\"t");
                const QJsonObject rQuote = p3Repo.libraryList(fQuote, 1, 50);
                CHECK(rQuote.value(QStringLiteral("total")).toInt() == 1,
                      "phase3: FTS5 echappe correctement les guillemets doubles");

                const QJsonObject facetsSun = p3Repo.libraryFacets(fSun);
                CHECK(facetsSun.value(QStringLiteral("rejected")).toObject()
                          .value(QStringLiteral("all")).toInt() == 1,
                      "phase3: libraryFacets utilise FTS5 filename filter");
            }

            // Pagination keyset complete (pageSize = 2) vs pagination offset
            {
                LibraryFilter allFilter;
                const QJsonObject fullPage = p3Repo.libraryList(allFilter, 1, 50);
                QVector<int> expectedIds;
                for (const QJsonValue& v : fullPage.value(QStringLiteral("items")).toArray())
                    expectedIds.append(v.toObject().value(QStringLiteral("id")).toInt());
                CHECK(expectedIds.size() == 7, "phase3: 7 photos dans libraryList complet");

                QVector<int> cursorIds;
                QString cursor;
                int rounds = 0;
                while (rounds < 20) {
                    ++rounds;
                    bool valid = false;
                    const QJsonObject pageObj = p3Repo.libraryList(
                        allFilter, 1, 2, cursor, &valid, /*skipTotal=*/!cursor.isEmpty());
                    CHECK(valid, "phase3: curseur valide accepte");
                    if (!cursor.isEmpty())
                        CHECK(!pageObj.contains(QStringLiteral("total")),
                              "phase3: skipTotal=true omet le champ total");
                    for (const QJsonValue& v : pageObj.value(QStringLiteral("items")).toArray())
                        cursorIds.append(v.toObject().value(QStringLiteral("id")).toInt());
                    const bool hasMore = pageObj.value(QStringLiteral("has_more")).toBool();
                    const QJsonValue nextVal = pageObj.value(QStringLiteral("next_cursor"));
                    if (!hasMore) {
                        CHECK(nextVal.isNull(), "phase3: derniere page a next_cursor null");
                        break;
                    }
                    cursor = nextVal.toString();
                    CHECK(!cursor.isEmpty(), "phase3: page intermediaire a next_cursor non vide");
                }
                CHECK(cursorIds == expectedIds,
                      "phase3: pagination keyset parcourt exactement les 7 photos (doublons + NULL taken_at)");

                bool badValid = true;
                p3Repo.libraryList(allFilter, 1, 2, QStringLiteral("!!!not-valid!!!"), &badValid);
                CHECK(!badValid, "phase3: curseur invalide rejete (cursorValid=false)");

                // Cache LibraryIdList : memes resultats bit-a-bit que libraryList SQL
                const LibraryIdList cachedIds = p3Repo.libraryIdList(allFilter);
                CHECK(cachedIds.ids == expectedIds,
                      "phase3: libraryIdList renvoie le meme ordre que libraryList SQL");
                QVector<int> cachedPageIds;
                QString cachedCur;
                for (int p = 1; p <= 4; ++p) {
                    bool cv = false;
                    const QJsonObject cp = p3Repo.libraryListFromCache(cachedIds, p, 2, QString(), &cv);
                    const QJsonObject sp = p3Repo.libraryList(allFilter, p, 2);
                    CHECK(cv && cp == sp, "phase3: libraryListFromCache identique a libraryList SQL");
                    for (const QJsonValue& v : cp.value(QStringLiteral("items")).toArray())
                        cachedPageIds.append(v.toObject().value(QStringLiteral("id")).toInt());
                    if (p == 1)
                        cachedCur = cp.value(QStringLiteral("next_cursor")).toString();
                }
                CHECK(cachedPageIds == expectedIds,
                      "phase3: pagination offset via LibraryIdList couvre les 7 photos");
                {
                    bool cv = false;
                    bool miss = true;
                    const QJsonObject cp2 = p3Repo.libraryListFromCache(cachedIds, 1, 2, cachedCur, &cv, false, &miss);
                    const QJsonObject sp2 = p3Repo.libraryList(allFilter, 1, 2, cachedCur);
                    CHECK(cv && !miss && cp2 == sp2,
                          "phase3: pagination curseur via LibraryIdList identique a SQL");
                }

                // Verifier aussi PhotoModule::libraryListJson + prefetch page N+1
                {
                    QJsonObject pfParams;
                    pfParams[QStringLiteral("db_path")] = p3Db;
                    pfParams[QStringLiteral("roots")] = QJsonArray{p3Root};
                    pfParams[QStringLiteral("xmp")] = QJsonObject{{QStringLiteral("enabled"), true}};
                    pfParams[QStringLiteral("watch")] = QJsonObject{
                        {QStringLiteral("scan_on_startup"), false},
                        {QStringLiteral("interval_ms"), 0},
                        {QStringLiteral("realtime"), false},
                    };
                    PhotoModule pfMod(QStringLiteral("photo-prefetch"), pfParams);
                    CHECK(pfMod.start(), "phase3: PhotoModule prefetch demarre");
                    for (int p = 1; p <= 4; ++p) {
                        bool okJson = false;
                        const QByteArray raw = pfMod.libraryListJson(allFilter, p, 2, QString(), &okJson);
                        const QJsonObject parsed = QJsonDocument::fromJson(raw).object();
                        const QJsonObject expected = pfMod.libraryList(allFilter, p, 2);
                        CHECK(okJson && parsed == expected,
                              "phase3: libraryListJson + prefetch identique a libraryList");
                    }
                    pfMod.stop();
                }
            }

            // Annulation cooperative de l'Indexer
            {
                writeBytes(p3Root + QStringLiteral("/2026/c1.jpg"), 120);
                writeBytes(p3Root + QStringLiteral("/2026/c2.jpg"), 130);
                Indexer cancelIdx(&p3Repo, nullptr, {p3Root}, 2000);
                auto token = std::make_shared<std::atomic_bool>(true);
                cancelIdx.setCancelToken(token);
                const int cancelRun = cancelIdx.run(IndexMode::Incremental, {fId}, QStringLiteral("api"));
                CHECK(cancelRun > 0, "phase3: Indexer annule cree un run proprement");
                const QJsonObject lr = p3Repo.latestRun();
                CHECK(lr.value(QStringLiteral("state")).toString() == QLatin1String("interrupted"),
                      "phase3: passe annulee cloturee en state='interrupted'");
                CHECK(lr.value(QStringLiteral("files_missing")).toInt() == 0
                      && lr.value(QStringLiteral("files_unavailable")).toInt() == 0,
                      "phase3: annulation ne marque aucun fichier disparu ni indisponible");
            }

            p3Repo.close();
        }
    }
    QDir(base).removeRecursively();

    std::printf(failures ? "\n%d test(s) en echec\n" : "\nTous les tests passent\n", failures);
    return failures ? 1 : 0;
}
