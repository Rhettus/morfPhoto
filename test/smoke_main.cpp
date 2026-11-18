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
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QVariantMap>

#include "morfphoto/PhotoScanner.h"
#include "morfphoto/PhotoRepository.h"
#include "morfphoto/ExifExtractor.h"
#include "morfphoto/LibraryMetadata.h"
#include "morfphoto/Indexer.h"
#include "morfphoto/ContextFile.h"
#include "morfphoto/SmbSourceNaming.h"
#include "morfphoto/OriginCheck.h"

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

    repo2.close();
    QDir(base).removeRecursively();

    std::printf(failures ? "\n%d test(s) en echec\n" : "\nTous les tests passent\n", failures);
    return failures ? 1 : 0;
}
