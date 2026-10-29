# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Vad det här är

WordPress-plugin "Klykk CVE Sårbarhetsbevakning" (kort: "Klykk CVE"; teknisk slug `k-cve`, PHP ≥ 7.4, WP ≥ 6.5) som installeras på kundsiter.
Repot är **publikt** (github.com/Klykk-Labs/k-cve): skriv inga kundnamn, interna sökvägar eller hemligheter här eller i koden.
Det kontrollerar regelbundet core, plugins, teman, servermjukvara och inbäddade Composer-paket mot kända
sårbarheter och mejlar en CVSS-graderad rapport med CVE-länkar. Se README.md för funktion och begränsningar.
UI- och mejltexter är på svenska och hårdkodade (ingen i18n).

## Kommandon

```
composer install                                  # phpunit 9.6 (dev) + plugin-update-checker; plattform låst till PHP 7.4
vendor/bin/phpunit                                # alla tester
vendor/bin/phpunit --filter test_osv_lookup       # ett test
vendor/bin/phpunit tests/CvssTest.php             # en testfil
php bin/build.php [v0.2.0]                        # bygger build/k-cve.zip (valfri tagg kontrolleras mot versionen)
```

Lokal PHP är 8.3, men koden måste fungera i 7.4: ingen `match`, nullsafe, `str_contains`, union types eller konstruktor-promotion.

## Arkitektur

Flöde (`Scanner::run`): `Inventory::collect()` → `Updates::collect()` → uppslag per komponent → EPSS →
`IntegrityScan::run()` → `Report::build()` → `Report::mailReason()` (ändrat fingerprint, påminnelse eller tvingat) → `Mailer::send()` →
POST till hubben (`K_CVE_HUB_*`, varje körning utom dry-run) → ping (`K_CVE_PING_URL`) och ny baslinje (`kcve_baseline`)
om varken mejl eller hubb misslyckades.

- **Hubben (0.5.0):** `Hub` (ren) bygger kroppen och signerar `hex(hmac_sha256(secret, timestamp + "." + body))` över
  exakt de byte som skickas. `tests/fixtures/hub-signature-vector.json` är uträknad med Python och delas med hubbens
  repo: ändra den aldrig på ett ställe. `Hub::payload` tar bort `first_seen` och ersätter `admin_*`-sökvägarna
  (`login (ID n)`) med `ID n`. Med `K_CVE_MAIL` = false räknas en lyckad hubbleverans som "skickad" (`kcve_last_sent`),
  annars skulle NY aldrig försvinna.
- **Rena klasser (testas utan WordPress):** `VersionMatcher`, `Cvss`, `Report`, `Priority`, `Integrity`, `Hub`, `Sources\WpVulnerability`,
  `Sources\Osv`, `Sources\Epss`, `Mailer::render()/subject()` och `Inventory::parse*()`. HTTP injiceras som callables
  i källorna, så testerna kör mot riktiga API-svar i `tests/fixtures/`. `tests/bootstrap.php` definierar
  `ABSPATH` så att filernas guard passerar.
- **WP-lager:** `Inventory` (WP-delarna), `Updates`, `Scanner` (HTTP med transient-cache, lås), `Plugin`
  (inställningar/cron/hooks), `Admin` (Verktyg → k-cve), `Cli` (`wp k-cve scan`).
- **Komponentnyckeln `"<typ>:<slug>"` kopplar ihop fynd och uppdateringar** (`Report` matchar på `key`).
  Inventory och Updates måste bygga nyckeln likadant. Composer-paket har nyckeln `composer:<värd>/<paket>`.
- **Serverkomponenter** (`Priority::SERVER_TYPES`) hamnar i rapportens `hosting`, inte i `vulnerable`. De räknas inte i
  `counts`, `top` eller `overdue` men ingår i fingerprintet. Det är medvetet att hubben (som läser `vulnerable` och
  `counts`) därmed inte larmar på dem.
- Ett fynd är en array: `id, title, cves[{id,url}], links[], score, vector, grade, kev, unfixed, fixed_in`, plus
  `epss, epss_percentile` (Scanner) och `is_new, days_open` (Report). Komponenter har `active` (prioriteringen).
- `kcve_first_seen` nycklas `<komponentnyckel>#<fynd-id>` **utan version**, så att en uppdatering som inte rättar
  fyndet inte nollställer dagräkningen. "NY" betyder sett efter `kcve_last_sent.time`, alltså senaste mejlet och inte
  senaste körningen. Annars skulle en förhandsvisning i wp-admin förbruka etiketten.
- Integritetsfynd är `{ group, path }` (`Integrity::GROUPS`). Grupperna i `EVENT_GROUPS` (nya admins och nya eller ändrade
  filer i mu-plugins/wp-content, jämfört med `kcve_baseline`) ingår **inte** i fingerprintet. De försvinner nästa körning,
  och det får inte räknas som en ändring. I stället ger de alltid `mailReason` 'changed'. Baslinjen sparas bara när
  körningen inte är dry-run och mejlet inte misslyckades, annars försvinner händelsen innan den mejlats.
- Lagrade rapporter (`kcve_last_report`) från äldre versioner renderas på adminsidan. Mailer måste därför tåla att
  nya nycklar saknas.

## Icke-uppenbara fallgropar (hittade under verifiering)

- **WPVulnerability-data:** core-svar saknar `operator`, så alla poster gäller exakt den versionen. `unfixed` kan
  vara int eller sträng. `impact` kan vara en tom array, och då blir graden "Ej graderad". `data.latest` är en
  tidsstämpel, inte en version. Titeln ligger i `source[].name`/`description`, och fältet `name` är ofta bara en
  version. Text som bara är ett id (`CVE-…`) räknas inte som titel.
- `version_compare('6.9', '6.9.0')` är -1. `VersionMatcher` normaliserar bort avslutande `.0`.
- **Anropa aldrig `wp_version_check()`:** i cron-kontext startar den `wp_maybe_auto_update`, vilket uppdaterar
  kundens site.
- Första `update_option()` på en option som inte finns går via `add_option()`. Därför hakar `Plugin` på både
  `add_option_` och `update_option_` för att schemalägga om.
- `get_core_checksums()` listar även filer under `wp-content/` (standardteman, akismet). De hoppas över. Saknade
  kärnfiler rapporteras bara för `.php`, eftersom `readme.html` och `license.txt` ofta tas bort som härdning.
- Kärnans checksummor hämtas för det **installerade paketets** språk (`$wp_local_package`, annars `en_US`), inte
  `get_locale()`. En site som installerats på engelska och sedan fått svenska har annars en "ändrad" `version.php`.
- `Integrity::isHarmless` släpper igenom kommentarer, `header()` med fasta strängar och `exit`/`die` först. En `//`- eller
  `#`-kommentar slutar vid en PHP-sluttagg, så kod efter den räknas. Filer över 1 KB läses bara i början och måste då börja med exit.
- Plugin-checksummornas `md5`/`sha256` är en sträng eller en lista (när filen skiljer sig mellan taggar). Svaret kan vara
  nära 1 MB, så `Scanner::pluginChecksums` cachar bara de reducerade `.php`-hasharna, en vecka, även 404.
- SQLite-drop-in (`DB_ENGINE === 'sqlite'`) utger sig för att vara MySQL 8.0.x, så DB-kontrollen hoppas över då.
- OSV ger bara CVSS-vektor och ingen poäng. `Cvss::scoreFromVector` räknar 3.x-poängen själv (v4 stöds inte,
  och då används GHSA-etiketten som reserv).

## Release och uppdateringar

Utgivning: höj versionen i **både** headern `Version:` och `KCVE_VERSION` i `k-cve.php`, committa, och kör
`git tag vX.Y.Z && git push --tags`. `.github/workflows/release.yml` kör testerna på PHP 7.4, bygger
`k-cve.zip` med `bin/build.php` (som avbryter om taggen och versionen skiljer sig) och skapar en GitHub Release.

På kundsiterna hämtar Plugin Update Checker (`vendor/`, laddas i `k-cve.php`) den senaste releasen. Bara
asseten `k-cve.zip` används (`REQUIRE_RELEASE_ASSETS`), aldrig GitHubs källkods-zip, eftersom den saknar
`vendor/`. Zippens mapp måste heta `k-cve`, eftersom det är den sluggen uppdateringen matchar på. Headern `Update URI`
hindrar att wordpress.org erbjuder ett annat plugin med samma slug. Inventory hoppar över pluginets egen mapp,
så att dess `vendor/` inte rapporteras som ett bibliotek.

## Integrationstest

Testa aldrig på riktiga kundsiter. Verifieringen gjordes på en tillfällig WP med SQLite (`sqlite-database-integration`) + WP-CLI-phar, med
WP 6.9.1, wpforms-lite 1.9.7.3 (facit: CVE-2026-32446) och ett testplugin med Guzzle 7.4.0 i
`vendor/composer/installed.json`. Ett mu-plugin med `pre_wp_mail`-filter fångade mejlen till fil (returnera
`false` för att simulera mejlfel). Livlinan verifierades med `K_CVE_PING_URL` mot en lokal `php -S`-router som loggar
anropen. Påminnelser testas genom att `kcve_first_seen` och `kcve_last_sent.time` backdateras 8 dagar.
Integriteten testas genom att plantera en ändrad och en okänd fil i `wp-includes/`, `uploads/2026/10/x.php`, ett nytt
mu-plugin, en ny admin (`wp user create … --role=administrator`) och en ändrad och en okänd PHP-fil i wpforms-lite.
Kontrollera att uppackningen av WP blev komplett: en avbruten uppackning ger hundratals "Saknad kärnfil".
Hubben (0.5.0) verifierades med `K_CVE_HUB_*` mot en lokal `php -S`-router som räknar om signaturen med `hash_equals`
och svarar med statuskoden i en fil: dry-run skickar inget, en vanlig körning ger giltig signatur, inget `first_seen` och
`admin_*` som `ID n`, svaret 500 eller en stängd port ger felkod 1 och ingen ping, och en ny admin följer med igen
nästa körning. `K_CVE_MAIL` = false ger inget mejl men rapporten skickas ändå.
