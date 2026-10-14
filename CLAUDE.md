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

Flöde (`Scanner::run`): `Inventory::collect()` → `Updates::collect()` → uppslag per komponent →
`Report::build()` → `Mailer::send()` om fingerprint ändrats.

- **Rena klasser (testas utan WordPress):** `VersionMatcher`, `Cvss`, `Report`, `Sources\WpVulnerability`,
  `Sources\Osv`, `Mailer::render()/subject()` och `Inventory::parse*()`. HTTP injiceras som callables
  i källorna, så testerna kör mot riktiga API-svar i `tests/fixtures/`. `tests/bootstrap.php` definierar
  `ABSPATH` så att filernas guard passerar.
- **WP-lager:** `Inventory` (WP-delarna), `Updates`, `Scanner` (HTTP med transient-cache, lås), `Plugin`
  (inställningar/cron/hooks), `Admin` (Verktyg → k-cve), `Cli` (`wp k-cve scan`).
- **Komponentnyckeln `"<typ>:<slug>"` kopplar ihop fynd och uppdateringar** (`Report` matchar på `key`).
  Inventory och Updates måste bygga nyckeln likadant. Composer-paket har nyckeln `composer:<värd>/<paket>`.
- Ett fynd är en array: `id, title, cves[{id,url}], links[], score, vector, grade, kev, unfixed, fixed_in`.

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
`vendor/composer/installed.json`. Ett mu-plugin med `pre_wp_mail`-filter fångade mejlen till fil.
