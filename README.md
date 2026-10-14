# k-cve — sårbarhetsbevakning för WordPress

WordPress-plugin som installeras på kundsiter. Med jämna mellanrum (dagligen eller veckovis) kontrollerar det:

- **WP-kärnan**, **alla installerade plugins** (även inaktiva) och **alla teman**
- **Plugin-beroenden** enligt headern `Requires Plugins` (visas som "krävs av X")
- **Servermjukvara**: PHP, MySQL/MariaDB, Apache/nginx (om versionen syns i `SERVER_SOFTWARE`), ImageMagick, cURL
- **Inbäddade Composer-bibliotek** i plugins och teman (`*/vendor/composer/installed.json`)

Om det finns något nytt skickas ett HTML-mejl. Sårbara komponenter kommer först, graderade efter CVSS
(Kritisk ≥ 9.0 · Hög ≥ 7.0 · Medel ≥ 4.0 · Låg · Ej graderad) och med länk till CVE. Därefter listas
övriga tillgängliga uppdateringar.

## Datakällor

| Vad | Källa |
|---|---|
| core, plugins, teman, server | [WPVulnerability.net](https://www.wpvulnerability.com/), gratis och utan nyckel |
| Composer-paket | [OSV.dev](https://osv.dev/) (GitHub Advisory Database m.fl.) |
| Tillgängliga uppdateringar | WordPress egen uppdateringsdata (inkl. premium-plugins med egen uppdaterare) |

API-svar cachas i 12 timmar (transients `kcve_*`).

## Installation och konfiguration

1. Zippa katalogen **utan** `vendor/`, `tests/`, `composer.*` och `phpunit.xml`. Installera den sedan som ett vanligt plugin.
2. Sätt mottagare antingen under **Verktyg → k-cve** eller, enklast vid utrullning, i `wp-config.php`:
   ```php
   define( 'K_CVE_NOTIFY_EMAIL', 'robert@example.com' );
   ```
   Konstanten vinner över inställningen. Om ingen mottagare är satt används sitens admin-e-post.
3. Välj intervall (dagligen/veckovis) på samma sida. Första körningen sker en timme efter aktivering.

**WP-Cron körs bara när siten får besök.** På siter med lite trafik bör en riktig cron anropa `wp-cron.php`.

## Hur notiser fungerar

- Mejl skickas bara när rapporten **ändrats** sedan förra mejlet, det vill säga nya fynd, ny version eller ny uppdatering.
  Ett fingerprint lagras i optionen `kcve_last_sent`.
- "Kör och mejla rapport" på inställningssidan och `--force-mail` i WP-CLI skickar alltid.
- Mejlet visar högst 10 fynd per komponent. Servrar kan ha över 100 CVE:er. Allt syns i `wp k-cve scan`.

## WP-CLI

```
wp k-cve scan              # kör, mejla om något ändrats
wp k-cve scan --dry-run    # kör utan mejl, skriv tabell
wp k-cve scan --force-mail # mejla oavsett
```

## Kända begränsningar

- Premium-plugins och -teman som inte finns i databasen listas som "Finns inte i sårbarhetsdatabasen" och kontrolleras inte.
- Webbserverns version döljs ofta (`ServerTokens Prod`), och då hoppas den över.
- Composer-paket som prefixats med PHP-Scoper kan heta något annat än originalet och missas då.
- WPVulnerability.net är ett communityprojekt utan SLA. Om ett uppslag misslyckas visas det under "Fel under kontrollen".
  Om ett fel försvinner till nästa körning räknas det som en ändring och ger ett nytt mejl.
- Pluginet anropar **inte** `wp_version_check()`, eftersom den i cron-kontext startar WordPress automatiska
  uppdateringar. Uppgiften om kärnuppdateringar kommer från WP:s egen kontroll (två gånger per dygn).

## Utveckling

```
composer install
vendor/bin/phpunit                                   # alla tester
vendor/bin/phpunit --filter test_osv_lookup          # ett test
```
