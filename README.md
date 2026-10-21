# Klykk CVE Sårbarhetsbevakning

WordPress-plugin som installeras på kundsiter. Med jämna mellanrum (dagligen eller veckovis) kontrollerar det:

- **WP-kärnan**, **alla installerade plugins** (även inaktiva) och **alla teman**
- **Plugin-beroenden** enligt headern `Requires Plugins` (visas som "krävs av X")
- **Servermjukvara**: PHP, MySQL/MariaDB, Apache/nginx (om versionen syns i `SERVER_SOFTWARE`), ImageMagick, cURL
- **Inbäddade Composer-bibliotek** i plugins och teman (`*/vendor/composer/installed.json`)

Om det finns något nytt skickas ett HTML-mejl. Sårbara komponenter kommer först, graderade efter CVSS
(Kritisk ≥ 9.0 · Hög ≥ 7.0 · Medel ≥ 4.0 · Låg · Ej graderad) och med länk till CVE. Därefter listas
övriga tillgängliga uppdateringar.

Överst i mejlet finns **Åtgärda först**: de tre komponenter som är viktigast att åtgärda. Där räknas mer in
än bara CVSS-graden. Poängen höjs om sårbarheten bekräftat utnyttjas (KEV), om
[EPSS](https://www.first.org/epss/) bedömer att den sannolikt utnyttjas, och om den går att nå utan inloggning.
Poängen sänks för inaktiva plugins och teman och för serverkomponenter. Skälen visas som etiketter.
Faktorerna är konstanter i `src/Priority.php`.

## Datakällor

| Vad | Källa |
|---|---|
| core, plugins, teman, server | [WPVulnerability.net](https://www.wpvulnerability.com/), gratis och utan nyckel |
| Composer-paket | [OSV.dev](https://osv.dev/) (GitHub Advisory Database m.fl.) |
| Tillgängliga uppdateringar | WordPress egen uppdateringsdata (inkl. premium-plugins med egen uppdaterare) |
| Sannolikhet för utnyttjande | [EPSS](https://www.first.org/epss/) från FIRST.org, gratis och utan nyckel |

API-svar cachas i 12 timmar (transients `kcve_*`).

## Installation och konfiguration

1. Ladda ner `k-cve.zip` från [senaste releasen](https://github.com/Klykk-Labs/k-cve/releases/latest) och installera den
   under Tillägg → Lägg till → Ladda upp. Använd inte GitHubs knapp "Source code (zip)", för den zippen saknar `vendor/`.
2. Sätt mottagare antingen under **Verktyg → Klykk CVE** eller, enklast vid utrullning, i `wp-config.php`:
   ```php
   define( 'K_CVE_NOTIFY_EMAIL', 'rapporter@example.com' );
   ```
   Konstanten vinner över inställningen. Om ingen mottagare är satt används sitens admin-e-post.
3. Välj intervall (dagligen/veckovis) på samma sida. Första körningen sker en timme efter aktivering.
4. Valfritt men rekommenderat: sätt en **livlina**. Efter varje lyckad körning anropar pluginet en URL med GET.
   Uteblir anropet, till exempel för att WP-Cron slutat köras, pluginet avaktiverats eller mejlet inte gick att
   skicka, larmar tjänsten. Med [healthchecks.io](https://healthchecks.io/) skapar du en check per site, med perioden
   lika med intervallet plus en dags marginal:
   ```php
   define( 'K_CVE_PING_URL', 'https://hc-ping.com/<uuid>' );
   ```
   Ingen sitedata skickas med anropet. URL:en kan också sättas på inställningssidan.

**WP-Cron körs bara när siten får besök.** På siter med lite trafik bör en riktig cron anropa `wp-cron.php`.

## Uppdateringar

Pluginet kontrollerar själv efter nya releaser på GitHub (via [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker)),
ungefär var tolfte timme. En ny version visas som en vanlig uppdatering under Tillägg och kan installeras manuellt
eller automatiskt, om automatiska uppdateringar är påslagna för pluginet.

Så här ger du ut en ny version:

1. Höj versionen i `k-cve.php` på **två** ställen: headern `Version:` och `KCVE_VERSION`.
2. Committa, och kör sedan `git tag v0.3.0 && git push && git push --tags`.
3. GitHub Action `Release` kör testerna på PHP 7.4, bygger `k-cve.zip` och publicerar releasen. Om taggen och
   versionen inte stämmer överens avbryts bygget.

**Den som kan publicera releaser i repot kan köra kod på alla siter där pluginet är installerat.** Skydda
GitHub-kontot och organisationen med tvåfaktorsautentisering och håll nere antalet personer med skrivrätt.

## Hur notiser fungerar

- Mejl skickas bara när rapporten **ändrats** sedan förra mejlet, det vill säga nya fynd, ny version eller ny uppdatering.
  Ett fingerprint lagras i optionen `kcve_last_sent`.
- **Påminnelse:** om ett fynd med graden Kritisk eller Hög har varit öppet i minst 7 dagar, och senaste mejlet är
  minst 7 dagar gammalt, skickas rapporten igen med ämnet `[Klykk CVE] Påminnelse: …`. När ett fynd sågs första
  gången lagras i `kcve_first_seen`, och mejlet visar "öppet i N dagar".
- Fynd som tillkommit sedan förra mejlet märks **NY**.
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
php bin/build.php                                    # bygger build/k-cve.zip lokalt
```
