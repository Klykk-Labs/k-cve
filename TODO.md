# TODO

## Planerat

Ordningen bygger på värde per arbetsinsats. Etapp 1 och 2 blir **0.3.0** och etapp 3 blir **0.4.0**.
Ren logik skrivs test först, som tidigare (`tests/`, fixtures med riktiga API-svar).

### Etapp 1 — Livlina och påminnelser (0.3.0) — KLAR, släppt i 0.4.0

Avvikelser från planen nedan:
- `kcve_first_seen` nycklas `<nyckel>#<fynd-id>` utan version. En uppdatering som inte rättar fyndet nollställer
  alltså inte dagräkningen.
- NY betyder nytt sedan förra **mejlet**, inte sedan förra körningen. Inget märks NY före det första mejlet.
- Beslutet ligger i `Report::mailReason()` i stället för en egen klass `Notifier`. Ämnet blir `[Klykk CVE] Påminnelse: …`.
- Ett misslyckat `wp_mail` ger exit 1 i WP-CLI och ett felmeddelande i wp-admin.

**Problem:** tystnad ser idag ut som att allt är bra. Om WP-Cron dör, pluginet avaktiveras eller `wp_mail`
misslyckas får man ingen signal. Ett kritiskt fynd mejlas också bara en gång, och dedup gör att det
sedan aldrig påminns om.

1. **Ping efter lyckad körning ("dead man's switch").**
   - Ny konstant `K_CVE_PING_URL` (vinner över inställningen) och ett fält på inställningssidan.
   - Pingen (`wp_remote_get`, timeout 5 s, ingen sitedata skickas) går bara när körningen gick hela vägen:
     inventering, uppslag och, om mejl skulle skickas, ett `wp_mail` som returnerade true. Om något fallerar
     uteblir pingen, och då larmar pingtjänsten.
   - Rekommenderad tjänst är healthchecks.io: gratis för 20 checkar, en check per kundsite, period lika med
     sitens intervall plus en dags marginal. Vilken URL som helst som tar emot GET fungerar.
2. **När ett fynd sågs första gången.**
   - Ny option `kcve_first_seen`: `{ "<komponentnyckel>@<version>#<fynd-id>": timestamp }`. Poster för fynd
     som försvunnit rensas bort.
   - `Report::build()` får `first_seen` som indata, så att den fortsätter vara en ren funktion. Varje fynd får
     `first_seen` och `is_new`, det sistnämnda sant om fyndet inte fanns vid förra körningen.
3. **Påminnelser.**
   - Om ett Kritisk- eller Hög-fynd varit öppet i mer än `REMIND_AFTER_DAYS` (7) dagar, och senaste mejlet
     är äldre än 7 dagar, skickas rapporten igen trots oförändrat fingerprint.
   - Ämnet börjar då med `Påminnelse:`, och fyndet visar "öppet i 12 dagar".
4. **Etiketten NY** på fynd och komponenter med `is_new`. Den blir nästan gratis när `first_seen` finns.

Tester: `Report` (is_new, rensning), beslutet om påminnelse som en ren funktion i stil med
`Notifier::shouldSend(report, last_sent, now)`, och Mailer (NY-etikett, påminnelseämne).

### Etapp 2 — Prioritering med EPSS och "Åtgärda först" (0.3.0) — KLAR, släppt i 0.4.0

Avvikelser från planen nedan:
- EPSS cachas 12 h via `Scanner::httpGet`, samma cache som de andra källorna, i stället för 24 h.
- Skälet för KEV heter `KEV` och skälet för serverkomponenter heter `server`. "Åtgärda först" visas även när det
  bara finns en sårbar komponent.

**Problem:** CVSS mäter allvarlighet, inte sannolikhet. Med 20 siter och många fynd behöver mejlet säga vad
som ska åtgärdas först.

1. **`Sources\Epss`**: `GET https://api.first.org/data/v1/epss?cve=A,B,…` (gratis, ingen nyckel), med
   högst 50 CVE:er per anrop. Svaren cachas 24 h, eftersom EPSS uppdateras dagligen. Varje fynd får
   `epss` och `epss_percentile`. Om anropet misslyckas blir det ett fel i rapporten, aldrig att körningen
   avbryts.
2. **Komponenten får `active: bool`** i stället för att statusen bara finns som text i `notes`.
3. **Ren `Priority::score(finding, component)`** med förklarbara faktorer:
   - bas: CVSS (ej graderad räknas som 5.0)
   - × 2.0 om KEV (bekräftat exploaterad)
   - × 1.5 om EPSS-percentil ≥ 0.9
   - × 1.3 om CVSS-vektorn har `AV:N` + `PR:N`, alltså att ingen inloggning krävs
   - × 0.5 om pluginet eller temat är inaktivt
   - × 0.7 för serverkomponenter (webbhotellets ansvar)

   Funktionen returnerar både poängen och skälen, till exempel `['KEV', 'EPSS 12 %', 'utan inloggning']`.
   Faktorerna ligger som konstanter så att de går att justera.
4. **Sektionen "Åtgärda först"** högst upp i mejlet och på adminsidan: de högst 3 viktigaste komponenterna,
   en rad var med åtgärd och skäl i form av etiketter. Accordion-raderna sorteras fortfarande efter grad.

Tester: `Epss` mot en fixtur, `Priority` med en tabell av fall och Mailer (sektionen finns och är tom
när inga fynd finns).

### Etapp 3 — Filintegritet och intrångstecken (0.4.0) — KLAR, släppt

Avvikelser från planen nedan:
- Baslinjehändelser (ny admin, ny eller ändrad PHP-fil i mu-plugins/wp-content) ingår inte i fingerprintet men ger
  alltid mejl. Annars skulle de ge ett extra mejl när de försvinner nästa körning. mu-plugins skannas rekursivt och
  med innehållshash, så att en bakdörr i en befintlig fil också syns.
- Saknade kärnfiler rapporteras bara för `.php`. "Silence is golden"-filer i uploads ignoreras.
- Mätt på testsiten: integritetsdelen tar 1,6 s (3 plugins) och hela körningen 9 s med kall cache. Ingen egen
  cron-händelse behövs än.

**Problem:** versionsjämförelsen upptäcker sårbar kod, men inte att någon redan har tagit sig in.

1. **Kärnfiler:** `get_core_checksums( $wp_version, get_locale() )`, som är WordPress egen funktion, jämförs
   med `md5_file()` för varje listad fil.
   - Rapportera **ändrade** och **saknade** filer, samt **okända `.php`-filer** i `wp-admin/` och
     `wp-includes/`, som inte finns i listan och därför är en stark signal.
   - Fel som `wp-content/` och `wp-config.php` ingår inte i listan och hoppas över.
2. **Plugins från wordpress.org:**
   `https://downloads.wordpress.org/plugin-checksums/<slug>/<version>.json` ger `files: { path: { md5, sha256 } }`.
   - Jämför `sha256`. `md5` kan vara en array, så båda formerna ska hanteras.
   - 404 betyder premium eller okänd version och hoppas över.
   - Bara **`.php`-filer** flaggas, både ändrade och okända, eftersom plugins ofta skriver cache- och
     översättningsfiler i sin egen mapp och annat ger falsklarm.
   - Svaren cachas per slug och version, eftersom de aldrig ändras.
3. **Intrångstecken:**
   - Körbara filer i `uploads/` (`.php`, `.phtml`, `.phar`, `.php5`–`.php8`). Det är så bland annat
     Elementor Pro-attacken skrev webshells. Skanningen tittar bara på filnamn, har en övre gräns för
     antal poster och rapporterar "avbruten efter N filer" om gränsen nås.
   - **Nya** filer i `mu-plugins/` och nya drop-ins (`wp-content/*.php`, t.ex. `db.php` och
     `object-cache.php`) jämfört med en baslinje i optionen `kcve_baseline`.
   - **Nya administratörskonton** sedan förra körningen, jämfört med samma baslinje.
   - **Första körningen** visar allt i mu-plugins och drop-ins som "att granska" en gång, i stället för att
     tyst godta det som baslinje. En redan infekterad site ska inte bli normalläget.
4. **Rapporten** får en egen sektion, "Integritet och intrångstecken", **överst**, med Kritisk-styling.
   Fynden ingår i fingerprintet, så ett nytt fynd ger ett mejl direkt.
5. **Prestanda:** att hasha kärnan (cirka 3 500 filer) tar ungefär 1–2 s. Hela körningen ska mätas på en
   testsite. Om den blir för långsam för WP-Cron på delade webbhotell körs integritetskontrollen som en
   egen cron-händelse.

Tester: en ren `ChecksumDiff::compare( $expected, $hasher, $files )` (ändrad, saknad, okänd, md5-array),
filtrering av körbara filtyper, baslinjediff för mu-plugins och admin-konton, samt fixtur från
plugin-checksums.

### Verifiering, alla etapper

Bygg upp testsiten enligt CLAUDE.md (SQLite-WP + WP-CLI-phar, WP 6.9.1, wpforms-lite 1.9.7.3) och plantera:

- en ändrad `wp-includes`-fil
- en okänd PHP-fil i `wp-includes/`
- `uploads/2026/10/x.php`
- ett nytt mu-plugin
- en ny administratör
- en ändrad PHP-fil i wpforms-lite

Alla ska rapporteras, och en andra körning ska inte ge nytt mejl. Pingen verifieras mot en lokal
`php -S`-endpoint som loggar anropen: ping vid lyckad körning, ingen ping när `wp_mail` stubbas till false.
Påminnelsen testas genom att `first_seen` och `kcve_last_sent` backdateras 8 dagar. EPSS jämförs mot API:t
för CVE:erna på testsiten.

## Backlog

- [x] **Rapportera till en central hubb (0.5.0, släppt 2026-10-23):** `K_CVE_HUB_URL`, `K_CVE_HUB_SITE` och `K_CVE_HUB_SECRET`. POST av rapporten efter
      varje körning, signerad med HMAC-SHA256 över `timestamp.body`, som också fungerar som hjärtslag. `K_CVE_MAIL`
      (standard true) stänger av mejlet. Inloggningsnamn för admins skickas inte, bara ID. Hubben anropar aldrig sajten.

- [x] **Ska påminnelser gälla serverkomponenter?** Nej, löst i 0.6.0 tillsammans med "Webbhotellets ansvar".
- [ ] **Tillfälliga API-fel ger extra mejl.** Behåll förra körningens fynd för komponenter som inte gick att
      kontrollera, märkta "(från förra kontrollen)", så att fingerprintet inte fladdrar.
- [ ] **CI vid push och PR,** inte bara vid tagg.
- [ ] **Integrationstester för WP-lagret** i Actions (Scanner-dedup, Inventory, Updates), med samma
      SQLite-WP-recept som testsiten.
- [x] **Sektionen "Webbhotellets ansvar" (0.6.0):** serverkomponenter i rapportens `hosting`, sist i mejlet, utan grad,
      "Åtgärda först" och påminnelser, med en färdig text till webbhotellet.
- [ ] **Övergivna plugins:** flagga `closed` från WPVulnerability och plugins vars `last_updated` på
      wordpress.org är äldre än 2 år, även utan känd CVE.
- [ ] **Selektiv automatisk uppdatering (frivilligt, avstängt som standard):** filtret `auto_update_plugin`
      slår på automatiska uppdateringar bara för plugins med öppna Kritisk- eller Hög-fynd.
- [ ] **"Uppdatera nu"-knappar** i accordion-raderna på adminsidan.
- [ ] **Slack- eller Teams-webhook** som komplement till e-post.
- [ ] **Kundrapport:** en förenklad version utan jargong med Klykk-profil, till exempel ett månatligt säkerhetsintyg.
- [ ] **Site Health-test och widget på panelen** som visar kritiska fynd i WordPress egna vyer.
- [ ] **Engelska och i18n,** så att pluginet kan få användare och bidrag utifrån och eventuellt hamna på wordpress.org.
- [ ] **Signerade releaser:** signera `k-cve.zip` med Ed25519 i Actions och verifiera signaturen före
      installation (`sodium_compat` finns i WP), så att ett kapat GitHub-konto inte räcker för att nå kundsiterna.
- [ ] **Skydd för taggar och grenar** på GitHub (bara ägaren får skapa `v*`-taggar).
- [ ] **Parallella HTTP-anrop** (`WpOrg\Requests\Requests::request_multiple`) om körningstiden blir ett problem.
- [ ] **Multisite:** stöds inte idag. Bestäm beteende vid nätverksaktivering.
