<?php
namespace KCve;

use KCve\Sources\Epss;
use KCve\Sources\Osv;
use KCve\Sources\WpVulnerability;

defined( 'ABSPATH' ) || exit;

/**
 * Orkestrerar en körning: inventering → uppslag → rapport → ev. mejl.
 */
class Scanner {
	private const LOCK      = 'kcve_running';
	private const CACHE_TTL = 12 * HOUR_IN_SECONDS;
	private const TIMEOUT   = 10;

	/**
	 * @param bool $force_mail Skicka även om inget ändrats sedan senaste mejlet.
	 * @param bool $dry_run    Skicka aldrig mejl (förhandsvisning).
	 * @return array Rapporten, plus 'mailed' => bool.
	 */
	public function run( bool $force_mail, bool $dry_run ): array {
		if ( get_transient( self::LOCK ) ) {
			throw new \RuntimeException( 'En kontroll pågår redan.' );
		}
		set_transient( self::LOCK, 1, 15 * MINUTE_IN_SECONDS );

		try {
			if ( function_exists( 'set_time_limit' ) ) {
				@set_time_limit( 300 ); // phpcs:ignore -- kan vara avstängt på delade webbhotell.
			}

			$errors     = [];
			$components = Inventory::collect();
			try {
				$updates = Updates::collect();
			} catch ( \Throwable $e ) {
				$updates  = [];
				$errors[] = 'Uppdateringskontroll: ' . $e->getMessage();
			}

			$components = $this->lookup( $components, $errors );
			$components = $this->epss( $components, $errors );
			$baseline   = get_option( Plugin::OPTION_BASELINE, null );
			$integrity  = IntegrityScan::run( [ $this, 'pluginChecksums' ], is_array( $baseline ) ? $baseline : null );
			$errors     = array_merge( $errors, $integrity['errors'] );
			$last_sent  = (array) get_option( Plugin::OPTION_LAST_SENT, [] );
			$report     = Report::build(
				[ 'name' => get_bloginfo( 'name' ), 'url' => home_url() ],
				$components,
				$updates,
				$errors,
				time(),
				(array) get_option( Plugin::OPTION_FIRST_SEEN, [] ),
				(int) ( $last_sent['time'] ?? 0 ),
				$integrity['items']
			);
			update_option( Plugin::OPTION_FIRST_SEEN, $report['first_seen'], false );
			update_option( Plugin::OPTION_LAST_REPORT, $report, false );

			$reason                = $dry_run || ! Plugin::mailEnabled() ? null : Report::mailReason( $report, $last_sent, time(), $force_mail );
			$report['reminder']    = 'reminder' === $reason;
			$report['mailed']      = $reason ? Mailer::send( $report, Plugin::recipient() ) : false;
			$report['mail_failed'] = $reason && ! $report['mailed'];

			// Hubben får rapporten efter varje körning, även oförändrad: det är hjärtslaget.
			$hub                 = $dry_run ? null : Plugin::hub();
			$report['hub_error'] = $hub ? $this->sendToHub( $report, $hub ) : null;
			$report['hub_sent']  = $hub && null === $report['hub_error'];

			// Utan mejl räknas leveransen till hubben som "skickad", så att NY gäller sedan senaste rapporten dit.
			$delivered = $report['mailed'] || ( $report['hub_sent'] && ! Plugin::mailEnabled() );
			if ( $delivered || ( ! $dry_run && ! Report::hasContent( $report ) ) ) {
				// Även utan innehåll, så att ett nytt fynd senare räknas som en ändring.
				update_option( Plugin::OPTION_LAST_SENT, [ 'fingerprint' => $report['fingerprint'], 'time' => time() ], false );
			}
			if ( ! $dry_run && ! $report['mail_failed'] && null === $report['hub_error'] ) {
				// Baslinjen flyttas bara när händelserna nått fram, annars försvinner de ur nästa mejl/rapport.
				update_option( Plugin::OPTION_BASELINE, $integrity['baseline'], false );
				// Livlina: pinga bara när hela körningen lyckades. Uteblir pingen larmar tjänsten.
				$this->ping();
			}
			return $report;
		} finally {
			delete_transient( self::LOCK );
		}
	}

	private function lookup( array $components, array &$errors ): array {
		$wpv = new WpVulnerability( [ $this, 'httpGet' ] );
		foreach ( $components as &$component ) {
			$component['known']    = true;
			$component['findings'] = [];
			if ( ! WpVulnerability::supports( $component['type'] ) ) {
				continue;
			}
			try {
				$result                = $wpv->lookup( $component );
				$component['known']    = $result['known'];
				$component['findings'] = $result['findings'];
			} catch ( \Throwable $e ) {
				$errors[] = $component['name'] . ' kunde inte kontrolleras: ' . $e->getMessage();
			}
		}
		unset( $component );

		$composer = array_filter(
			$components,
			static function ( $component ) {
				return 'composer' === $component['type'];
			}
		);
		if ( $composer ) {
			try {
				$osv = new Osv( [ $this, 'httpPost' ], [ $this, 'httpGet' ] );
				foreach ( $osv->lookup( $composer ) as $index => $findings ) {
					$components[ $index ]['findings'] = $findings;
				}
			} catch ( \Throwable $e ) {
				$errors[] = 'Inbäddade bibliotek (OSV) kunde inte kontrolleras: ' . $e->getMessage();
			}
		}
		return $components;
	}

	/** EPSS är bara ett tillägg till prioriteringen: fel blir en rad i rapporten, inte en avbruten körning. */
	private function epss( array $components, array &$errors ): array {
		$scores = [];
		$cves   = Epss::cves( $components );
		if ( $cves ) {
			try {
				$scores = ( new Epss( [ $this, 'httpGet' ] ) )->lookup( $cves );
			} catch ( \Throwable $e ) {
				$errors[] = 'EPSS kunde inte hämtas: ' . $e->getMessage();
			}
		}
		return Epss::annotate( $components, $scores );
	}

	/** Svaret ignoreras: ett misslyckat anrop syns som en utebliven ping hos tjänsten. Ingen sitedata skickas. */
	private function ping(): void {
		$url = Plugin::pingUrl();
		if ( $url ) {
			wp_remote_get( $url, [ 'timeout' => 5, 'user-agent' => 'k-cve/' . KCVE_VERSION ] );
		}
	}

	/** Signerad POST till hubben. null vid 2xx, annars felbeskrivningen. Svarets innehåll används inte. */
	private function sendToHub( array $report, array $hub ): ?string {
		try {
			$request = Hub::request( $report, $hub['site'], $hub['secret'], time() );
		} catch ( \Throwable $e ) {
			return $e->getMessage();
		}
		$response = wp_remote_post(
			$hub['url'],
			[ 'timeout' => Hub::TIMEOUT, 'user-agent' => 'k-cve/' . KCVE_VERSION . ' (WordPress)', 'headers' => $request['headers'], 'body' => $request['body'] ]
		);
		if ( is_wp_error( $response ) ) {
			return $response->get_error_message();
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		return $code >= 200 && $code < 300 ? null : "HTTP $code från hubben";
	}

	/**
	 * Checksummor för ett plugin från wordpress.org, bara .php-filer. null om pluginet eller versionen saknas där (404).
	 * Cachas en vecka, även 404, eftersom en släppt version aldrig ändras. Lagras reducerat: hela svaret kan vara närmare 1 MB.
	 */
	public function pluginChecksums( string $slug, string $version ): ?array {
		$cache_key = 'kcve_sums_' . md5( $slug . '@' . $version );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached['files'];
		}
		$url      = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$response = wp_remote_get( $url, $this->requestArgs() );
		$files    = 404 === wp_remote_retrieve_response_code( $response ) ? null : Integrity::pluginExpected( $this->decode( $response, $url ) );
		set_transient( $cache_key, [ 'files' => $files ], WEEK_IN_SECONDS );
		return $files;
	}

	/** Cachade GET-anrop (12 h). Bara lyckade svar cachas. */
	public function httpGet( string $url ): array {
		$cache_key = 'kcve_' . md5( $url );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$data = $this->decode( wp_remote_get( $url, $this->requestArgs() ), $url );
		set_transient( $cache_key, $data, self::CACHE_TTL );
		return $data;
	}

	public function httpPost( string $url, array $body ): array {
		$args                            = $this->requestArgs();
		$args['body']                    = wp_json_encode( $body );
		$args['headers']['Content-Type'] = 'application/json';
		return $this->decode( wp_remote_post( $url, $args ), $url );
	}

	private function requestArgs(): array {
		// Ingen site-URL i user-agent: kundens adress ska inte läcka till tredje part.
		return [ 'timeout' => self::TIMEOUT, 'user-agent' => 'k-cve/' . KCVE_VERSION . ' (WordPress)', 'headers' => [ 'Accept' => 'application/json' ] ];
	}

	private function decode( $response, string $url ): array {
		if ( is_wp_error( $response ) ) {
			throw new \RuntimeException( $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			throw new \RuntimeException( "HTTP $code från " . wp_parse_url( $url, PHP_URL_HOST ) );
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			throw new \RuntimeException( 'Ogiltigt JSON-svar från ' . wp_parse_url( $url, PHP_URL_HOST ) );
		}
		return $data;
	}
}
