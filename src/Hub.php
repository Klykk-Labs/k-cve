<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Rapport till en central hubb (K_CVE_HUB_*): innehåll och HMAC-signering. Ren, själva anropet görs i Scanner.
 *
 * Signaturen är hex(hmac_sha256(hemlighet, tidsstämpel + "." + kropp)) över exakt de byte som skickas.
 * Hubben verifierar på samma sätt; tests/fixtures/hub-signature-vector.json delas med hubbens tester.
 */
class Hub {
	public const TIMEOUT = 15;

	/** Admin-grupper där sökvägen är "inloggningsnamn (ID n)". Bara id:t lämnar siten. */
	private const ADMIN_GROUPS = [ 'admin_new', 'admin_review' ];

	public static function sign( string $secret, int $timestamp, string $body ): string {
		return hash_hmac( 'sha256', $timestamp . '.' . $body, $secret );
	}

	/** Rapporten som den skickas: utan intern data och utan administratörers inloggningsnamn. */
	public static function payload( array $report ): array {
		unset( $report['first_seen'] );
		foreach ( $report['integrity'] ?? [] as $index => $item ) {
			if ( in_array( $item['group'], self::ADMIN_GROUPS, true ) && preg_match( '/\(ID (\d+)\)$/', $item['path'], $match ) ) {
				$report['integrity'][ $index ]['path'] = 'ID ' . $match[1];
			}
		}
		return $report;
	}

	/** @return array{body: string, headers: array<string, string>} */
	public static function request( array $report, string $site, string $secret, int $timestamp ): array {
		// Ogiltig UTF-8 (t.ex. i ett sitenamn) ersätts hellre än att hela rapporten uteblir.
		$body = json_encode( self::payload( $report ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( false === $body ) {
			throw new \RuntimeException( 'Rapporten kunde inte kodas som JSON: ' . json_last_error_msg() );
		}
		return [
			'body'    => $body,
			'headers' => [
				'Content-Type'     => 'application/json',
				'X-KCve-Site'      => $site,
				'X-KCve-Timestamp' => (string) $timestamp,
				'X-KCve-Signature' => self::sign( $secret, $timestamp, $body ),
			],
		];
	}
}
