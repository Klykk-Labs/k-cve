<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Vad ska åtgärdas först? CVSS mäter allvarlighet, inte sannolikhet, så poängen justeras
 * med förklarbara faktorer. Ren logik; skälen visas i mejlet.
 */
class Priority {
	public const UNGRADED_SCORE   = 5.0;
	public const KEV_FACTOR       = 2.0;  // Bekräftat exploaterad.
	public const EPSS_PERCENTILE  = 0.9;
	public const EPSS_FACTOR      = 1.5;
	public const NO_AUTH_FACTOR   = 1.3;  // Nåbar över nätet utan inloggning.
	public const INACTIVE_FACTOR  = 0.5;
	public const SERVER_FACTOR    = 0.7;  // Webbhotellets ansvar, och ofta backportade fixar.
	public const SERVER_TYPES     = [ 'php', 'mysql', 'mariadb', 'apache', 'nginx', 'imagemagick', 'curl' ];

	/** @return array{score: float, reasons: string[]} */
	public static function score( array $finding, array $component ): array {
		$score   = null !== $finding['score'] ? (float) $finding['score'] : self::UNGRADED_SCORE;
		$reasons = [];
		if ( ! empty( $finding['kev'] ) ) {
			$score    *= self::KEV_FACTOR;
			$reasons[] = 'KEV';
		}
		if ( ( $finding['epss_percentile'] ?? 0 ) >= self::EPSS_PERCENTILE ) {
			$score    *= self::EPSS_FACTOR;
			$reasons[] = 'EPSS ' . self::percent( (float) $finding['epss'] );
		}
		$vector = (string) ( $finding['vector'] ?? '' );
		if ( preg_match( '#/AV:N(/|$)#', $vector ) && preg_match( '#/PR:N(/|$)#', $vector ) ) {
			$score    *= self::NO_AUTH_FACTOR;
			$reasons[] = 'utan inloggning';
		}
		if ( false === ( $component['active'] ?? true ) ) {
			$score    *= self::INACTIVE_FACTOR;
			$reasons[] = 'inaktivt';
		}
		if ( in_array( $component['type'], self::SERVER_TYPES, true ) ) {
			$score    *= self::SERVER_FACTOR;
			$reasons[] = 'server';
		}
		return [ 'score' => $score, 'reasons' => $reasons ];
	}

	/** Komponentens prioritet är dess viktigaste fynd. */
	public static function component( array $component ): array {
		$best = [ 'score' => 0.0, 'reasons' => [] ];
		foreach ( $component['findings'] as $finding ) {
			$candidate = self::score( $finding, $component );
			if ( $candidate['score'] > $best['score'] ) {
				$best = $candidate;
			}
		}
		return $best;
	}

	/** Sannolikhet i procent: "12 %", "2,8 %". */
	private static function percent( float $probability ): string {
		$percent = $probability * 100;
		return ( $percent >= 10 ? number_format( $percent, 0 ) : number_format( $percent, 1, ',', '' ) ) . ' %';
	}
}
