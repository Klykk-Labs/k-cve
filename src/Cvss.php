<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * CVSS 3.x bas-poäng och gradering. Poängen räknas själv eftersom OSV bara levererar vektorn.
 * Formler: https://www.first.org/cvss/v3.1/specification-document (avsnitt 7).
 */
class Cvss {
	public const GRADES = [ 'critical', 'high', 'medium', 'low', 'none' ];

	private const WEIGHTS = [
		'AV' => [ 'N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2 ],
		'AC' => [ 'L' => 0.77, 'H' => 0.44 ],
		'UI' => [ 'N' => 0.85, 'R' => 0.62 ],
		'CIA' => [ 'H' => 0.56, 'L' => 0.22, 'N' => 0.0 ],
	];

	public static function scoreFromVector( string $vector ): ?float {
		if ( ! preg_match( '#^CVSS:3\.[01]/#', $vector ) ) {
			return null;
		}
		$m = [];
		foreach ( explode( '/', substr( $vector, 9 ) ) as $part ) {
			$kv = explode( ':', $part, 2 );
			if ( 2 === count( $kv ) ) {
				$m[ $kv[0] ] = $kv[1];
			}
		}
		foreach ( [ 'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A' ] as $key ) {
			if ( ! isset( $m[ $key ] ) ) {
				return null;
			}
		}
		$changed = 'C' === $m['S'];
		$pr      = [ 'N' => 0.85, 'L' => $changed ? 0.68 : 0.62, 'H' => $changed ? 0.5 : 0.27 ];
		if ( ! isset( self::WEIGHTS['AV'][ $m['AV'] ], self::WEIGHTS['AC'][ $m['AC'] ], $pr[ $m['PR'] ], self::WEIGHTS['UI'][ $m['UI'] ],
			self::WEIGHTS['CIA'][ $m['C'] ], self::WEIGHTS['CIA'][ $m['I'] ], self::WEIGHTS['CIA'][ $m['A'] ] ) ) {
			return null;
		}

		$cia = self::WEIGHTS['CIA'];
		$iss = 1 - ( 1 - $cia[ $m['C'] ] ) * ( 1 - $cia[ $m['I'] ] ) * ( 1 - $cia[ $m['A'] ] );
		$impact = $changed
			? 7.52 * ( $iss - 0.029 ) - 3.25 * pow( $iss - 0.02, 15 )
			: 6.42 * $iss;
		if ( $impact <= 0 ) {
			return 0.0;
		}
		$exploitability = 8.22 * self::WEIGHTS['AV'][ $m['AV'] ] * self::WEIGHTS['AC'][ $m['AC'] ] * $pr[ $m['PR'] ] * self::WEIGHTS['UI'][ $m['UI'] ];
		$base = $changed ? 1.08 * ( $impact + $exploitability ) : $impact + $exploitability;
		return self::roundUp( min( $base, 10 ) );
	}

	public static function grade( ?float $score ): string {
		if ( null === $score || $score <= 0 ) {
			return 'none';
		}
		if ( $score >= 9.0 ) {
			return 'critical';
		}
		if ( $score >= 7.0 ) {
			return 'high';
		}
		return $score >= 4.0 ? 'medium' : 'low';
	}

	/** GitHub Advisory-etiketter (LOW/MODERATE/HIGH/CRITICAL) när ingen v3-vektor finns. */
	public static function gradeFromLabel( ?string $label ): string {
		$map = [ 'critical' => 'critical', 'high' => 'high', 'moderate' => 'medium', 'medium' => 'medium', 'low' => 'low' ];
		return $map[ strtolower( (string) $label ) ] ?? 'none';
	}

	public static function rank( string $grade ): int {
		$rank = array_search( $grade, self::GRADES, true );
		return false === $rank ? count( self::GRADES ) : $rank;
	}

	/** Roundup enligt CVSS 3.1, appendix A (undviker flyttalsfel som 4.000001 → 4.1). */
	private static function roundUp( float $value ): float {
		$int = (int) round( $value * 100000 );
		if ( 0 === $int % 10000 ) {
			return $int / 100000.0;
		}
		return ( floor( $int / 10000 ) + 1 ) / 10.0;
	}
}
