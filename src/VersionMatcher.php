<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Tolkar WPVulnerability.net:s operator-objekt
 * ({min_version, min_operator, max_version, max_operator, unfixed}).
 */
class VersionMatcher {
	private const OPERATORS = [
		'lt' => '<',
		'le' => '<=',
		'gt' => '>',
		'ge' => '>=',
		'eq' => '==',
	];

	public static function matches( string $version, array $operator ): bool {
		$bounds = [
			[ $operator['min_version'] ?? null, $operator['min_operator'] ?? null ],
			[ $operator['max_version'] ?? null, $operator['max_operator'] ?? null ],
		];
		foreach ( $bounds as list( $bound, $op ) ) {
			if ( null === $bound || '' === $bound ) {
				continue;
			}
			if ( ! isset( self::OPERATORS[ $op ] ) ) {
				return false;
			}
			if ( ! self::compare( $version, $bound, self::OPERATORS[ $op ] ) ) {
				return false;
			}
		}
		return true;
	}

	/** Första version som inte är sårbar, om den går att utläsa. */
	public static function fixedIn( array $operator ): ?string {
		if ( ! empty( $operator['unfixed'] ) && '0' !== (string) $operator['unfixed'] ) {
			return null;
		}
		if ( 'lt' === ( $operator['max_operator'] ?? null ) && ! empty( $operator['max_version'] ) ) {
			return (string) $operator['max_version'];
		}
		return null;
	}

	public static function compare( string $a, string $b, string $op ): bool {
		return version_compare( self::normalize( $a ), self::normalize( $b ), $op );
	}

	/** version_compare('6.9', '6.9.0') ger -1, så avslutande ".0"-segment tas bort. */
	private static function normalize( string $version ): string {
		$version = ltrim( trim( $version ), 'vV' );
		return preg_replace( '/(\.0+)+$/', '', $version );
	}
}
