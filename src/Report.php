<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Sätter ihop inventering, fynd och uppdateringar till en sorterad rapport.
 * Ren logik utan WP-beroenden.
 */
class Report {
	/**
	 * @param array $components Komponenter med 'key', 'name', 'version', 'known', 'findings', 'notes'.
	 * @param array $updates    Tillgängliga uppdateringar med 'key', 'name', 'current', 'new'.
	 * @param array $errors     Fel som strängar.
	 */
	public static function build( array $site, array $components, array $updates, array $errors, int $time ): array {
		$update_by_key = array_column( $updates, null, 'key' );
		$counts        = array_fill_keys( Cvss::GRADES, 0 );
		$vulnerable    = [];
		$unknown       = [];

		foreach ( $components as $component ) {
			if ( empty( $component['known'] ) ) {
				$unknown[] = $component['name'] . ' ' . $component['version'];
			}
			if ( empty( $component['findings'] ) ) {
				continue;
			}
			$findings = $component['findings'];
			usort( $findings, [ self::class, 'compareFindings' ] );
			foreach ( $findings as $finding ) {
				$counts[ $finding['grade'] ]++;
			}
			$component['findings']    = $findings;
			$component['worst_grade'] = $findings[0]['grade'];
			$component['max_score']   = max( array_map( 'floatval', array_column( $findings, 'score' ) ) ?: [ 0.0 ] );
			$component['any_unfixed'] = in_array( true, array_column( $findings, 'unfixed' ), true );
			$component['fix_version'] = isset( $update_by_key[ $component['key'] ] )
				? $update_by_key[ $component['key'] ]['new']
				: self::highestVersion( array_filter( array_column( $findings, 'fixed_in' ) ) );
			$vulnerable[] = $component;
		}

		usort(
			$vulnerable,
			static function ( $a, $b ) {
				return [ Cvss::rank( $a['worst_grade'] ), -$a['max_score'], ! $a['any_unfixed'], $a['name'] ]
					<=> [ Cvss::rank( $b['worst_grade'] ), -$b['max_score'], ! $b['any_unfixed'], $b['name'] ];
			}
		);

		$vulnerable_keys = array_column( $vulnerable, 'key' );
		$other_updates   = array_values(
			array_filter(
				$updates,
				static function ( $update ) use ( $vulnerable_keys ) {
					return ! in_array( $update['key'], $vulnerable_keys, true );
				}
			)
		);

		$report = [
			'site'       => $site,
			'generated'  => $time,
			'vulnerable' => $vulnerable,
			'updates'    => $other_updates,
			'unknown'    => $unknown,
			'errors'     => array_values( $errors ),
			'counts'     => $counts,
		];
		$report['fingerprint'] = self::fingerprint( $report );
		return $report;
	}

	public static function hasContent( array $report ): bool {
		return ! empty( $report['vulnerable'] ) || ! empty( $report['updates'] );
	}

	/** Ändras bara när fynden eller uppdateringarna ändras, inte av ordning eller tidpunkt. */
	public static function fingerprint( array $report ): string {
		$parts = [];
		foreach ( $report['vulnerable'] as $component ) {
			$ids = array_column( $component['findings'], 'id' );
			sort( $ids );
			$parts[] = $component['key'] . '@' . $component['version'] . ':' . implode( ',', $ids );
		}
		foreach ( $report['updates'] as $update ) {
			$parts[] = 'update:' . $update['key'] . '@' . $update['new'];
		}
		sort( $parts );
		return sha1( implode( "\n", $parts ) );
	}

	private static function compareFindings( array $a, array $b ): int {
		return [ Cvss::rank( $a['grade'] ), -(float) $a['score'], ! $a['unfixed'] ]
			<=> [ Cvss::rank( $b['grade'] ), -(float) $b['score'], ! $b['unfixed'] ];
	}

	private static function highestVersion( array $versions ): ?string {
		$highest = null;
		foreach ( $versions as $version ) {
			if ( null === $highest || VersionMatcher::compare( $version, $highest, '>' ) ) {
				$highest = $version;
			}
		}
		return $highest;
	}
}
