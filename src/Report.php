<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Sätter ihop inventering, fynd och uppdateringar till en sorterad rapport.
 * Ren logik utan WP-beroenden.
 */
class Report {
	/** Öppna Kritisk/Hög-fynd påminns om när de varit öppna så här länge och senaste mejlet är lika gammalt. */
	public const REMIND_AFTER_DAYS = 7;
	public const TOP = 3; // Rader i "Åtgärda först".
	private const DAY = 86400; // DAY_IN_SECONDS finns inte utan WordPress (testerna).

	/**
	 * @param array $components Komponenter med 'key', 'name', 'version', 'known', 'findings', 'notes'.
	 * @param array $updates    Tillgängliga uppdateringar med 'key', 'name', 'current', 'new'.
	 * @param array $errors     Fel som strängar.
	 * @param array $first_seen Förra körningens { "<key>#<fynd-id>": timestamp }.
	 * @param int   $since      Tidpunkt för senaste mejlet (0 = aldrig). Fynd sedda efter den är "nya".
	 * @param array $integrity  Integritetsfynd [ { group, path } ], se Integrity.
	 */
	public static function build( array $site, array $components, array $updates, array $errors, int $time, array $first_seen = [], int $since = 0, array $integrity = [] ): array {
		$update_by_key = array_column( $updates, null, 'key' );
		$counts        = array_fill_keys( Cvss::GRADES, 0 );
		$vulnerable    = [];
		$hosting       = [];
		$unknown       = [];
		$seen          = [];
		$overdue       = 0;

		foreach ( $components as $component ) {
			if ( empty( $component['known'] ) ) {
				$unknown[] = $component['name'] . ' ' . $component['version'];
			}
			if ( empty( $component['findings'] ) ) {
				continue;
			}
			// Serverprogram (PHP, databas, cURL …) uppdateras av webbhotellet: egen lista, utan grad, påminnelse och prioritet.
			$hosted   = in_array( $component['type'], Priority::SERVER_TYPES, true );
			$findings = $component['findings'];
			usort( $findings, [ self::class, 'compareFindings' ] );
			foreach ( $findings as &$finding ) {
				if ( ! $hosted ) {
					$counts[ $finding['grade'] ]++;
				}
				// Utan version i nyckeln: en uppdatering som inte rättar fyndet ska inte nollställa dagräkningen.
				$seen_key             = $component['key'] . '#' . $finding['id'];
				$seen[ $seen_key ]    = (int) ( $first_seen[ $seen_key ] ?? $time );
				$finding['is_new']    = $since > 0 && $seen[ $seen_key ] > $since;
				$finding['days_open'] = intdiv( max( 0, $time - $seen[ $seen_key ] ), self::DAY );
				if ( ! $hosted && Cvss::rank( $finding['grade'] ) <= Cvss::rank( 'high' ) && $finding['days_open'] >= self::REMIND_AFTER_DAYS ) {
					$overdue++;
				}
			}
			unset( $finding );
			$component['findings']    = $findings;
			$component['worst_grade'] = $findings[0]['grade'];
			$component['max_score']   = max( array_map( 'floatval', array_column( $findings, 'score' ) ) ?: [ 0.0 ] );
			$component['has_new']     = in_array( true, array_column( $findings, 'is_new' ), true );
			$component['priority']    = Priority::component( $component );
			$component['any_unfixed'] = in_array( true, array_column( $findings, 'unfixed' ), true );
			$component['fix_version'] = isset( $update_by_key[ $component['key'] ] )
				? $update_by_key[ $component['key'] ]['new']
				: self::highestVersion( array_filter( array_column( $findings, 'fixed_in' ) ) );
			if ( $hosted ) {
				$hosting[] = $component;
			} else {
				$vulnerable[] = $component;
			}
		}

		usort( $vulnerable, [ self::class, 'compareComponents' ] );
		usort( $hosting, [ self::class, 'compareComponents' ] );

		$by_priority = $vulnerable;
		usort(
			$by_priority,
			static function ( $a, $b ) {
				return [ -$a['priority']['score'], $a['name'] ] <=> [ -$b['priority']['score'], $b['name'] ];
			}
		);

		$vulnerable_keys = array_column( array_merge( $vulnerable, $hosting ), 'key' );
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
			'integrity'  => array_values( $integrity ),
			'vulnerable' => $vulnerable,
			'hosting'    => $hosting,
			'top'        => array_slice( array_column( $by_priority, 'key' ), 0, self::TOP ),
			'updates'    => $other_updates,
			'unknown'    => $unknown,
			'errors'     => array_values( $errors ),
			'counts'     => $counts,
			'first_seen' => $seen,
			'overdue'    => $overdue,
		];
		$report['fingerprint'] = self::fingerprint( $report );
		return $report;
	}

	/**
	 * Varför rapporten ska mejlas: 'forced', 'changed' (nytt fingerprint), 'reminder' eller null (inget mejl).
	 *
	 * @param array $last_sent { fingerprint, time } för senaste mejlet.
	 */
	public static function mailReason( array $report, array $last_sent, int $now, bool $force ): ?string {
		if ( ! self::hasContent( $report ) ) {
			return null;
		}
		if ( $force ) {
			return 'forced';
		}
		if ( self::hasEvents( $report ) || ( $last_sent['fingerprint'] ?? '' ) !== $report['fingerprint'] ) {
			return 'changed';
		}
		if ( $report['overdue'] > 0 && $now - (int) ( $last_sent['time'] ?? 0 ) >= self::REMIND_AFTER_DAYS * self::DAY ) {
			return 'reminder';
		}
		return null;
	}

	public static function hasContent( array $report ): bool {
		return ! empty( $report['vulnerable'] ) || ! empty( $report['hosting'] ) || ! empty( $report['updates'] ) || ! empty( $report['integrity'] );
	}

	/** Baslinjehändelser (ny admin, ny fil i mu-plugins …) syns bara en gång och mejlas därför alltid. */
	private static function hasEvents( array $report ): bool {
		foreach ( $report['integrity'] ?? [] as $item ) {
			if ( in_array( $item['group'], Integrity::EVENT_GROUPS, true ) ) {
				return true;
			}
		}
		return false;
	}

	/** Ändras bara när fynden eller uppdateringarna ändras, inte av ordning eller tidpunkt. */
	public static function fingerprint( array $report ): string {
		$parts = [];
		// Serverkomponenter ingår: en ny version eller ett nytt fynd är värt att veta, även om webbhotellet åtgärdar det.
		foreach ( array_merge( $report['vulnerable'], $report['hosting'] ?? [] ) as $component ) {
			$ids = array_column( $component['findings'], 'id' );
			sort( $ids );
			$parts[] = $component['key'] . '@' . $component['version'] . ':' . implode( ',', $ids );
		}
		foreach ( $report['updates'] as $update ) {
			$parts[] = 'update:' . $update['key'] . '@' . $update['new'];
		}
		foreach ( $report['integrity'] ?? [] as $item ) {
			if ( ! in_array( $item['group'], Integrity::EVENT_GROUPS, true ) ) {
				$parts[] = 'integrity:' . $item['group'] . ':' . $item['path'];
			}
		}
		sort( $parts );
		return sha1( implode( "\n", $parts ) );
	}

	private static function compareComponents( array $a, array $b ): int {
		return [ Cvss::rank( $a['worst_grade'] ), -$a['max_score'], ! $a['any_unfixed'], $a['name'] ]
			<=> [ Cvss::rank( $b['worst_grade'] ), -$b['max_score'], ! $b['any_unfixed'], $b['name'] ];
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
