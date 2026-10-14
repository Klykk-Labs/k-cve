<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * WP-CLI: `wp k-cve scan`.
 */
class Cli {
	/**
	 * Kör en sårbarhetskontroll.
	 *
	 * ## OPTIONS
	 *
	 * [--dry-run]
	 * : Skicka inget mejl.
	 *
	 * [--force-mail]
	 * : Mejla även om inget ändrats sedan förra mejlet.
	 *
	 * ## EXAMPLES
	 *
	 *     wp k-cve scan --dry-run
	 */
	public function scan( $args, $assoc_args ): void {
		$dry_run = ! empty( $assoc_args['dry-run'] );
		try {
			$report = ( new Scanner() )->run( ! empty( $assoc_args['force-mail'] ), $dry_run );
		} catch ( \Throwable $e ) {
			\WP_CLI::error( $e->getMessage() );
			return;
		}

		$rows = [];
		foreach ( $report['vulnerable'] as $component ) {
			foreach ( $component['findings'] as $finding ) {
				$rows[] = [
					'grad'       => Mailer::GRADE_LABELS[ $finding['grade'] ],
					'cvss'       => null !== $finding['score'] ? number_format( $finding['score'], 1 ) : '-',
					'komponent'  => $component['name'] . ' ' . $component['version'],
					'cve'        => implode( ' ', array_column( $finding['cves'], 'id' ) ) ?: '-',
					'rättad i'   => $finding['unfixed'] ? 'ingen fix' : ( $finding['fixed_in'] ?? '?' ),
					'sårbarhet'  => $finding['title'],
				];
			}
		}
		if ( $rows ) {
			\WP_CLI\Utils\format_items( 'table', $rows, array_keys( $rows[0] ) );
		}
		foreach ( $report['updates'] as $update ) {
			\WP_CLI::log( sprintf( 'Uppdatering: %s %s → %s', $update['name'], $update['current'], $update['new'] ) );
		}
		foreach ( $report['errors'] as $error ) {
			\WP_CLI::warning( $error );
		}
		\WP_CLI::success( Mailer::subject( $report ) . ( $report['mailed'] ? ' (mejlat till ' . Plugin::recipient() . ')' : ( $dry_run ? ' (dry-run)' : ' (inget mejl: oförändrat)' ) ) );
	}
}
