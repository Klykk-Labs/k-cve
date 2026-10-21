<?php
namespace KCve\Sources;

defined( 'ABSPATH' ) || exit;

/**
 * EPSS (FIRST.org): sannolikheten att en CVE utnyttjas de närmaste 30 dagarna.
 * Gratis, ingen nyckel, uppdateras dagligen.
 */
class Epss {
	public const URL         = 'https://api.first.org/data/v1/epss?cve=';
	private const BATCH_SIZE = 50; // API:ts standardgräns är 100 svar; 50 håller också URL:en kort.

	/** @var callable(string): array */
	private $get;

	public function __construct( callable $get ) {
		$this->get = $get;
	}

	/** @return array [ 'CVE-…' => [ 'epss' => float, 'percentile' => float ] ]. CVE:er utan data saknas. */
	public function lookup( array $cves ): array {
		$scores = [];
		foreach ( array_chunk( array_values( array_unique( $cves ) ), self::BATCH_SIZE ) as $chunk ) {
			$response = call_user_func( $this->get, self::URL . implode( ',', $chunk ) );
			foreach ( $response['data'] ?? [] as $row ) {
				$scores[ $row['cve'] ] = [ 'epss' => (float) $row['epss'], 'percentile' => (float) $row['percentile'] ];
			}
		}
		return $scores;
	}

	/** Lägger 'epss' och 'epss_percentile' på varje fynd: högsta värdet bland fyndets CVE:er, annars null. */
	public static function annotate( array $components, array $scores ): array {
		foreach ( $components as &$component ) {
			foreach ( $component['findings'] as &$finding ) {
				$best = null;
				foreach ( $finding['cves'] as $cve ) {
					if ( isset( $scores[ $cve['id'] ] ) && ( null === $best || $scores[ $cve['id'] ]['percentile'] > $best['percentile'] ) ) {
						$best = $scores[ $cve['id'] ];
					}
				}
				$finding['epss']            = $best ? $best['epss'] : null;
				$finding['epss_percentile'] = $best ? $best['percentile'] : null;
			}
			unset( $finding );
		}
		unset( $component );
		return $components;
	}

	/** Alla CVE-id:n i komponenternas fynd. */
	public static function cves( array $components ): array {
		$cves = [];
		foreach ( $components as $component ) {
			foreach ( $component['findings'] as $finding ) {
				foreach ( $finding['cves'] as $cve ) {
					$cves[] = $cve['id'];
				}
			}
		}
		return array_values( array_unique( $cves ) );
	}
}
