<?php
namespace KCve\Sources;

use KCve\Cvss;
use KCve\VersionMatcher;

defined( 'ABSPATH' ) || exit;

/**
 * Composer-paket som ligger inbäddade i plugins/teman kontrolleras mot OSV.dev
 * (GitHub Advisory Database m.fl., ecosystem "Packagist").
 */
class Osv {
	public const BATCH_URL = 'https://api.osv.dev/v1/querybatch';
	public const VULN_URL  = 'https://api.osv.dev/v1/vulns/';
	private const BATCH_SIZE = 500;

	/** @var callable(string, array): array POST med JSON-body, kastar \RuntimeException vid fel. */
	private $post;
	/** @var callable(string): array */
	private $get;

	public function __construct( callable $post, callable $get ) {
		$this->post = $post;
		$this->get  = $get;
	}

	/**
	 * @param array $components Composer-komponenter (slug = "vendor/paket").
	 * @return array Fynd per komponentindex (samma nycklar som $components).
	 */
	public function lookup( array $components ): array {
		$ids_per_component = [];
		foreach ( array_chunk( $components, self::BATCH_SIZE, true ) as $chunk ) {
			$queries = [];
			foreach ( $chunk as $component ) {
				$queries[] = [
					'package' => [ 'name' => $component['slug'], 'ecosystem' => 'Packagist' ],
					'version' => ltrim( $component['version'], 'vV' ),
				];
			}
			$response = ( $this->post )( self::BATCH_URL, [ 'queries' => $queries ] );
			$results  = $response['results'] ?? [];
			foreach ( array_keys( $chunk ) as $i => $key ) {
				$ids_per_component[ $key ] = array_column( $results[ $i ]['vulns'] ?? [], 'id' );
			}
		}

		$details  = [];
		$findings = [];
		foreach ( $ids_per_component as $key => $ids ) {
			foreach ( $ids as $id ) {
				if ( ! isset( $details[ $id ] ) ) {
					$details[ $id ] = ( $this->get )( self::VULN_URL . rawurlencode( $id ) );
				}
				$findings[ $key ][] = self::parseVuln( $details[ $id ], $components[ $key ]['slug'], $components[ $key ]['version'] );
			}
		}
		return $findings;
	}

	public static function parseVuln( array $vuln, string $package, string $version ): array {
		$cves = [];
		foreach ( array_merge( [ $vuln['id'] ?? '' ], (array) ( $vuln['aliases'] ?? [] ) ) as $alias ) {
			if ( preg_match( '/^CVE-\d{4}-\d+$/', $alias ) ) {
				$cves[] = [ 'id' => $alias, 'url' => 'https://www.cve.org/CVERecord?id=' . $alias ];
			}
		}

		$vector = null;
		foreach ( (array) ( $vuln['severity'] ?? [] ) as $severity ) {
			if ( 'CVSS_V3' === ( $severity['type'] ?? '' ) ) {
				$vector = $severity['score'];
			}
		}
		$score = null !== $vector ? Cvss::scoreFromVector( $vector ) : null;
		$grade = null !== $score
			? Cvss::grade( $score )
			: Cvss::gradeFromLabel( $vuln['database_specific']['severity'] ?? null );

		$fixed_in = self::fixedIn( $vuln, $package, $version );
		$id       = (string) ( $vuln['id'] ?? '' );
		return [
			'id'       => $id,
			'title'    => (string) ( $vuln['summary'] ?? $id ),
			'cves'     => $cves,
			'links'    => [ 'https://osv.dev/vulnerability/' . rawurlencode( $id ) ],
			'score'    => $score,
			'vector'   => $vector,
			'grade'    => $grade,
			'kev'      => false,
			'unfixed'  => null === $fixed_in,
			'fixed_in' => $fixed_in,
		];
	}

	/** Hittar det intervall (introduced → fixed) som innehåller installerad version. */
	private static function fixedIn( array $vuln, string $package, string $version ): ?string {
		foreach ( (array) ( $vuln['affected'] ?? [] ) as $affected ) {
			if ( strcasecmp( $affected['package']['name'] ?? '', $package ) !== 0 ) {
				continue;
			}
			foreach ( (array) ( $affected['ranges'] ?? [] ) as $range ) {
				$introduced = '0';
				foreach ( (array) ( $range['events'] ?? [] ) as $event ) {
					if ( isset( $event['introduced'] ) ) {
						$introduced = $event['introduced'];
					} elseif ( isset( $event['fixed'] ) ) {
						$in_range = ( '0' === $introduced || VersionMatcher::compare( $version, $introduced, '>=' ) )
							&& VersionMatcher::compare( $version, $event['fixed'], '<' );
						if ( $in_range ) {
							return $event['fixed'];
						}
					}
				}
			}
		}
		return null;
	}
}
