<?php
use KCve\Sources\Osv;
use KCve\Sources\WpVulnerability;
use PHPUnit\Framework\TestCase;

class SourcesTest extends TestCase {
	private function wpv( array $routes ): WpVulnerability {
		return new WpVulnerability(
			static function ( string $url ) use ( $routes ) {
				if ( ! isset( $routes[ $url ] ) ) {
					throw new RuntimeException( "Oväntad URL $url" );
				}
				return kcve_fixture( $routes[ $url ] );
			}
		);
	}

	public function test_plugin_lookup_matches_known_cve(): void {
		$wpv    = $this->wpv( [ 'https://www.wpvulnerability.net/plugin/wpforms-lite/' => 'wpv-plugin-wpforms-lite.json' ] );
		$result = $wpv->lookup( [ 'type' => 'plugin', 'slug' => 'wpforms-lite', 'version' => '1.9.7.3' ] );

		$this->assertTrue( $result['known'] );
		$match = array_values( array_filter( $result['findings'], static function ( $f ) {
			return in_array( 'CVE-2026-32446', array_column( $f['cves'], 'id' ), true );
		} ) );
		$this->assertCount( 1, $match );
		$this->assertSame( 4.3, $match[0]['score'] );
		$this->assertSame( 'medium', $match[0]['grade'] );
		$this->assertSame( '1.9.9.4', $match[0]['fixed_in'] );
		$this->assertSame( 'Contact Form by WPForms <= 1.9.9.3 - Missing Authorization', $match[0]['title'] );
		$this->assertSame( 'https://www.cve.org/CVERecord?id=CVE-2026-32446', $match[0]['cves'][0]['url'] );
	}

	public function test_findings_without_impact_are_kept_ungraded(): void {
		$findings = WpVulnerability::parseFindings( kcve_fixture( 'wpv-plugin-wpforms-lite.json' ), '1.0' );
		$ungraded = array_filter( $findings, static function ( $f ) {
			return null === $f['score'];
		} );
		$this->assertNotEmpty( $ungraded );
		foreach ( $ungraded as $f ) {
			$this->assertSame( 'none', $f['grade'] );
		}
	}

	public function test_latest_version_has_no_findings(): void {
		$this->assertSame( [], WpVulnerability::parseFindings( kcve_fixture( 'wpv-plugin-wpforms-lite.json' ), '99.0' ) );
	}

	public function test_titles_are_decoded(): void {
		foreach ( WpVulnerability::parseFindings( kcve_fixture( 'wpv-plugin-wpforms-lite.json' ), '1.0' ) as $f ) {
			$this->assertStringNotContainsString( '&#8211;', $f['title'] );
		}
	}

	public function test_core_findings_apply_without_operator(): void {
		$findings = WpVulnerability::parseFindings( kcve_fixture( 'wpv-core-6.9.1.json' ), '6.9.1' );
		$this->assertCount( 25, $findings );
		$this->assertNotSame( '6.9.1', $findings[0]['title'], 'Titeln ska hämtas från källan, inte versionsnumret' );
	}

	public function test_php_lookup_uses_version_and_description_title(): void {
		$wpv      = $this->wpv( [ 'https://www.wpvulnerability.net/php/7.4.0/' => 'wpv-php-7.4.0.json' ] );
		$findings = $wpv->lookup( [ 'type' => 'php', 'slug' => 'php', 'version' => '7.4.0' ] )['findings'];
		$this->assertNotEmpty( $findings );
		$this->assertStringStartsWith( 'In PHP versions before', $findings[0]['title'] );
	}

	public function test_identifier_names_are_not_titles(): void {
		$response = [ 'data' => [ 'vulnerability' => [ [
			'uuid'   => 'x',
			'name'   => 'PHP 8.3 < 8.3.19',
			'source' => [
				[ 'id' => 'EUVD-2025-1', 'name' => 'CVE-2025-1861', 'link' => 'https://euvd.test' ],
				[ 'id' => 'CVE-2025-1861', 'name' => 'CVE-2025-1861', 'description' => '[en] Riktig beskrivning.' ],
			],
		] ] ] ];
		$this->assertSame( 'Riktig beskrivning.', WpVulnerability::parseFindings( $response, '8.3.14' )[0]['title'] );

		$response['data']['vulnerability'][0]['source'] = [ [ 'id' => 'CVE-2025-1861', 'description' => 'CVE-2025-1861' ] ];
		$this->assertSame( 'PHP 8.3 < 8.3.19', WpVulnerability::parseFindings( $response, '8.3.14' )[0]['title'] );
	}

	public function test_unknown_plugin(): void {
		$wpv    = $this->wpv( [ 'https://www.wpvulnerability.net/plugin/this-plugin-does-not-exist-kcve/' => 'wpv-plugin-unknown.json' ] );
		$result = $wpv->lookup( [ 'type' => 'plugin', 'slug' => 'this-plugin-does-not-exist-kcve', 'version' => '1.0' ] );
		$this->assertFalse( $result['known'] );
		$this->assertSame( [], $result['findings'] );
	}

	public function test_osv_lookup(): void {
		$posted = null;
		$osv    = new Osv(
			static function ( string $url, array $body ) use ( &$posted ) {
				$posted = $body;
				return kcve_fixture( 'osv-querybatch.json' );
			},
			static function ( string $url ) {
				$id   = basename( $url );
				$file = __DIR__ . "/fixtures/osv-vuln-$id.json";
				// Bara en detaljfixtur finns; övriga får ett minimalt svar.
				return is_file( $file ) ? kcve_fixture( "osv-vuln-$id.json" ) : [ 'id' => $id, 'summary' => 'x' ];
			}
		);
		$components = [
			'a' => [ 'type' => 'composer', 'slug' => 'guzzlehttp/guzzle', 'version' => 'v7.4.0' ],
			'b' => [ 'type' => 'composer', 'slug' => 'psr/log', 'version' => '1.1.4' ],
		];
		$result = $osv->lookup( $components );

		$this->assertSame( '7.4.0', $posted['queries'][0]['version'] );
		$this->assertArrayNotHasKey( 'b', $result );
		$guzzle = array_column( $result['a'], null, 'id' )['GHSA-25mq-v84q-4j7r'];
		$this->assertSame( 'CVE-2022-31090', $guzzle['cves'][0]['id'] );
		$this->assertSame( 7.7, $guzzle['score'] );
		$this->assertSame( 'high', $guzzle['grade'] );
		$this->assertSame( '7.4.5', $guzzle['fixed_in'] );
	}

	public function test_osv_label_fallback(): void {
		$finding = Osv::parseVuln( [ 'id' => 'GHSA-x', 'database_specific' => [ 'severity' => 'MODERATE' ] ], 'a/b', '1.0' );
		$this->assertNull( $finding['score'] );
		$this->assertSame( 'medium', $finding['grade'] );
		$this->assertTrue( $finding['unfixed'] );
	}
}
