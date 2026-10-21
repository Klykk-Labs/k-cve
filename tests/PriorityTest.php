<?php
use KCve\Priority;
use KCve\Report;
use KCve\Sources\Epss;
use PHPUnit\Framework\TestCase;

class PriorityTest extends TestCase {
	private function finding( array $overrides = [] ): array {
		return array_merge( [ 'id' => 'f', 'title' => 'F', 'cves' => [], 'links' => [], 'score' => 6.0, 'vector' => null, 'grade' => 'medium', 'kev' => false, 'unfixed' => false, 'fixed_in' => null ], $overrides );
	}

	private function component( string $key, array $findings, array $overrides = [] ): array {
		list( $type, $slug ) = explode( ':', $key, 2 );
		return array_merge( [ 'key' => $key, 'type' => $type, 'slug' => $slug, 'name' => $slug, 'version' => '1.0', 'known' => true, 'notes' => [], 'findings' => $findings ], $overrides );
	}

	public function cases(): array {
		$plugin = [ 'type' => 'plugin' ];
		return [
			'bara CVSS'             => [ [ 'score' => 9.8 ], $plugin, 9.8, [] ],
			'ograderad räknas som 5' => [ [ 'score' => null, 'grade' => 'none' ], $plugin, 5.0, [] ],
			'KEV'                   => [ [ 'kev' => true ], $plugin, 12.0, [ 'KEV' ] ],
			'hög EPSS'              => [ [ 'epss' => 0.1234, 'epss_percentile' => 0.95 ], $plugin, 9.0, [ 'EPSS 12 %' ] ],
			'låg EPSS ignoreras'    => [ [ 'epss' => 0.003, 'epss_percentile' => 0.4 ], $plugin, 6.0, [] ],
			'utan inloggning'       => [ [ 'vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' ], $plugin, 7.8, [ 'utan inloggning' ] ],
			'kräver inloggning'     => [ [ 'vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' ], $plugin, 6.0, [] ],
			'inaktivt plugin'       => [ [], [ 'type' => 'plugin', 'active' => false ], 3.0, [ 'inaktivt' ] ],
			'serverkomponent'       => [ [], [ 'type' => 'php' ], 4.2, [ 'server' ] ],
			'allt på en gång'       => [ [ 'kev' => true, 'epss' => 0.975, 'epss_percentile' => 0.999, 'vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' ], [ 'type' => 'plugin', 'active' => false ], 11.7, [ 'KEV', 'EPSS 98 %', 'utan inloggning', 'inaktivt' ] ],
		];
	}

	/** @dataProvider cases */
	public function test_score( array $finding, array $component, float $score, array $reasons ): void {
		$result = Priority::score( $this->finding( $finding ), $component );
		$this->assertEqualsWithDelta( $score, $result['score'], 0.001 );
		$this->assertSame( $reasons, $result['reasons'] );
	}

	public function test_epss_formatting(): void {
		$this->assertSame( [ 'EPSS 2,8 %' ], Priority::score( $this->finding( [ 'epss' => 0.0281, 'epss_percentile' => 0.91 ] ), [ 'type' => 'plugin' ] )['reasons'] );
	}

	public function test_report_picks_top_three_by_priority_not_grade(): void {
		$report = Report::build( [ 'name' => 'T', 'url' => 'u' ], [
			$this->component( 'plugin:critical-inactive', [ $this->finding( [ 'score' => 9.8, 'grade' => 'critical' ] ) ], [ 'active' => false ] ),
			$this->component( 'plugin:kev', [ $this->finding( [ 'score' => 6.5, 'kev' => true ] ) ] ),
			$this->component( 'plugin:high', [ $this->finding( [ 'score' => 7.5, 'grade' => 'high' ] ) ] ),
			$this->component( 'php:php', [ $this->finding( [ 'score' => 9.0, 'grade' => 'critical' ] ) ] ),
			$this->component( 'plugin:clean', [] ),
		], [], [], 1 );

		$this->assertSame( [ 'plugin:kev', 'plugin:high', 'php:php' ], $report['top'] );
		$this->assertSame( 'plugin:critical-inactive', $report['vulnerable'][0]['key'], 'Accordion sorteras fortfarande efter grad' );
		$this->assertSame( [ 'KEV' ], array_column( $report['vulnerable'], 'priority', 'key' )['plugin:kev']['reasons'] );
	}

	public function test_epss_lookup_batches_and_parses(): void {
		$urls = [];
		$epss = new Epss(
			static function ( string $url ) use ( &$urls ) {
				$urls[] = $url;
				return kcve_fixture( 'epss.json' );
			}
		);
		$scores = $epss->lookup( [ 'CVE-2021-44228', 'CVE-2026-32446', 'CVE-2023-6553', 'CVE-2021-44228', 'CVE-1999-99999' ] );

		$this->assertSame( [ Epss::URL . 'CVE-2021-44228,CVE-2026-32446,CVE-2023-6553,CVE-1999-99999' ], $urls, 'Unika CVE:er i ett anrop' );
		$this->assertSame( [ 'epss' => 0.97846, 'percentile' => 0.99909 ], $scores['CVE-2023-6553'] );
		$this->assertArrayNotHasKey( 'CVE-1999-99999', $scores, 'Okända CVE:er saknas i svaret' );

		$urls = [];
		$epss->lookup( array_map( static function ( $i ) { return "CVE-2020-$i"; }, range( 1000, 1119 ) ) );
		$this->assertCount( 3, $urls, '120 CVE:er blir 3 anrop om högst 50' );
	}

	public function test_epss_annotate_uses_highest_cve(): void {
		$scores     = [ 'CVE-2026-32446' => [ 'epss' => 0.00281, 'percentile' => 0.19342 ], 'CVE-2023-6553' => [ 'epss' => 0.97846, 'percentile' => 0.99909 ] ];
		$components = [
			$this->component( 'plugin:a', [
				$this->finding( [ 'cves' => [ [ 'id' => 'CVE-2026-32446', 'url' => '' ], [ 'id' => 'CVE-2023-6553', 'url' => '' ] ] ] ),
				$this->finding( [ 'id' => 'utan-cve' ] ),
			] ),
		];
		$findings = Epss::annotate( $components, $scores )[0]['findings'];

		$this->assertSame( 0.97846, $findings[0]['epss'] );
		$this->assertSame( 0.99909, $findings[0]['epss_percentile'] );
		$this->assertNull( $findings[1]['epss'] );
		$this->assertNull( $findings[1]['epss_percentile'] );
	}
}
