<?php
use KCve\Mailer;
use KCve\Report;
use KCve\Sources\WpVulnerability;
use PHPUnit\Framework\TestCase;

class MailerTest extends TestCase {
	private function report(): array {
		$components = [
			[
				'key' => 'plugin:wpforms-lite', 'type' => 'plugin', 'slug' => 'wpforms-lite', 'name' => 'WPForms Lite <script>',
				'version' => '1.9.7.3', 'known' => true, 'notes' => [ 'aktivt' ],
				'findings' => WpVulnerability::parseFindings( kcve_fixture( 'wpv-plugin-wpforms-lite.json' ), '1.9.7.3' ),
			],
			[ 'key' => 'plugin:premium', 'type' => 'plugin', 'slug' => 'premium', 'name' => 'Premium', 'version' => '2.0', 'known' => false, 'notes' => [], 'findings' => [] ],
		];
		$updates = [
			[ 'key' => 'plugin:wpforms-lite', 'type' => 'plugin', 'name' => 'WPForms Lite', 'current' => '1.9.7.3', 'new' => '2.0.3' ],
			[ 'key' => 'theme:astra', 'type' => 'theme', 'name' => 'Astra', 'current' => '4.0', 'new' => '4.1' ],
		];
		return Report::build( [ 'name' => 'Kund AB', 'url' => 'https://kund.test' ], $components, $updates, [ 'nginx kunde inte kontrolleras: timeout' ], 1760000000 );
	}

	public function test_render_contains_graded_findings_with_cve_links(): void {
		$html = Mailer::render( $this->report() );
		$this->assertStringContainsString( 'https://www.cve.org/CVERecord?id=CVE-2026-32446', $html );
		$this->assertStringContainsString( 'Uppdatera till <strong>2.0.3</strong>', $html );
		$this->assertStringContainsString( 'Övriga uppdateringar', $html );
		$this->assertStringContainsString( 'Astra', $html );
		$this->assertStringContainsString( 'Premium 2.0', $html );
		$this->assertStringContainsString( 'timeout', $html );
		$this->assertStringNotContainsString( '<script>', $html, 'Allt från externa källor ska escapas' );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
	}

	public function test_subject(): void {
		$subject = Mailer::subject( $this->report() );
		$this->assertStringStartsWith( '[k-cve] Kund AB: 1 sårbara komponenter', $subject );
		$this->assertStringEndsWith( ', 1 övriga uppdateringar', $subject );
	}

	public function test_rows_per_component_are_capped(): void {
		$findings = [];
		for ( $i = 0; $i < 15; $i++ ) {
			$findings[] = [ 'id' => "f$i", 'title' => "Fynd $i", 'cves' => [], 'links' => [], 'score' => 5.0, 'vector' => null, 'grade' => 'medium', 'kev' => false, 'unfixed' => false, 'fixed_in' => null ];
		}
		$component = [ 'key' => 'mysql:mysql', 'type' => 'mysql', 'slug' => 'mysql', 'name' => 'MySQL', 'version' => '8.0.38', 'known' => true, 'notes' => [], 'findings' => $findings ];
		$html      = Mailer::render( Report::build( [ 'name' => 'S', 'url' => 'u' ], [ $component ], [], [], 1 ) );
		$this->assertSame( 10, substr_count( $html, '>Fynd ' ) );
		$this->assertStringContainsString( '… och 5 till', $html );
	}

	public function test_fix_text_without_known_version(): void {
		$finding = [ 'id' => 'a', 'title' => 'A', 'cves' => [], 'links' => [], 'score' => 5.0, 'vector' => null, 'grade' => 'medium', 'kev' => false, 'unfixed' => false, 'fixed_in' => null ];
		$core    = [ 'key' => 'core:wordpress', 'type' => 'core', 'slug' => 'wordpress', 'name' => 'WordPress', 'version' => '6.9.1', 'known' => true, 'notes' => [], 'findings' => [ $finding ] ];
		$html    = Mailer::render( Report::build( [ 'name' => 'S', 'url' => 'u' ], [ $core ], [], [], 1 ) );
		$this->assertStringContainsString( 'Uppdatera till senaste version', $html );

		$core['findings'][0]['unfixed'] = true;
		$html = Mailer::render( Report::build( [ 'name' => 'S', 'url' => 'u' ], [ $core ], [], [], 1 ) );
		$this->assertStringContainsString( 'Ingen rättad version känd', $html );
	}

	public function test_clean_report(): void {
		$report = Report::build( [ 'name' => 'Ren', 'url' => 'u' ], [], [], [], 1 );
		$this->assertSame( '[k-cve] Ren: inga kända sårbarheter', Mailer::subject( $report ) );
		$this->assertStringContainsString( 'Inga kända sårbarheter hittades.', Mailer::render( $report ) );
	}
}
