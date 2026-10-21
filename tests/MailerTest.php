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

	public function test_components_are_collapsible_with_type_tag(): void {
		$html = Mailer::render( $this->report() );
		$this->assertSame( 1, substr_count( $html, '<details' ), 'En accordion per sårbar komponent' );
		$this->assertMatchesRegularExpression( '#<summary[^>]*>.*>Plugin</span>.*WPForms Lite &lt;script&gt; 1\.9\.7\.3.*sårbarheter.*Uppdatera till <strong>2\.0\.3</strong>.*</summary>#s', $html );
		$this->assertStringContainsString( '>Tema</span>', $html, 'Typtagg även i uppdateringstabellen' );
	}

	public function test_subject(): void {
		$subject = Mailer::subject( $this->report() );
		$this->assertStringStartsWith( '[Klykk CVE] Kund AB: 1 sårbara komponenter', $subject );
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
		$this->assertSame( '[Klykk CVE] Ren: inga kända sårbarheter', Mailer::subject( $report ) );
		$this->assertStringContainsString( 'Inga kända sårbarheter hittades.', Mailer::render( $report ) );
	}

	public function test_new_label_and_days_open(): void {
		$finding   = [ 'id' => 'a', 'title' => 'Gammalt fynd', 'cves' => [], 'links' => [], 'score' => 9.8, 'vector' => null, 'grade' => 'critical', 'kev' => false, 'unfixed' => false, 'fixed_in' => '2.0' ];
		$new       = array_merge( $finding, [ 'id' => 'b', 'title' => 'Nytt fynd' ] );
		$component = [ 'key' => 'plugin:p', 'type' => 'plugin', 'slug' => 'p', 'name' => 'P', 'version' => '1.0', 'known' => true, 'notes' => [], 'findings' => [ $finding, $new ] ];
		$now       = 100 * 86400;
		$report    = Report::build( [ 'name' => 'S', 'url' => 'u' ], [ $component ], [], [], $now, [ 'plugin:p#a' => $now - 12 * 86400 ], $now - 86400 );
		$html      = Mailer::render( $report );

		$this->assertMatchesRegularExpression( '#<summary.*>NY</span>.*</summary>#s', $html, 'Komponenten märks NY' );
		$this->assertMatchesRegularExpression( '#Nytt fynd <span[^>]*>NY</span>#', $html );
		$this->assertDoesNotMatchRegularExpression( '#Gammalt fynd <span[^>]*>NY<#', $html, 'Gamla fynd märks inte NY' );
		$this->assertStringContainsString( 'öppet i 12 dagar', $html );

		$report['reminder'] = true;
		$this->assertStringStartsWith( '[Klykk CVE] Påminnelse: S: ', Mailer::subject( $report ) );
		$this->assertStringContainsString( 'har varit öppna i minst 7 dagar', Mailer::render( $report ) );
	}

	public function test_fix_first_section(): void {
		$kev    = [ 'id' => 'k', 'title' => 'K', 'cves' => [], 'links' => [], 'score' => 6.5, 'vector' => null, 'grade' => 'medium', 'kev' => true, 'unfixed' => false, 'fixed_in' => '3.1' ];
		$report = Report::build( [ 'name' => 'S', 'url' => 'u' ], [
			[ 'key' => 'plugin:k', 'type' => 'plugin', 'slug' => 'k', 'name' => 'Kevplugin', 'version' => '3.0', 'known' => true, 'notes' => [], 'findings' => [ $kev ] ],
		], [], [], 1 );
		$html = Mailer::render( $report );

		$this->assertMatchesRegularExpression( '#Åtgärda först</h3><ol.*<li.*Kevplugin 3\.0.*Uppdatera till <strong>3\.1</strong>.*>KEV</span>.*</li></ol>.*<details#s', $html );
		$this->assertStringNotContainsString( 'Åtgärda först', Mailer::render( Report::build( [ 'name' => 'S', 'url' => 'u' ], [], [], [], 1 ) ) );
	}

	public function test_old_stored_reports_still_render(): void {
		$report = $this->report();
		foreach ( $report['vulnerable'] as &$component ) {
			unset( $component['has_new'] );
			foreach ( $component['findings'] as &$finding ) {
				unset( $finding['is_new'], $finding['days_open'] );
			}
			unset( $finding );
		}
		unset( $component, $report['first_seen'], $report['overdue'], $report['top'] );
		$this->assertStringContainsString( 'CVE-2026-32446', Mailer::render( $report ), 'Senaste rapporten från 0.2.0 ligger kvar i databasen' );
	}
}
