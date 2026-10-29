<?php
use KCve\Report;
use PHPUnit\Framework\TestCase;

class ReportTest extends TestCase {
	private function finding( string $id, ?float $score, string $grade, bool $unfixed = false, ?string $fixed_in = null ): array {
		return [ 'id' => $id, 'title' => $id, 'cves' => [], 'links' => [], 'score' => $score, 'vector' => null, 'grade' => $grade, 'kev' => false, 'unfixed' => $unfixed, 'fixed_in' => $fixed_in ];
	}

	private function component( string $key, string $version, array $findings, bool $known = true ): array {
		list( $type, $slug ) = explode( ':', $key, 2 );
		return [ 'key' => $key, 'type' => $type, 'slug' => $slug, 'name' => ucfirst( $slug ), 'version' => $version, 'known' => $known, 'findings' => $findings, 'notes' => [] ];
	}

	private function build( array $components, array $updates = [], array $errors = [] ): array {
		return Report::build( [ 'name' => 'Test', 'url' => 'https://example.test' ], $components, $updates, $errors, 1700000000 );
	}

	public function test_components_sorted_by_worst_grade_then_score(): void {
		$report = $this->build( [
			$this->component( 'plugin:medium', '1.0', [ $this->finding( 'm', 5.0, 'medium' ) ] ),
			$this->component( 'plugin:clean', '1.0', [] ),
			$this->component( 'plugin:ungraded', '1.0', [ $this->finding( 'u', null, 'none' ) ] ),
			$this->component( 'plugin:high-low', '1.0', [ $this->finding( 'h1', 7.1, 'high' ) ] ),
			$this->component( 'plugin:high-top', '1.0', [ $this->finding( 'l', 2.0, 'low' ), $this->finding( 'h2', 8.8, 'high' ) ] ),
		] );

		$this->assertSame( [ 'plugin:high-top', 'plugin:high-low', 'plugin:medium', 'plugin:ungraded' ], array_column( $report['vulnerable'], 'key' ) );
		$this->assertSame( 'high', $report['vulnerable'][0]['worst_grade'] );
		$this->assertSame( [ 'h2', 'l' ], array_column( $report['vulnerable'][0]['findings'], 'id' ), 'Fynd sorteras inom komponenten' );
		$this->assertSame( [ 'critical' => 0, 'high' => 2, 'medium' => 1, 'low' => 1, 'none' => 1 ], $report['counts'] );
	}

	public function test_unfixed_breaks_ties(): void {
		$report = $this->build( [
			$this->component( 'plugin:a', '1.0', [ $this->finding( 'a', 7.5, 'high' ) ] ),
			$this->component( 'plugin:b', '1.0', [ $this->finding( 'b', 7.5, 'high', true ) ] ),
		] );
		$this->assertSame( 'plugin:b', $report['vulnerable'][0]['key'] );
	}

	public function test_fix_version_prefers_available_update(): void {
		$updates = [ [ 'key' => 'plugin:a', 'type' => 'plugin', 'name' => 'A', 'current' => '1.0', 'new' => '2.1' ] ];
		$report  = $this->build( [
			$this->component( 'plugin:a', '1.0', [ $this->finding( 'x', 5.0, 'medium', false, '1.5' ), $this->finding( 'y', 6.0, 'medium', false, '2.0' ) ] ),
			$this->component( 'plugin:b', '1.0', [ $this->finding( 'z', 5.0, 'medium', false, '1.5' ), $this->finding( 'w', 6.0, 'medium', false, '1.10' ) ] ),
		], $updates );

		$by_key = array_column( $report['vulnerable'], null, 'key' );
		$this->assertSame( '2.1', $by_key['plugin:a']['fix_version'] );
		$this->assertSame( '1.10', $by_key['plugin:b']['fix_version'], 'Högsta fixed_in, jämfört som version' );
		$this->assertSame( [], $report['updates'], 'Uppdateringen redovisas redan under sårbarheter' );
	}

	public function test_other_updates_and_unknown(): void {
		$updates = [ [ 'key' => 'theme:t', 'type' => 'theme', 'name' => 'T', 'current' => '1.0', 'new' => '1.1' ] ];
		$report  = $this->build( [ $this->component( 'plugin:premium', '3.0', [], false ) ], $updates, [ 'plugin:x: timeout' ] );
		$this->assertSame( $updates, $report['updates'] );
		$this->assertSame( [ 'Premium 3.0' ], $report['unknown'] );
		$this->assertSame( [ 'plugin:x: timeout' ], $report['errors'] );
		$this->assertTrue( Report::hasContent( $report ) );
		$this->assertFalse( Report::hasContent( $this->build( [] ) ) );
	}

	public function test_fingerprint_ignores_order_and_time_but_not_content(): void {
		$a = $this->component( 'plugin:a', '1.0', [ $this->finding( 'x', 5.0, 'medium' ) ] );
		$b = $this->component( 'plugin:b', '1.0', [ $this->finding( 'y', 6.0, 'medium' ) ] );

		$one = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a, $b ], [], [], 1 );
		$two = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $b, $a ], [], [], 2 );
		$this->assertSame( $one['fingerprint'], $two['fingerprint'] );

		$a['version'] = '1.1';
		$three        = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a, $b ], [], [], 3 );
		$this->assertNotSame( $one['fingerprint'], $three['fingerprint'] );
	}
	public function test_first_seen_is_kept_pruned_and_marks_new_since_last_mail(): void {
		$day  = 86400;
		$now  = 1000 + 8 * $day;
		$a    = $this->component( 'plugin:a', '1.0', [ $this->finding( 'x', 7.5, 'high' ), $this->finding( 'y', 5.0, 'medium' ) ] );
		$prev = [ 'plugin:a#x' => 1000, 'plugin:gone#z' => 500 ];

		$report   = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a ], [], [], $now, $prev, 1500 );
		$findings = array_column( $report['vulnerable'][0]['findings'], null, 'id' );

		$this->assertSame( [ 'plugin:a#x' => 1000, 'plugin:a#y' => $now ], $report['first_seen'], 'Försvunna fynd rensas' );
		$this->assertFalse( $findings['x']['is_new'] );
		$this->assertTrue( $findings['y']['is_new'], 'Sett efter senaste mejlet' );
		$this->assertSame( 8, $findings['x']['days_open'] );
		$this->assertSame( 0, $findings['y']['days_open'] );
		$this->assertTrue( $report['vulnerable'][0]['has_new'] );
		$this->assertSame( 1, $report['overdue'], 'Bara Kritisk/Hög öppna minst 7 dagar räknas' );
		$this->assertSame( $report['fingerprint'], Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a ], [], [], $now )['fingerprint'], 'first_seen påverkar inte fingerprintet' );
	}

	public function test_nothing_is_new_before_first_mail(): void {
		$a      = $this->component( 'plugin:a', '1.0', [ $this->finding( 'x', 7.5, 'high' ) ] );
		$report = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a ], [], [], 5000 );
		$this->assertFalse( $report['vulnerable'][0]['findings'][0]['is_new'] );
		$this->assertFalse( $report['vulnerable'][0]['has_new'] );
	}

	public function test_server_components_are_the_hosts_responsibility(): void {
		$day    = 86400;
		$now    = 100 * $day;
		$db     = $this->component( 'mariadb:mariadb', '11.4.12', [ $this->finding( 'm', 9.9, 'critical', false, '11.4.13' ) ] );
		$plugin = $this->component( 'plugin:a', '1.0', [ $this->finding( 'x', 5.0, 'medium' ) ] );
		$build  = function ( array $components ) use ( $now, $day ) {
			return Report::build( [ 'name' => 'T', 'url' => 'u' ], $components, [], [], $now, [ 'mariadb:mariadb#m' => $now - 30 * $day ], 1 );
		};
		$report = $build( [ $db, $plugin ] );

		$this->assertSame( [ 'plugin:a' ], array_column( $report['vulnerable'], 'key' ) );
		$this->assertSame( [ 'mariadb:mariadb' ], array_column( $report['hosting'], 'key' ) );
		$this->assertSame( '11.4.13', $report['hosting'][0]['fix_version'] );
		$this->assertSame( 30, $report['hosting'][0]['findings'][0]['days_open'] );
		$this->assertSame( 0, $report['counts']['critical'], 'Graderingen överst gäller det som går att åtgärda på siten' );
		$this->assertSame( 1, $report['counts']['medium'] );
		$this->assertSame( [ 'plugin:a' ], $report['top'] );
		$this->assertSame( 0, $report['overdue'], 'Inga påminnelser om serverkomponenter' );
		$this->assertNotSame( $build( [ $plugin ] )['fingerprint'], $report['fingerprint'], 'En ny serverversion eller ett nytt fynd ger ändå ett mejl' );
		$this->assertSame( 'changed', Report::mailReason( $build( [ $db ] ), [], $now, false ) );
	}

	public function test_mail_reason(): void {
		$day    = 86400;
		$now    = 100 * $day;
		$a      = $this->component( 'plugin:a', '1.0', [ $this->finding( 'x', 9.8, 'critical' ) ] );
		$fresh  = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a ], [], [], $now, [ 'plugin:a#x' => $now - $day ], 1 );
		$old    = Report::build( [ 'name' => 'T', 'url' => 'u' ], [ $a ], [], [], $now, [ 'plugin:a#x' => $now - 10 * $day ], 1 );
		$same   = function ( array $report, int $sent ) { return [ 'fingerprint' => $report['fingerprint'], 'time' => $sent ]; };

		$this->assertNull( Report::mailReason( $this->build( [] ), [], $now, true ), 'Inget innehåll, inget mejl' );
		$this->assertSame( 'changed', Report::mailReason( $fresh, [ 'fingerprint' => 'annat', 'time' => $now ], $now, false ) );
		$this->assertSame( 'changed', Report::mailReason( $fresh, [], $now, false ) );
		$this->assertNull( Report::mailReason( $fresh, $same( $fresh, $now - 10 * $day ), $now, false ), 'Inget fynd har varit öppet länge nog' );
		$this->assertNull( Report::mailReason( $old, $same( $old, $now - 3 * $day ), $now, false ), 'Senaste mejlet är för nytt' );
		$this->assertSame( 'reminder', Report::mailReason( $old, $same( $old, $now - 7 * $day ), $now, false ) );
		$this->assertSame( 'forced', Report::mailReason( $fresh, $same( $fresh, $now ), $now, true ) );
	}
}
