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
}
