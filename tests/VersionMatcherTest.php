<?php
use KCve\VersionMatcher;
use PHPUnit\Framework\TestCase;

class VersionMatcherTest extends TestCase {
	private function op( $min, $min_op, $max, $max_op, $unfixed = '0' ): array {
		return [ 'min_version' => $min, 'min_operator' => $min_op, 'max_version' => $max, 'max_operator' => $max_op, 'unfixed' => $unfixed ];
	}

	public function test_max_lt(): void {
		$op = $this->op( null, null, '1.9.9.4', 'lt' );
		$this->assertTrue( VersionMatcher::matches( '1.9.7.3', $op ) );
		$this->assertTrue( VersionMatcher::matches( '1.9.9.3', $op ) );
		$this->assertFalse( VersionMatcher::matches( '1.9.9.4', $op ) );
		$this->assertFalse( VersionMatcher::matches( '2.0', $op ) );
	}

	public function test_max_le(): void {
		$op = $this->op( null, null, '2.0.2.1', 'le' );
		$this->assertTrue( VersionMatcher::matches( '2.0.2.1', $op ) );
		$this->assertFalse( VersionMatcher::matches( '2.0.2.2', $op ) );
	}

	public function test_min_and_max_range(): void {
		$op = $this->op( '1.8.8.2', 'ge', '2.0.2', 'lt' );
		$this->assertFalse( VersionMatcher::matches( '1.8.8.1', $op ) );
		$this->assertTrue( VersionMatcher::matches( '1.8.8.2', $op ) );
		$this->assertTrue( VersionMatcher::matches( '2.0.1', $op ) );
		$this->assertFalse( VersionMatcher::matches( '2.0.2', $op ) );
	}

	public function test_gt_and_eq(): void {
		$this->assertFalse( VersionMatcher::matches( '1.0', $this->op( '1.0', 'gt', null, null ) ) );
		$this->assertTrue( VersionMatcher::matches( '1.0.1', $this->op( '1.0', 'gt', null, null ) ) );
		$this->assertTrue( VersionMatcher::matches( '3.2', $this->op( null, null, '3.2', 'eq' ) ) );
	}

	public function test_trailing_zero_segments_are_equal(): void {
		// version_compare('6.9', '6.9.0') === -1, vilket annars ger falsklarm vid "lt 6.9.0".
		$this->assertFalse( VersionMatcher::matches( '6.9', $this->op( null, null, '6.9.0', 'lt' ) ) );
		$this->assertTrue( VersionMatcher::matches( '6.9.0', $this->op( null, null, '6.9', 'le' ) ) );
	}

	public function test_no_bounds_matches(): void {
		$this->assertTrue( VersionMatcher::matches( '1.0', $this->op( null, null, null, null, '1' ) ) );
		$this->assertTrue( VersionMatcher::matches( '1.0', [] ) );
	}

	public function test_unknown_operator_does_not_match(): void {
		$this->assertFalse( VersionMatcher::matches( '1.0', $this->op( null, null, '2.0', 'weird' ) ) );
	}

	public function test_fixed_in(): void {
		$this->assertSame( '1.9.9.4', VersionMatcher::fixedIn( $this->op( null, null, '1.9.9.4', 'lt' ) ) );
		$this->assertNull( VersionMatcher::fixedIn( $this->op( null, null, '2.0', 'le' ) ) );
		$this->assertNull( VersionMatcher::fixedIn( $this->op( null, null, '2.0', 'lt', '1' ) ) );
	}
}
