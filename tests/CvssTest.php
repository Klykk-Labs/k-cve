<?php
use KCve\Cvss;
use PHPUnit\Framework\TestCase;

class CvssTest extends TestCase {
	/** @dataProvider vectors */
	public function test_base_score( string $vector, float $expected ): void {
		$this->assertSame( $expected, Cvss::scoreFromVector( $vector ) );
	}

	public function vectors(): array {
		// Facit från NVD:s kalkylator.
		return [
			'CVE-2022-31090 (guzzle)'  => [ 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N', 7.7 ],
			'klassisk RCE'             => [ 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8 ],
			'PHP-fixtur'               => [ 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L', 2.3 ],
			'lagrad XSS'               => [ 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4 ],
			'scope changed max'        => [ 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0 ],
			'ingen påverkan'           => [ 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0 ],
		];
	}

	public function test_invalid_vector_returns_null(): void {
		$this->assertNull( Cvss::scoreFromVector( 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' ) );
		$this->assertNull( Cvss::scoreFromVector( 'garbage' ) );
	}

	public function test_grade(): void {
		$this->assertSame( 'critical', Cvss::grade( 9.0 ) );
		$this->assertSame( 'high', Cvss::grade( 8.9 ) );
		$this->assertSame( 'high', Cvss::grade( 7.0 ) );
		$this->assertSame( 'medium', Cvss::grade( 4.0 ) );
		$this->assertSame( 'low', Cvss::grade( 0.1 ) );
		$this->assertSame( 'none', Cvss::grade( 0.0 ) );
		$this->assertSame( 'none', Cvss::grade( null ) );
	}

	public function test_grade_from_label(): void {
		$this->assertSame( 'medium', Cvss::gradeFromLabel( 'MODERATE' ) );
		$this->assertSame( 'critical', Cvss::gradeFromLabel( 'critical' ) );
		$this->assertSame( 'none', Cvss::gradeFromLabel( null ) );
	}
}
