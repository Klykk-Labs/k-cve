<?php
use KCve\Hub;
use KCve\Report;
use PHPUnit\Framework\TestCase;

class HubTest extends TestCase {
	private function report( array $integrity = [] ): array {
		return Report::build( [ 'name' => 'Test', 'url' => 'https://example.test' ], [], [], [], 1700000000, [], 0, $integrity );
	}

	public function test_signature_matches_shared_vector(): void {
		// Samma fil finns i klykk-dash. Uträknad med Pythons hmac, inte med koden som testas.
		$vector = kcve_fixture( 'hub-signature-vector.json' );
		$this->assertSame( $vector['signature'], Hub::sign( $vector['secret'], $vector['timestamp'], $vector['body'] ) );
	}

	public function test_request_signs_exact_body_and_sets_headers(): void {
		$request = Hub::request( $this->report(), '12', 'hemlighet', 1792750000 );

		$this->assertSame( '12', $request['headers']['X-KCve-Site'] );
		$this->assertSame( '1792750000', $request['headers']['X-KCve-Timestamp'] );
		$this->assertSame( 'application/json', $request['headers']['Content-Type'] );
		$this->assertSame( hash_hmac( 'sha256', '1792750000.' . $request['body'], 'hemlighet' ), $request['headers']['X-KCve-Signature'] );
		$this->assertIsArray( json_decode( $request['body'], true ) );
	}

	public function test_payload_has_keys_hub_requires_and_no_first_seen(): void {
		$payload = Hub::payload( $this->report() );

		foreach ( [ 'generated', 'vulnerable', 'counts', 'fingerprint' ] as $key ) {
			$this->assertArrayHasKey( $key, $payload );
		}
		$this->assertArrayNotHasKey( 'first_seen', $payload, 'first_seen är intern data' );
	}

	public function test_payload_replaces_admin_logins_with_id(): void {
		$payload = Hub::payload( $this->report( [
			[ 'group' => 'admin_new', 'path' => 'eve (ID 7)' ],
			[ 'group' => 'admin_review', 'path' => 'namn med (parentes) (ID 1)' ],
			[ 'group' => 'file_new', 'path' => 'mu-plugins/x (ID 3).php' ],
		] ) );

		$this->assertSame(
			[ 'ID 7', 'ID 1', 'mu-plugins/x (ID 3).php' ],
			array_column( $payload['integrity'], 'path' ),
			'Bara admin-grupperna rensas, filsökvägar lämnas orörda'
		);
	}

	public function test_invalid_utf8_does_not_break_encoding(): void {
		$report                    = $this->report();
		$report['site']['name']    = "Trasig \xC3\x28 text";
		$request                   = Hub::request( $report, '1', 's', 1 );
		$this->assertIsArray( json_decode( $request['body'], true ) );
	}
}
