<?php
use KCve\Integrity;
use KCve\Mailer;
use KCve\Report;
use PHPUnit\Framework\TestCase;

class IntegrityTest extends TestCase {
	public function test_compare_finds_modified_missing_and_unknown(): void {
		$expected = [ 'a.php' => [ 'h1' ], 'b.php' => [ 'h2' ], 'c.php' => [ 'h3', 'h3b' ], 'gone.php' => [ 'h4' ] ];
		$hashes   = [ 'a.php' => 'h1', 'b.php' => 'EVIL', 'c.php' => 'h3b', 'shell.php' => 'x' ];
		$diff     = Integrity::compare(
			$expected,
			static function ( $path ) use ( $hashes ) {
				return $hashes[ $path ];
			},
			array_keys( $hashes )
		);
		$this->assertSame( [ 'b.php' ], $diff['modified'], 'c.php matchar en av flera godkända hashar' );
		$this->assertSame( [ 'gone.php' ], $diff['missing'] );
		$this->assertSame( [ 'shell.php' ], $diff['unknown'] );
	}

	public function test_plugin_checksums_keep_php_and_accept_hash_arrays(): void {
		$expected = Integrity::pluginExpected( kcve_fixture( 'plugin-checksums-hello-dolly.json' ) );
		$this->assertSame( [ 'hello.php' ], array_keys( $expected ), 'Bara .php-filer jämförs' );
		$this->assertSame( [ '9ea06ae4bede901030b22a7ac6112eafa8cec51892861abeb8a33364d807eeff' ], $expected['hello.php'] );

		$array_form = Integrity::pluginExpected( [ 'files' => [ 'x.php' => [ 'md5' => 'm', 'sha256' => [ 'S1', 's2' ] ] ] ] );
		$this->assertSame( [ 'x.php' => [ 's1', 's2' ] ], $array_form );
	}

	public function test_executable_names_and_stubs(): void {
		foreach ( [ 'x.php', 'X.PHP', 'a.php7', 'a.phtml', 'a.phar', '2026/10/shell.php5' ] as $name ) {
			$this->assertTrue( Integrity::isExecutable( $name ), $name );
		}
		foreach ( [ 'bild.jpg', 'x.php.jpg', 'php', 'a.phps' ] as $name ) {
			$this->assertFalse( Integrity::isExecutable( $name ), $name );
		}
		$this->assertTrue( Integrity::isHarmless( "<?php\n// Silence is golden.\n" ) );
		$this->assertTrue( Integrity::isHarmless( '<?php' ) );
		$this->assertFalse( Integrity::isHarmless( '<?php system($_GET["c"]);' ) );
		$this->assertFalse( Integrity::isHarmless( "<?php // Silence is golden.\neval(\$_POST['x']);" ) );
		// En //-kommentar slutar vid en sluttagg, så det som följer är ny kod.
		$this->assertFalse( Integrity::isHarmless( '<?php // x ?><?php system($_GET["c"]);' ) );
		$this->assertFalse( Integrity::isHarmless( "<?php # x ?>\n<?php eval(\$_POST['x']);" ) );
	}

	public function test_harmless_guards_from_plugins(): void {
		// WPForms uploads/wpforms/cache/index.php.
		$this->assertTrue( Integrity::isHarmless( "<?php\nheader( \$_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found' );\nheader( 'Status: 404 Not Found' );\n" ) );
		// MC4WP debug-log.php: allt efter exit körs aldrig, inte ens kod som loggats från formulär.
		$this->assertTrue( Integrity::isHarmless( "<?php exit; ?>\n[2026-10-29] Fel: <?php system('x'); ?>\n" ) );
		$this->assertTrue( Integrity::isHarmless( "<?php die(); ?>\nlogg", false ), 'Exit-vakten räcker även för en avkortad fil' );
		$this->assertFalse( Integrity::isHarmless( "<?php\n// bara kommentarer i början\n", false ), 'Avkortad fil utan exit kan ha kod längre ned' );
		$this->assertFalse( Integrity::isHarmless( "<?php header( \$_GET['h'] );" ) );
		$this->assertFalse( Integrity::isHarmless( "<?php header( 'x' ); \$_SERVER['SERVER_PROTOCOL']( 'id' );" ) );
		$this->assertFalse( Integrity::isHarmless( '<?php exit_handler(); system("x");' ) );
		$this->assertFalse( Integrity::isHarmless( '<?php system("x"); exit;' ) );
	}

	public function test_baseline_changes(): void {
		$changes = Integrity::changes(
			[ 'mu-plugins/a.php' => 'h1', 'mu-plugins/b.php' => 'h2', 'wp-content/gone.php' => 'h3' ],
			[ 'mu-plugins/a.php' => 'h1', 'mu-plugins/b.php' => 'EVIL', 'mu-plugins/plugins.php' => 'h4' ]
		);
		$this->assertSame( [ 'mu-plugins/plugins.php' ], $changes['new'] );
		$this->assertSame( [ 'mu-plugins/b.php' ], $changes['changed'], 'Borttagna filer rapporteras inte' );
	}

	private function report( array $integrity ): array {
		return Report::build( [ 'name' => 'S', 'url' => 'u' ], [], [], [], 1, [], 0, $integrity );
	}

	public function test_report_fingerprint_and_mail_reason(): void {
		$clean      = $this->report( [] );
		$persistent = $this->report( [ [ 'group' => 'uploads', 'path' => 'uploads/2026/10/x.php' ] ] );
		$event      = $this->report( [ [ 'group' => 'admin_new', 'path' => 'eve (ID 7)' ] ] );

		$this->assertFalse( Report::hasContent( $clean ) );
		$this->assertTrue( Report::hasContent( $persistent ) );
		$this->assertNotSame( $clean['fingerprint'], $persistent['fingerprint'], 'Ett nytt integritetsfynd ger mejl direkt' );
		$this->assertSame( $clean['fingerprint'], $event['fingerprint'], 'Händelser försvinner nästa körning och får inte ge ett extra mejl då' );

		$sent = [ 'fingerprint' => $event['fingerprint'], 'time' => 1 ];
		$this->assertSame( 'changed', Report::mailReason( $event, $sent, 2, false ), 'Händelser mejlas alltid' );
		$this->assertNull( Report::mailReason( $persistent, [ 'fingerprint' => $persistent['fingerprint'], 'time' => 1 ], 2, false ) );
	}

	public function test_mail_shows_integrity_first(): void {
		$items = [ [ 'group' => 'admin_new', 'path' => 'eve <b>' ], [ 'group' => 'core_modified', 'path' => 'wp-includes/load.php' ] ];
		for ( $i = 0; $i < 25; $i++ ) {
			$items[] = [ 'group' => 'uploads', 'path' => "uploads/$i.php" ];
		}
		$report = $this->report( $items );
		$html   = Mailer::render( $report );

		$this->assertMatchesRegularExpression( '#Integritet och intrångstecken.*Ändrad kärnfil.*wp-includes/load\.php.*Nytt administratörskonto.*eve &lt;b&gt;.*Körbar fil i uppladdningar#s', $html, 'Kärnfiler först' );
		$this->assertStringContainsString( '… och 5 till', $html );
		$this->assertStringStartsWith( '[Klykk CVE] S: 27 integritetsfynd', Mailer::subject( $report ) );
		$this->assertStringNotContainsString( 'Integritet och', Mailer::render( $this->report( [] ) ) );
	}
}
