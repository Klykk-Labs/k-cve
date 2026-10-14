<?php
use KCve\Inventory;
use PHPUnit\Framework\TestCase;

class InventoryTest extends TestCase {
	public function test_composer2_installed_json(): void {
		$json = json_encode( [ 'packages' => [
			[ 'name' => 'guzzlehttp/guzzle', 'version' => 'v7.4.0' ],
			[ 'name' => 'acme/dev', 'version' => 'dev-main' ],
			[ 'name' => 'acme/branch', 'version' => '2.x-dev' ],
			[ 'name' => 'psr/log', 'version' => '1.1.4' ],
		] ] );
		$this->assertSame(
			[ [ 'name' => 'guzzlehttp/guzzle', 'version' => '7.4.0' ], [ 'name' => 'psr/log', 'version' => '1.1.4' ] ],
			Inventory::parseComposerInstalled( $json )
		);
	}

	public function test_composer1_installed_json_and_garbage(): void {
		$this->assertSame( [ [ 'name' => 'a/b', 'version' => '1.0.0' ] ], Inventory::parseComposerInstalled( '[{"name":"a/b","version":"1.0.0"}]' ) );
		$this->assertSame( [], Inventory::parseComposerInstalled( 'not json' ) );
	}

	public function test_server_software(): void {
		$this->assertSame( [ 'apache', '2.4.58' ], Inventory::parseServerSoftware( 'Apache/2.4.58 (Unix) OpenSSL/3.0' ) );
		$this->assertSame( [ 'nginx', '1.24.0' ], Inventory::parseServerSoftware( 'nginx/1.24.0' ) );
		$this->assertNull( Inventory::parseServerSoftware( 'Apache' ) );
		$this->assertNull( Inventory::parseServerSoftware( 'Microsoft-IIS/10.0' ) );
	}

	public function test_db_server_info(): void {
		$this->assertSame( [ 'mariadb', '10.6.12' ], Inventory::parseDbServerInfo( '5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1', '5.5.5' ) );
		$this->assertSame( [ 'mariadb', '10.11.6' ], Inventory::parseDbServerInfo( '10.11.6-MariaDB', '10.11.6' ) );
		$this->assertSame( [ 'mysql', '8.0.36' ], Inventory::parseDbServerInfo( '8.0.36-0ubuntu0.22.04.1', '8.0.36' ) );
	}

	public function test_imagemagick_and_plugin_slug(): void {
		$this->assertSame( '6.9.11-60', Inventory::parseImageMagick( 'ImageMagick 6.9.11-60 Q16 x86_64 2021-01-25 https://imagemagick.org' ) );
		$this->assertSame( 'akismet', Inventory::pluginSlug( 'akismet/akismet.php' ) );
		$this->assertSame( 'hello', Inventory::pluginSlug( 'hello.php' ) );
	}
}
