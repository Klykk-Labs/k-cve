<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Samlar integritetsfynd från filsystemet och WordPress. Jämförelserna ligger i Integrity.
 */
class IntegrityScan {
	/** Övre gräns för poster som gås igenom i uploads, som kan vara mycket stor. */
	private const MAX_UPLOAD_ENTRIES = 50000;

	/**
	 * @param callable   $plugin_checksums (slug, version) => { path: [sha256] } eller null om pluginet saknas på wordpress.org.
	 * @param array|null $baseline         Förra körningens { files, admins }, eller null första gången.
	 * @return array{items: array, baseline: array, errors: string[]}
	 */
	public static function run( callable $plugin_checksums, ?array $baseline ): array {
		$items  = [];
		$errors = [];

		self::core( $items, $errors );
		self::plugins( $plugin_checksums, $items, $errors );
		self::uploads( $items, $errors );

		$current = [ 'files' => self::watchedFiles(), 'admins' => self::admins() ];
		if ( null === $baseline ) {
			// En redan infekterad site ska inte tyst bli normalläget: visa allt en gång.
			foreach ( array_keys( $current['files'] ) as $path ) {
				$items[] = [ 'group' => 'file_review', 'path' => $path ];
			}
			foreach ( $current['admins'] as $id => $login ) {
				$items[] = [ 'group' => 'admin_review', 'path' => self::adminLabel( $id, $login ) ];
			}
		} else {
			$files = Integrity::changes( (array) ( $baseline['files'] ?? [] ), $current['files'] );
			foreach ( $files['new'] as $path ) {
				$items[] = [ 'group' => 'file_new', 'path' => $path ];
			}
			foreach ( $files['changed'] as $path ) {
				$items[] = [ 'group' => 'file_changed', 'path' => $path ];
			}
			foreach ( Integrity::changes( (array) ( $baseline['admins'] ?? [] ), $current['admins'] )['new'] as $id ) {
				$items[] = [ 'group' => 'admin_new', 'path' => self::adminLabel( (int) $id, $current['admins'][ $id ] ) ];
			}
		}
		return [ 'items' => $items, 'baseline' => $current, 'errors' => $errors ];
	}

	/** Kärnfiler mot WordPress egna checksummor (md5). wp-content ingår inte i jämförelsen. */
	private static function core( array &$items, array &$errors ): void {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$version   = get_bloginfo( 'version' );
		$checksums = get_core_checksums( $version, get_locale() );
		if ( ! is_array( $checksums ) && 'en_US' !== get_locale() ) {
			$checksums = get_core_checksums( $version, 'en_US' );
		}
		if ( ! is_array( $checksums ) ) {
			$errors[] = 'Kärnfilernas checksummor kunde inte hämtas från WordPress.org.';
			return;
		}

		$expected = [];
		$present  = [];
		foreach ( $checksums as $path => $md5 ) {
			if ( 0 === strpos( $path, 'wp-content/' ) ) {
				continue;
			}
			$expected[ $path ] = [ $md5 ];
			if ( is_file( ABSPATH . $path ) ) {
				$present[] = $path;
			}
		}
		// Okända filer letas bara i wp-admin och wp-includes. I webbroten ligger ofta wp-config.php och annat legitimt.
		foreach ( [ 'wp-admin', 'wp-includes' ] as $dir ) {
			foreach ( self::phpFiles( ABSPATH . $dir, $dir . '/' ) as $path ) {
				if ( ! isset( $expected[ $path ] ) ) {
					$present[] = $path;
				}
			}
		}

		$diff = Integrity::compare(
			$expected,
			static function ( $path ) {
				return md5_file( ABSPATH . $path );
			},
			$present
		);
		foreach ( $diff['modified'] as $path ) {
			$items[] = [ 'group' => 'core_modified', 'path' => $path ];
		}
		foreach ( $diff['unknown'] as $path ) {
			$items[] = [ 'group' => 'core_unknown', 'path' => $path ];
		}
		// readme.html och license.txt tas ofta bort som "härdning"; bara saknad PHP är intressant.
		foreach ( array_filter( $diff['missing'], [ Integrity::class, 'isExecutable' ] ) as $path ) {
			$items[] = [ 'group' => 'core_missing', 'path' => $path ];
		}
	}

	/** .php-filer i plugins från wordpress.org. Premium-plugins (404) hoppas över. */
	private static function plugins( callable $plugin_checksums, array &$items, array &$errors ): void {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$self = basename( untrailingslashit( KCVE_DIR ) );
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			// Enfilsplugins (hello.php) har ingen egen mapp. Klykk CVE finns inte på wordpress.org (ett annat plugin kan ha sluggen).
			if ( '.' === $slug || $self === $slug ) {
				continue;
			}
			try {
				$expected = call_user_func( $plugin_checksums, $slug, (string) $data['Version'] );
			} catch ( \Throwable $e ) {
				$errors[] = $data['Name'] . ': checksummor kunde inte hämtas: ' . $e->getMessage();
				continue;
			}
			if ( null === $expected ) {
				continue;
			}
			$root = WP_PLUGIN_DIR . '/' . $slug . '/';
			$diff = Integrity::compare(
				$expected,
				static function ( $path ) use ( $root ) {
					return hash_file( 'sha256', $root . $path );
				},
				self::phpFiles( $root, '' )
			);
			foreach ( $diff['modified'] as $path ) {
				$items[] = [ 'group' => 'plugin_modified', 'path' => $slug . '/' . $path ];
			}
			foreach ( $diff['unknown'] as $path ) {
				$items[] = [ 'group' => 'plugin_unknown', 'path' => $slug . '/' . $path ];
			}
		}
	}

	/** Körbara filer i uploads: så skrivs webshells in via sårbara uppladdningsformulär. Bara filnamn, inget innehåll. */
	private static function uploads( array &$items, array &$errors ): void {
		$base = wp_upload_dir( null, false )['basedir'] ?? '';
		if ( ! $base || ! is_dir( $base ) ) {
			return;
		}
		$entries = 0;
		foreach ( self::iterate( $base ) as $file ) {
			if ( ++$entries > self::MAX_UPLOAD_ENTRIES ) {
				$errors[] = 'Uppladdningsmappen: kontrollen avbröts efter ' . number_format( self::MAX_UPLOAD_ENTRIES, 0, ',', ' ' ) . ' filer.';
				return;
			}
			if ( ! $file->isFile() || ! Integrity::isExecutable( $file->getFilename() ) ) {
				continue;
			}
			if ( $file->getSize() < 1024 && Integrity::isStub( (string) file_get_contents( $file->getPathname() ) ) ) {
				continue;
			}
			$items[] = [ 'group' => 'uploads', 'path' => 'uploads/' . self::relative( $file->getPathname(), $base ) ];
		}
	}

	/** { path: md5 } för PHP-filer i mu-plugins (alla nivåer) och direkt i wp-content (drop-ins). */
	private static function watchedFiles(): array {
		$files = [];
		if ( is_dir( WPMU_PLUGIN_DIR ) ) {
			foreach ( self::phpFiles( WPMU_PLUGIN_DIR, 'mu-plugins/' ) as $path ) {
				$files[ $path ] = md5_file( WPMU_PLUGIN_DIR . '/' . substr( $path, strlen( 'mu-plugins/' ) ) );
			}
		}
		foreach ( glob( WP_CONTENT_DIR . '/*.php' ) ?: [] as $file ) {
			$files[ 'wp-content/' . basename( $file ) ] = md5_file( $file );
		}
		ksort( $files );
		return $files;
	}

	/** { ID: login } för administratörer. */
	private static function admins(): array {
		$admins = [];
		foreach ( get_users( [ 'role' => 'administrator', 'fields' => [ 'ID', 'user_login' ] ] ) as $user ) {
			$admins[ (int) $user->ID ] = (string) $user->user_login;
		}
		return $admins;
	}

	private static function adminLabel( int $id, string $login ): string {
		return $login . ' (ID ' . $id . ')';
	}

	/** Relativa sökvägar med prefix till alla PHP-filer under $dir. */
	private static function phpFiles( string $dir, string $prefix ): array {
		$paths = [];
		if ( ! is_dir( $dir ) ) {
			return $paths;
		}
		foreach ( self::iterate( $dir ) as $file ) {
			if ( $file->isFile() && Integrity::isExecutable( $file->getFilename() ) ) {
				$paths[] = $prefix . self::relative( $file->getPathname(), $dir );
			}
		}
		return $paths;
	}

	/** Rekursivt, följer inte symlänkar och hoppar över oläsbara mappar. */
	private static function iterate( string $dir ): \RecursiveIteratorIterator {
		return new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);
	}

	private static function relative( string $path, string $root ): string {
		return ltrim( str_replace( '\\', '/', substr( $path, strlen( rtrim( $root, '/\\' ) ) ) ), '/' );
	}
}
