<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Samlar allt som ska kontrolleras: core, plugins, teman, server-mjukvara och
 * Composer-paket som plugins/teman bäddar in under vendor/.
 *
 * Varje komponent: key, type, slug, name, version, notes[].
 */
class Inventory {
	public static function collect(): array {
		$components = [];
		$components[] = self::make( 'core', 'wordpress', 'WordPress', get_bloginfo( 'version' ) );

		foreach ( self::plugins() as $component ) {
			$components[] = $component;
		}
		foreach ( self::themes() as $component ) {
			$components[] = $component;
		}
		foreach ( self::server() as $component ) {
			$components[] = $component;
		}
		foreach ( self::composer() as $component ) {
			$components[] = $component;
		}
		return $components;
	}

	private static function plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins     = get_plugins();
		$required_by = [];
		foreach ( $plugins as $file => $data ) {
			// "Requires Plugins"-headern (WP 6.5+) är en kommaseparerad lista med slugs.
			foreach ( array_filter( array_map( 'trim', explode( ',', $data['RequiresPlugins'] ?? '' ) ) ) as $dependency ) {
				$required_by[ $dependency ][] = $data['Name'];
			}
		}

		$components = [];
		foreach ( $plugins as $file => $data ) {
			$slug  = self::pluginSlug( $file );
			$notes = [ is_plugin_active( $file ) ? 'aktivt' : 'inaktivt' ];
			if ( isset( $required_by[ $slug ] ) ) {
				$notes[] = 'krävs av ' . implode( ', ', $required_by[ $slug ] );
			}
			// Nyckeln måste bli "plugin:<slug>", samma som i Updates, annars kopplas inte uppdateringen till fynden.
			$components[] = self::make( 'plugin', $slug, $data['Name'], $data['Version'], $notes );
		}
		return $components;
	}

	private static function themes(): array {
		$active     = get_stylesheet();
		$themes     = wp_get_themes();
		$components = [];
		foreach ( $themes as $stylesheet => $theme ) {
			$notes = [];
			if ( $stylesheet === $active ) {
				$notes[] = 'aktivt tema';
			}
			$children = [];
			foreach ( $themes as $other ) {
				if ( $other->get_template() === $stylesheet && $other->get_stylesheet() !== $stylesheet ) {
					$children[] = $other->get( 'Name' );
				}
			}
			if ( $children ) {
				$notes[] = 'förälder till ' . implode( ', ', $children );
			}
			$components[] = self::make( 'theme', $stylesheet, $theme->get( 'Name' ), $theme->get( 'Version' ), $notes );
		}
		return $components;
	}

	private static function server(): array {
		global $wpdb;
		$components = [];

		$php = self::extractVersion( PHP_VERSION );
		if ( $php ) {
			$components[] = self::make( 'php', 'php', 'PHP', $php );
		}

		// SQLite-drop-in:en utger sig för att vara MySQL 8.0.x — det skulle ge falska MySQL-fynd.
		$sqlite = defined( 'DB_ENGINE' ) && 'sqlite' === DB_ENGINE;
		$db     = $sqlite ? null : self::parseDbServerInfo( (string) $wpdb->db_server_info(), (string) $wpdb->db_version() );
		if ( $db ) {
			$components[] = self::make( $db[0], $db[0], 'mariadb' === $db[0] ? 'MariaDB' : 'MySQL', $db[1] );
		}

		$web = self::parseServerSoftware( (string) ( $_SERVER['SERVER_SOFTWARE'] ?? '' ) );
		if ( $web ) {
			$components[] = self::make( $web[0], $web[0], 'apache' === $web[0] ? 'Apache' : 'nginx', $web[1] );
		}

		if ( class_exists( '\Imagick' ) ) {
			$imagick = self::parseImageMagick( (string) ( \Imagick::getVersion()['versionString'] ?? '' ) );
			if ( $imagick ) {
				$components[] = self::make( 'imagemagick', 'imagemagick', 'ImageMagick', $imagick );
			}
		}

		if ( function_exists( 'curl_version' ) ) {
			$curl = self::extractVersion( (string) ( curl_version()['version'] ?? '' ) );
			if ( $curl ) {
				$components[] = self::make( 'curl', 'curl', 'cURL', $curl );
			}
		}
		return $components;
	}

	private static function composer(): array {
		$hosts = [];
		foreach ( glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR ) ?: [] as $dir ) {
			$hosts[ $dir ] = 'plugin ' . basename( $dir );
		}
		foreach ( glob( get_theme_root() . '/*', GLOB_ONLYDIR ) ?: [] as $dir ) {
			$hosts[ $dir ] = 'tema ' . basename( $dir );
		}
		// Vårt eget vendor/ innehåller bara dev-beroenden (phpunit) vid lokal utveckling.
		unset( $hosts[ untrailingslashit( KCVE_DIR ) ] );

		$components = [];
		foreach ( $hosts as $dir => $label ) {
			$files = array_merge(
				glob( $dir . '/vendor/composer/installed.json' ) ?: [],
				glob( $dir . '/*/vendor/composer/installed.json' ) ?: []
			);
			foreach ( $files as $file ) {
				foreach ( self::parseComposerInstalled( (string) file_get_contents( $file ) ) as $package ) {
					$components[ $label . '|' . $package['name'] ] = self::make(
						'composer',
						$package['name'],
						$package['name'],
						$package['version'],
						[ 'inbäddat i ' . $label ],
						$label . '/' . $package['name']
					);
				}
			}
		}
		return array_values( $components );
	}

	private static function make( string $type, string $slug, string $name, string $version, array $notes = [], ?string $id = null ): array {
		return [
			'key'     => $type . ':' . ( $id ?? $slug ),
			'type'    => $type,
			'slug'    => $slug,
			'name'    => $name,
			'version' => $version,
			'notes'   => $notes,
		];
	}

	public static function pluginSlug( string $file ): string {
		return false !== strpos( $file, '/' ) ? dirname( $file ) : basename( $file, '.php' );
	}

	/** Composer 2 ({"packages": [...]}) och Composer 1 ([...]). Dev-versioner hoppas över. */
	public static function parseComposerInstalled( string $json ): array {
		$data     = json_decode( $json, true );
		$packages = isset( $data['packages'] ) ? $data['packages'] : $data;
		$result   = [];
		foreach ( is_array( $packages ) ? $packages : [] as $package ) {
			$name    = $package['name'] ?? '';
			$version = ltrim( (string) ( $package['version'] ?? '' ), 'vV' );
			if ( '' === $name || '' === $version || 0 === strpos( $version, 'dev-' ) || '-dev' === substr( $version, -4 ) ) {
				continue;
			}
			$result[] = [ 'name' => $name, 'version' => $version ];
		}
		return $result;
	}

	/** "Apache/2.4.58 (Unix)" → ['apache', '2.4.58']. Ofta dold ("Apache"), då null. */
	public static function parseServerSoftware( string $software ): ?array {
		if ( preg_match( '#^(apache|nginx)/(\d+\.\d+(?:\.\d+)?)#i', $software, $m ) ) {
			return [ strtolower( $m[1] ), $m[2] ];
		}
		return null;
	}

	/** MariaDB rapporterar t.ex. "5.5.5-10.6.12-MariaDB" — den riktiga versionen står före "-MariaDB". */
	public static function parseDbServerInfo( string $server_info, string $db_version ): ?array {
		if ( stripos( $server_info, 'mariadb' ) !== false ) {
			return preg_match( '/(\d+\.\d+\.\d+)-MariaDB/i', $server_info, $m ) ? [ 'mariadb', $m[1] ] : null;
		}
		$version = self::extractVersion( $server_info ) ?? self::extractVersion( $db_version );
		return $version ? [ 'mysql', $version ] : null;
	}

	public static function parseImageMagick( string $version_string ): ?string {
		return preg_match( '/ImageMagick (\d+\.\d+\.\d+(?:-\d+)?)/', $version_string, $m ) ? $m[1] : null;
	}

	public static function extractVersion( string $value ): ?string {
		return preg_match( '/\d+\.\d+(?:\.\d+)?/', $value, $m ) ? $m[0] : null;
	}
}
