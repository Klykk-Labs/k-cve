<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Filintegritet och intrångstecken: ren logik. Filsystemet och HTTP ligger i IntegrityScan.
 *
 * Ett fynd är [ 'group' => nyckel i GROUPS, 'path' => fil eller konto ].
 */
class Integrity {
	/** I visningsordning: kärnfiler först, eftersom de aldrig ska ändras. */
	public const GROUPS = [
		'core_modified'   => 'Ändrad kärnfil',
		'core_unknown'    => 'Okänd PHP-fil i wp-admin/wp-includes',
		'core_missing'    => 'Saknad kärnfil',
		'admin_new'       => 'Nytt administratörskonto',
		'file_new'        => 'Ny PHP-fil i mu-plugins/wp-content',
		'file_changed'    => 'Ändrad PHP-fil i mu-plugins/wp-content',
		'uploads'         => 'Körbar fil i uppladdningar',
		'plugin_modified' => 'Ändrad PHP-fil i plugin',
		'plugin_unknown'  => 'Okänd PHP-fil i plugin',
		'admin_review'    => 'Första kontrollen, granska: administratörskonto',
		'file_review'     => 'Första kontrollen, granska: PHP-fil i mu-plugins/wp-content',
	];

	/**
	 * Jämförelser mot baslinjen. De rapporteras en gång och ingår därför inte i fingerprintet,
	 * annars skulle nästa körning (då de blivit baslinje) se ut som en ändring och ge ett extra mejl.
	 */
	public const EVENT_GROUPS = [ 'admin_new', 'file_new', 'file_changed', 'admin_review', 'file_review' ];

	private const EXECUTABLE = '/\.(php[0-9]?|phtml|phar)$/i';

	/**
	 * @param array    $expected { path: string[] godkända hashar }.
	 * @param callable $hash     path => hash för en fil som finns.
	 * @param string[] $present  Filer som finns, relativt samma rot.
	 * @return array{modified: string[], missing: string[], unknown: string[]}
	 */
	public static function compare( array $expected, callable $hash, array $present ): array {
		$present_set = array_flip( $present );
		$diff        = [ 'modified' => [], 'missing' => [], 'unknown' => [] ];
		foreach ( $expected as $path => $hashes ) {
			if ( ! isset( $present_set[ $path ] ) ) {
				$diff['missing'][] = (string) $path;
			} elseif ( ! in_array( call_user_func( $hash, (string) $path ), $hashes, true ) ) {
				$diff['modified'][] = (string) $path;
			}
		}
		foreach ( $present as $path ) {
			if ( ! isset( $expected[ $path ] ) ) {
				$diff['unknown'][] = $path;
			}
		}
		return $diff;
	}

	/**
	 * downloads.wordpress.org/plugin-checksums → { path: [sha256, …] } för .php-filer.
	 * Andra filer jämförs inte: plugins skriver cache och översättningar i sin egen mapp.
	 * Hashen är en sträng eller, om filen skiljer sig mellan källorna, en lista.
	 */
	public static function pluginExpected( array $response ): array {
		$expected = [];
		foreach ( $response['files'] ?? [] as $path => $hashes ) {
			if ( self::isExecutable( (string) $path ) && isset( $hashes['sha256'] ) ) {
				$expected[ (string) $path ] = array_map( 'strtolower', (array) $hashes['sha256'] );
			}
		}
		return $expected;
	}

	public static function isExecutable( string $path ): bool {
		return 1 === preg_match( self::EXECUTABLE, $path );
	}

	/**
	 * PHP-filer som plugins lägger i uploads och wp-content och som inte kan köra något: bara kommentarer
	 * ("Silence is golden"), header() med fasta strängar (WPForms 404-vakt), eller exit/die först
	 * (MC4WP:s debug-log.php, där loggraderna efter exit aldrig körs). En //- eller #-kommentar slutar vid ?>.
	 *
	 * @param bool $complete false om $contents bara är början av filen: då räcker bara exit-vakten.
	 */
	public static function isHarmless( string $contents, bool $complete = true ): bool {
		$matched = preg_match(
			'#^\s*<\?php(?:\s+|(?://|\#)(?:[^\n?]|\?(?!>))*|/\*.*?\*/'
			. '|header\(\s*(?:\$_SERVER\[\s*\'SERVER_PROTOCOL\'\s*\]\s*\.\s*)?\'[^\'\\\\]*\'\s*\)\s*;)*'
			. '(?:(?<exit>(?:exit|die)\s*(?:\(\s*\))?\s*;).*|(?:\?>\s*)?$)#s',
			$contents,
			$m
		);
		return 1 === $matched && ( $complete || ! empty( $m['exit'] ) );
	}

	/**
	 * @param array $baseline { key: hash } från förra körningen.
	 * @return array{new: string[], changed: string[]} Borttagna poster rapporteras inte.
	 */
	public static function changes( array $baseline, array $current ): array {
		$changes = [ 'new' => [], 'changed' => [] ];
		foreach ( $current as $key => $hash ) {
			if ( ! isset( $baseline[ $key ] ) ) {
				$changes['new'][] = (string) $key;
			} elseif ( $baseline[ $key ] !== $hash ) {
				$changes['changed'][] = (string) $key;
			}
		}
		return $changes;
	}

	/** Grupperat i visningsordning: { group: [path, …] }. */
	public static function grouped( array $items ): array {
		$grouped = [];
		foreach ( array_keys( self::GROUPS ) as $group ) {
			foreach ( $items as $item ) {
				if ( $item['group'] === $group ) {
					$grouped[ $group ][] = $item['path'];
				}
			}
		}
		return $grouped;
	}
}
