<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * HTML-rapport (samma markup i mejlet och på inställningssidan) och utskick.
 * render()/subject() är rena funktioner; bara send() rör WordPress.
 */
class Mailer {
	public const GRADE_LABELS = [
		'critical' => 'Kritisk',
		'high'     => 'Hög',
		'medium'   => 'Medel',
		'low'      => 'Låg',
		'none'     => 'Ej graderad',
	];

	private const GRADE_COLORS = [
		'critical' => '#991b1b',
		'high'     => '#c2410c',
		'medium'   => '#a16207',
		'low'      => '#1d4ed8',
		'none'     => '#4b5563',
	];

	/** Servrar kan ha 100+ CVE:er; mejlet visar de allvarligaste per komponent. */
	private const MAX_ROWS = 10;

	private const TYPE_LABELS = [
		'core'        => 'WordPress',
		'plugin'      => 'Plugin',
		'theme'       => 'Tema',
		'composer'    => 'Bibliotek',
		'php'         => 'Server',
		'mysql'       => 'Server',
		'mariadb'     => 'Server',
		'apache'      => 'Server',
		'nginx'       => 'Server',
		'imagemagick' => 'Server',
		'curl'        => 'Server',
	];

	public static function send( array $report, string $to ): bool {
		return wp_mail( $to, self::subject( $report ), self::render( $report ), [ 'Content-Type: text/html; charset=UTF-8' ] );
	}

	public static function subject( array $report ): string {
		$parts = [];
		foreach ( [ 'critical', 'high' ] as $grade ) {
			if ( $report['counts'][ $grade ] > 0 ) {
				$parts[] = $report['counts'][ $grade ] . ' ' . strtolower( self::GRADE_LABELS[ $grade ] );
			}
		}
		$vulnerable = count( $report['vulnerable'] );
		$summary    = $vulnerable
			? $vulnerable . ' sårbara komponenter' . ( $parts ? ' (' . implode( ', ', $parts ) . ')' : '' )
			: 'inga kända sårbarheter';
		$updates = count( $report['updates'] );
		if ( $updates ) {
			$summary .= ', ' . $updates . ' övriga uppdateringar';
		}
		return '[k-cve] ' . $report['site']['name'] . ': ' . $summary;
	}

	public static function render( array $report ): string {
		$h    = 'font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827;font-size:14px;line-height:1.45';
		$cell = 'padding:6px 8px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top';
		$out  = '<div style="' . $h . '">';
		$out .= '<h2 style="margin:0 0 4px">Sårbarhetsrapport: ' . self::e( $report['site']['name'] ) . '</h2>';
		$out .= '<p style="margin:0 0 16px;color:#4b5563"><a href="' . self::e( $report['site']['url'] ) . '">' . self::e( $report['site']['url'] ) . '</a> · '
			. self::e( gmdate( 'Y-m-d H:i', $report['generated'] ) ) . ' UTC</p>';

		// Sammanfattning per grad.
		$out .= '<p style="margin:0 0 16px">';
		foreach ( $report['counts'] as $grade => $count ) {
			if ( $count > 0 ) {
				$out .= self::badge( $grade, $count . ' ' . self::GRADE_LABELS[ $grade ] ) . ' ';
			}
		}
		if ( ! $report['vulnerable'] ) {
			$out .= 'Inga kända sårbarheter hittades.';
		}
		$out .= '</p>';

		foreach ( $report['vulnerable'] as $component ) {
			$all_unfixed = ! in_array( false, array_column( $component['findings'], 'unfixed' ), true );
			if ( $component['fix_version'] ) {
				$fix = 'Uppdatera till <strong>' . self::e( $component['fix_version'] ) . '</strong>';
			} elseif ( $all_unfixed ) {
				$fix = '<strong style="color:#991b1b">Ingen rättad version känd</strong>';
			} else {
				// T.ex. core-fynd (saknar fixed_in) när WP:s uppdateringsinfo inte hämtats än.
				$fix = 'Uppdatera till senaste version';
			}
			$out .= '<h3 style="margin:20px 0 4px;font-size:15px">' . self::badge( $component['worst_grade'] ) . ' '
				. self::e( ( self::TYPE_LABELS[ $component['type'] ] ?? $component['type'] ) . ': ' . $component['name'] . ' ' . $component['version'] ) . '</h3>';
			$out .= '<p style="margin:0 0 6px;color:#4b5563">' . $fix
				. ( $component['notes'] ? ' · ' . self::e( implode( ' · ', $component['notes'] ) ) : '' ) . '</p>';
			$out .= '<table style="border-collapse:collapse;width:100%;margin-bottom:8px"><tr>'
				. '<th style="' . $cell . '">Grad</th><th style="' . $cell . '">CVSS</th><th style="' . $cell . '">Sårbarhet</th>'
				. '<th style="' . $cell . '">Rättad i</th><th style="' . $cell . '">CVE / källa</th></tr>';
			foreach ( array_slice( $component['findings'], 0, self::MAX_ROWS ) as $finding ) {
				$out .= '<tr>'
					. '<td style="' . $cell . '">' . self::badge( $finding['grade'] ) . '</td>'
					. '<td style="' . $cell . '">' . ( null !== $finding['score'] ? self::e( number_format( $finding['score'], 1 ) ) : '–' ) . '</td>'
					. '<td style="' . $cell . '">' . self::e( $finding['title'] )
					. ( $finding['kev'] ? ' <strong style="color:#991b1b">· Aktivt exploaterad (KEV)</strong>' : '' ) . '</td>'
					. '<td style="' . $cell . '">' . ( $finding['unfixed'] ? 'Ingen fix' : self::e( $finding['fixed_in'] ?? '?' ) ) . '</td>'
					. '<td style="' . $cell . '">' . self::links( $finding ) . '</td>'
					. '</tr>';
			}
			$out .= '</table>';
			$hidden = count( $component['findings'] ) - self::MAX_ROWS;
			if ( $hidden > 0 ) {
				$out .= '<p style="margin:0 0 8px;color:#4b5563">… och ' . $hidden . ' till med samma eller lägre grad (alla syns med <code>wp k-cve scan</code>).</p>';
			}
		}

		if ( $report['updates'] ) {
			$out .= '<h3 style="margin:24px 0 6px;font-size:15px">Övriga uppdateringar</h3>';
			$out .= '<table style="border-collapse:collapse;width:100%"><tr><th style="' . $cell . '">Typ</th><th style="' . $cell . '">Namn</th><th style="' . $cell . '">Installerad</th><th style="' . $cell . '">Ny version</th></tr>';
			foreach ( $report['updates'] as $update ) {
				$out .= '<tr><td style="' . $cell . '">' . self::e( self::TYPE_LABELS[ $update['type'] ] ?? $update['type'] ) . '</td>'
					. '<td style="' . $cell . '">' . self::e( $update['name'] ) . '</td>'
					. '<td style="' . $cell . '">' . self::e( $update['current'] ) . '</td>'
					. '<td style="' . $cell . '">' . self::e( $update['new'] ) . '</td></tr>';
			}
			$out .= '</table>';
		}

		if ( $report['unknown'] ) {
			$out .= '<p style="margin:20px 0 0;color:#4b5563"><strong>Finns inte i sårbarhetsdatabasen</strong> (t.ex. premium-plugins, kontrolleras inte): '
				. self::e( implode( ', ', $report['unknown'] ) ) . '</p>';
		}
		if ( $report['errors'] ) {
			$out .= '<p style="margin:12px 0 0;color:#991b1b"><strong>Fel under kontrollen:</strong><br>'
				. implode( '<br>', array_map( [ self::class, 'e' ], $report['errors'] ) ) . '</p>';
		}

		$out .= '<p style="margin:24px 0 0;color:#6b7280;font-size:12px">Data: WPVulnerability.net och OSV.dev. Skickat av k-cve.</p>';
		return $out . '</div>';
	}

	private static function links( array $finding ): string {
		$links = [];
		foreach ( $finding['cves'] as $cve ) {
			$links[] = '<a href="' . self::e( $cve['url'] ) . '">' . self::e( $cve['id'] ) . '</a>';
		}
		if ( ! $links && $finding['links'] ) {
			$links[] = '<a href="' . self::e( $finding['links'][0] ) . '">' . self::e( self::host( $finding['links'][0] ) ) . '</a>';
		}
		return $links ? implode( '<br>', $links ) : '–';
	}

	private static function badge( string $grade, ?string $text = null ): string {
		return '<span style="display:inline-block;padding:1px 7px;border-radius:9px;color:#fff;font-size:12px;font-weight:600;background:'
			. self::GRADE_COLORS[ $grade ] . '">' . self::e( $text ?? self::GRADE_LABELS[ $grade ] ) . '</span>';
	}

	private static function host( string $url ): string {
		return (string) preg_replace( '/^www\./', '', (string) parse_url( $url, PHP_URL_HOST ) );
	}

	private static function e( $value ): string {
		return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' );
	}
}

