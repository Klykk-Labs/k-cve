<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Inställningssida under Verktyg → Klykk CVE.
 */
class Admin {
	private const PAGE = 'k-cve';

	public static function register(): void {
		add_action( 'admin_menu', [ self::class, 'menu' ] );
		add_action( 'admin_init', [ self::class, 'settings' ] );
		add_action( 'admin_post_kcve_run', [ self::class, 'handleRun' ] );
	}

	public static function menu(): void {
		add_management_page( 'Klykk CVE Sårbarhetsbevakning', 'Klykk CVE', 'manage_options', self::PAGE, [ self::class, 'render' ] );
	}

	public static function settings(): void {
		register_setting( 'kcve', Plugin::OPTION_SETTINGS, [ 'sanitize_callback' => [ self::class, 'sanitize' ] ] );
	}

	public static function sanitize( $input ): array {
		$input = (array) $input;
		return [
			'email'    => sanitize_email( $input['email'] ?? '' ),
			'interval' => isset( Plugin::INTERVALS[ $input['interval'] ?? '' ] ) ? $input['interval'] : 'daily',
			'ping_url' => esc_url_raw( trim( (string) ( $input['ping_url'] ?? '' ) ), [ 'http', 'https' ] ),
		];
	}

	public static function handleRun(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Otillräcklig behörighet.', 403 );
		}
		check_admin_referer( 'kcve_run' );
		$send = ! empty( $_POST['send'] );
		$args = [ 'page' => self::PAGE ];
		try {
			$report         = ( new Scanner() )->run( $send, ! $send );
			$args['kcve']   = $report['mailed'] ? 'mailed' : ( $report['mail_failed'] ? 'failed' : ( $send ? 'nothing' : 'done' ) );
			if ( $report['hub_error'] ) {
				$args['kcve']       = 'hub_failed';
				$args['kcve_error'] = rawurlencode( $report['hub_error'] );
			}
		} catch ( \Throwable $e ) {
			$args['kcve']       = 'error';
			$args['kcve_error'] = rawurlencode( $e->getMessage() );
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'tools.php' ) ) );
		exit;
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings  = Plugin::settings();
		$locked    = defined( 'K_CVE_NOTIFY_EMAIL' ) && K_CVE_NOTIFY_EMAIL;
		$ping_lock = defined( 'K_CVE_PING_URL' ) && K_CVE_PING_URL;
		$report    = get_option( Plugin::OPTION_LAST_REPORT );
		$last_sent = (array) get_option( Plugin::OPTION_LAST_SENT, [] );
		$next      = wp_next_scheduled( Plugin::CRON_HOOK );
		$status    = sanitize_key( $_GET['kcve'] ?? '' ); // phpcs:ignore WordPress.Security.NonceVerification -- endast visning.
		$messages  = [
			'done'    => [ 'success', 'Kontrollen är klar. Inget mejl skickades (förhandsvisning).' ],
			'mailed'  => [ 'success', 'Kontrollen är klar och rapporten mejlades till ' . Plugin::recipient() . '.' ],
			'nothing' => [ 'info', 'Kontrollen är klar. Inget att rapportera.' ],
			'failed'  => [ 'error', 'Kontrollen är klar, men mejlet till ' . Plugin::recipient() . ' kunde inte skickas (wp_mail misslyckades).' ],
			'error'   => [ 'error', 'Fel: ' . sanitize_text_field( wp_unslash( rawurldecode( $_GET['kcve_error'] ?? '' ) ) ) ], // phpcs:ignore
			'hub_failed' => [ 'error', 'Kontrollen är klar, men rapporten kunde inte skickas till hubben: ' . sanitize_text_field( wp_unslash( rawurldecode( $_GET['kcve_error'] ?? '' ) ) ) ], // phpcs:ignore
		];
		?>
		<div class="wrap">
			<h1>Klykk CVE Sårbarhetsbevakning</h1>
			<?php if ( isset( $messages[ $status ] ) ) : ?>
				<div class="notice notice-<?php echo esc_attr( $messages[ $status ][0] ); ?> is-dismissible"><p><?php echo esc_html( $messages[ $status ][1] ); ?></p></div>
			<?php endif; ?>

			<form method="post" action="options.php">
				<?php settings_fields( 'kcve' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="kcve-email">Skicka rapporter till</label></th>
						<td>
							<?php if ( $locked ) : ?>
								<code><?php echo esc_html( K_CVE_NOTIFY_EMAIL ); ?></code>
								<p class="description">Satt via <code>K_CVE_NOTIFY_EMAIL</code> i wp-config.php.</p>
								<input type="hidden" name="<?php echo esc_attr( Plugin::OPTION_SETTINGS ); ?>[email]" value="<?php echo esc_attr( $settings['email'] ); ?>">
							<?php else : ?>
								<input type="email" id="kcve-email" class="regular-text" name="<?php echo esc_attr( Plugin::OPTION_SETTINGS ); ?>[email]"
									value="<?php echo esc_attr( $settings['email'] ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>">
								<p class="description">Om fältet är tomt används sitens admin-e-post.</p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="kcve-interval">Intervall</label></th>
						<td>
							<select id="kcve-interval" name="<?php echo esc_attr( Plugin::OPTION_SETTINGS ); ?>[interval]">
								<?php foreach ( Plugin::INTERVALS as $value => $label ) : ?>
									<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $settings['interval'], $value ); ?>><?php echo esc_html( $label ); ?></option>
								<?php endforeach; ?>
							</select>
							<p class="description">
								Nästa körning: <?php echo $next ? esc_html( get_date_from_gmt( gmdate( 'Y-m-d H:i:s', $next ), 'Y-m-d H:i' ) ) : 'inte schemalagd'; ?>.
								WP-Cron körs bara när siten får besök. På siter med lite trafik bör en riktig cron anropa <code>wp-cron.php</code>.
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="kcve-ping">Livlina (ping-URL)</label></th>
						<td>
							<?php if ( $ping_lock ) : ?>
								<code><?php echo esc_html( K_CVE_PING_URL ); ?></code>
								<p class="description">Satt via <code>K_CVE_PING_URL</code> i wp-config.php.</p>
								<input type="hidden" name="<?php echo esc_attr( Plugin::OPTION_SETTINGS ); ?>[ping_url]" value="<?php echo esc_attr( $settings['ping_url'] ); ?>">
							<?php else : ?>
								<input type="url" id="kcve-ping" class="regular-text" name="<?php echo esc_attr( Plugin::OPTION_SETTINGS ); ?>[ping_url]"
									value="<?php echo esc_attr( $settings['ping_url'] ); ?>" placeholder="https://hc-ping.com/…">
								<p class="description">Anropas (GET) efter varje lyckad schemalagd kontroll. Med t.ex. healthchecks.io får du larm om kontrollerna slutar köras eller mejlen inte går iväg. Lämna tomt för att stänga av.</p>
							<?php endif; ?>
						</td>
					</tr>
				</table>
				<?php submit_button( 'Spara inställningar' ); ?>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="kcve_run">
				<?php wp_nonce_field( 'kcve_run' ); ?>
				<p>
					<button class="button">Kör kontroll nu (förhandsvisning)</button>
					<button class="button button-primary" name="send" value="1">Kör och mejla rapport</button>
				</p>
				<p class="description">
					En körning tar normalt 10–60 sekunder. Mejl skickas automatiskt bara när något har ändrats sedan förra mejlet.
					<?php if ( ! empty( $last_sent['time'] ) ) : ?>
						Senast uppdaterad utskicksstatus: <?php echo esc_html( wp_date( 'Y-m-d H:i', $last_sent['time'] ) ); ?>.
					<?php endif; ?>
				</p>
			</form>

			<h2>Senaste rapport</h2>
			<?php if ( is_array( $report ) ) : ?>
				<div style="background:#fff;border:1px solid #c3c4c7;padding:16px 20px;max-width:1100px">
					<?php echo Mailer::render( $report ); // phpcs:ignore WordPress.Security.EscapeOutput -- render() escapar allt externt innehåll. ?>
				</div>
			<?php else : ?>
				<p>Ingen kontroll har körts ännu.</p>
			<?php endif; ?>
		</div>
		<?php
	}
}
