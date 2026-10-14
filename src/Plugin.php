<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Inställningar, schemaläggning och hooks.
 */
class Plugin {
	public const OPTION_SETTINGS    = 'kcve_settings';
	public const OPTION_LAST_REPORT = 'kcve_last_report';
	public const OPTION_LAST_SENT   = 'kcve_last_sent';
	public const CRON_HOOK          = 'kcve_scan';
	public const INTERVALS          = [ 'daily' => 'Dagligen', 'weekly' => 'Veckovis' ];

	public static function boot(): void {
		add_action( self::CRON_HOOK, [ self::class, 'runScheduled' ] );
		// Första sparningen går via add_option() och triggar inte update_option_-kroken.
		add_action( 'add_option_' . self::OPTION_SETTINGS, [ self::class, 'reschedule' ] );
		add_action( 'update_option_' . self::OPTION_SETTINGS, [ self::class, 'reschedule' ] );
		Admin::register();
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'k-cve', Cli::class );
		}
	}

	public static function activate(): void {
		self::reschedule();
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function reschedule(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		// Första körningen en timme efter aktivering, så att aktiveringen inte blir långsam.
		wp_schedule_event( time() + HOUR_IN_SECONDS, self::settings()['interval'], self::CRON_HOOK );
	}

	public static function runScheduled(): void {
		try {
			( new Scanner() )->run( false, false );
		} catch ( \Throwable $e ) {
			error_log( 'Klykk CVE: ' . $e->getMessage() ); // phpcs:ignore -- cron har ingen annan kanal.
		}
	}

	public static function settings(): array {
		$settings = wp_parse_args( (array) get_option( self::OPTION_SETTINGS, [] ), [ 'email' => '', 'interval' => 'daily' ] );
		if ( ! isset( self::INTERVALS[ $settings['interval'] ] ) ) {
			$settings['interval'] = 'daily';
		}
		return $settings;
	}

	/** K_CVE_NOTIFY_EMAIL i wp-config.php vinner, så att utrullning till många siter slipper klick. */
	public static function recipient(): string {
		if ( defined( 'K_CVE_NOTIFY_EMAIL' ) && K_CVE_NOTIFY_EMAIL ) {
			return (string) K_CVE_NOTIFY_EMAIL;
		}
		return self::settings()['email'] ?: (string) get_option( 'admin_email' );
	}
}
