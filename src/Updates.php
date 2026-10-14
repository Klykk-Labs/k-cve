<?php
namespace KCve;

defined( 'ABSPATH' ) || exit;

/**
 * Tillgängliga uppdateringar enligt WordPress egna uppdateringskontroll.
 * Premium-plugins med egen uppdaterare syns också här, eftersom de hakar in i samma transient.
 */
class Updates {
	public static function collect(): array {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// Respekterar WP:s egen 12-timmarsgräns, så detta är billigt om kontrollen nyligen körts.
		// wp_version_check() anropas medvetet INTE: i cron-kontext startar den WP:s automatiska
		// bakgrundsuppdateringar (wp-includes/update.php, do_action('wp_maybe_auto_update')).
		// Kärnans uppdateringsinfo läses i stället från transienten som WP själv förnyar två gånger per dygn.
		wp_update_plugins();
		wp_update_themes();

		$updates = [];

		foreach ( (array) get_core_updates() as $offer ) {
			if ( isset( $offer->response ) && 'upgrade' === $offer->response ) {
				$updates[] = self::make( 'core:wordpress', 'WordPress', get_bloginfo( 'version' ), $offer->current );
				break;
			}
		}

		$plugins   = get_plugins();
		$transient = get_site_transient( 'update_plugins' );
		foreach ( (array) ( $transient->response ?? [] ) as $file => $info ) {
			if ( isset( $plugins[ $file ] ) ) {
				$updates[] = self::make( 'plugin:' . Inventory::pluginSlug( $file ), $plugins[ $file ]['Name'], $plugins[ $file ]['Version'], $info->new_version );
			}
		}

		$transient = get_site_transient( 'update_themes' );
		foreach ( (array) ( $transient->response ?? [] ) as $stylesheet => $info ) {
			$theme = wp_get_theme( $stylesheet );
			if ( $theme->exists() ) {
				$updates[] = self::make( 'theme:' . $stylesheet, $theme->get( 'Name' ), $theme->get( 'Version' ), $info['new_version'] );
			}
		}
		return $updates;
	}

	private static function make( string $key, string $name, string $current, string $new ): array {
		return [ 'key' => $key, 'type' => strtok( $key, ':' ), 'name' => $name, 'current' => $current, 'new' => $new ];
	}
}
