<?php
/**
 * Plugin Name:       Klykk CVE Sårbarhetsbevakning
 * Plugin URI:        https://github.com/Klykk-Labs/k-cve
 * Description:       Kontrollerar regelbundet WP-kärna, plugins, teman och deras beroenden mot kända sårbarheter och mejlar en rapport graderad efter CVSS, med CVE-länkar.
 * Version:           0.5.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            Robert Arbestål
 * License:           GPL-2.0-or-later
 * Text Domain:       k-cve
 * Update URI:        https://github.com/Klykk-Labs/k-cve
 */

defined( 'ABSPATH' ) || exit;

define( 'KCVE_VERSION', '0.5.0' );
define( 'KCVE_DIR', plugin_dir_path( __FILE__ ) );

require KCVE_DIR . 'src/autoload.php';

// Uppdateringar från GitHub Releases. Bara den byggda k-cve.zip används, aldrig källkods-zippen
// (den saknar vendor/ och innehåller utvecklingsfiler). "Update URI" ovan hindrar att ett annat
// plugin med samma slug på wordpress.org skulle kunna erbjudas som uppdatering.
if ( is_file( KCVE_DIR . 'vendor/autoload.php' ) ) {
	require KCVE_DIR . 'vendor/autoload.php';
	$kcve_updater = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker( 'https://github.com/Klykk-Labs/k-cve/', __FILE__, 'k-cve' );
	$kcve_api     = $kcve_updater->getVcsApi();
	// Konstanten läses via objektets klass så att koden inte låses till PUC:s versionsnamnrymd (v5p7).
	$kcve_api->enableReleaseAssets( '/k-cve\.zip$/', constant( get_class( $kcve_api ) . '::REQUIRE_RELEASE_ASSETS' ) );
}

register_activation_hook( __FILE__, [ KCve\Plugin::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ KCve\Plugin::class, 'deactivate' ] );
KCve\Plugin::boot();
