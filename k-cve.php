<?php
/**
 * Plugin Name:       k-cve sårbarhetsbevakning
 * Description:       Kontrollerar regelbundet WP-kärna, plugins, teman och deras beroenden mot kända sårbarheter och mejlar en rapport graderad efter CVSS, med CVE-länkar.
 * Version:           0.1.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            Robert Arbestål
 * License:           GPL-2.0-or-later
 * Text Domain:       k-cve
 */

defined( 'ABSPATH' ) || exit;

define( 'KCVE_VERSION', '0.1.0' );
define( 'KCVE_DIR', plugin_dir_path( __FILE__ ) );

require KCVE_DIR . 'src/autoload.php';

register_activation_hook( __FILE__, [ KCve\Plugin::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ KCve\Plugin::class, 'deactivate' ] );
KCve\Plugin::boot();
