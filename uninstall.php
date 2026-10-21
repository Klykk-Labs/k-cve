<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

wp_clear_scheduled_hook( 'kcve_scan' );
delete_option( 'kcve_settings' );
delete_option( 'kcve_last_report' );
delete_option( 'kcve_last_sent' );
delete_option( 'kcve_first_seen' );

// Cachade API-svar (transients med prefixet kcve_).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_kcve\\_%' OR option_name LIKE '\\_transient\\_timeout\\_kcve\\_%'" ); // phpcs:ignore
