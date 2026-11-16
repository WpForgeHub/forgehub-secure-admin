<?php
/**
 * Secure Admin Guard Uninstall
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wpfh_sadm_settings' );
delete_option( 'wpfh_sadm_lockout_logs' );

global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '%wpfh_sadm_%'" );
