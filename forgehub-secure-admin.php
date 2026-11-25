<?php
/**
 * Plugin Name:       ForgeHub Secure Admin Guard
 * Plugin URI:        https://wpforgehub.com/plugins/forgehub-secure-admin/
 * Description:       Lightweight zero-bloat login protection with brute force rate limiting, email OTP two-factor authentication, and WordPress hardening.
 * Version:           1.3.1
 * Author:            WPForgeHub
 * Author URI:        https://wpforgehub.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       forgehub-secure-admin
 * Domain Path:       /languages
 * Requires at least: 6.0
 * Requires PHP:      7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPFH_SADM_VERSION', '1.3.1' );
define( 'WPFH_SADM_FILE', __FILE__ );
define( 'WPFH_SADM_PATH', plugin_dir_path( __FILE__ ) );
define( 'WPFH_SADM_URL', plugin_dir_url( __FILE__ ) );

/**
 * Freemius SDK helper wrapper
 */
if ( ! function_exists( 'wpfh_sadm_fs' ) ) {
	function wpfh_sadm_fs() {
		global $wpfh_sadm_fs;

		if ( ! isset( $wpfh_sadm_fs ) ) {
			$fs_path = WPFH_SADM_PATH . 'freemius/start.php';
			if ( file_exists( $fs_path ) ) {
				require_once $fs_path;
				$wpfh_sadm_fs = fs_dynamic_init( array(
					'id'             => '45179',
					'slug'           => 'forgehub-secure-admin',
					'type'           => 'plugin',
					'public_key'     => 'pk_db2e6d7cc198d35c08e3d17a51779',
					'is_premium'     => false,
					'has_addons'     => false,
					'has_paid_plans' => true,
					'menu'           => array(
						'slug'       => 'forgehub-secure-admin',
						'first-path' => 'options-general.php?page=forgehub-secure-admin',
						'parent'     => array(
							'slug' => 'options-general.php',
						),
					),
				) );
				// Freemius forbids uninstall.php in premium builds; use its after_uninstall hook there.
				$wpfh_sadm_fs->add_action( 'after_uninstall', 'wpfh_sadm_uninstall_cleanup' );
			} else {
				// Clean fallback for standard WordPress distribution
				$wpfh_sadm_fs = new class {
					public function can_use_premium_code() {
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
						return (bool) apply_filters( 'fs_can_use_premium_code__forgehub-secure-admin', false );
					}
					public function is__premium_only() { return false; }
					public function is_plan( $plan ) {
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
						return (bool) apply_filters( 'fs_is_plan__forgehub-secure-admin', false, $plan );
					}
					public function get_upgrade_url() {
						return 'https://wpforgehub.com/product/secure-admin/#pricing';
					}
				};
			}
		}

		return $wpfh_sadm_fs;
	}

	wpfh_sadm_fs();
}

/**
 * Removes plugin options on uninstall (Freemius premium build; free build uses uninstall.php).
 */
function wpfh_sadm_uninstall_cleanup() {
	delete_option( 'wpfh_sadm_settings' );
	delete_option( 'wpfh_sadm_lockout_logs' );
	delete_option( 'wpfh_sadm_activity_logs' );
}

/**
 * Retrieve plugin settings with sensible defaults.
 *
 * @return array
 */
function wpfh_sadm_get_settings() {
	$defaults = array(
		// Brute Force
		'brute_force_enabled'  => 1,
		'max_attempts'         => 5,
		'lockout_duration'     => 15, // in minutes
		'whitelist_ips'        => '',
		'trust_proxy_headers'  => 0,
		// 2FA (opt-in so fresh installs never lock out sites without working wp_mail)
		'email_2fa_enabled'    => 0,
		// Hardening
		'generic_login_errors' => 1,
		'disable_xmlrpc'       => 1,
		'block_author_query'   => 1,
		'hide_wp_version'      => 1,
		'hide_login_slug'      => '',
		'security_headers'     => 0,
		'disable_file_editor'  => 0,
		'honeypot_enabled'     => 1,
		'math_captcha_enabled' => 1,
		'login_badge_enabled'  => 0,
		'lost_password_limit'  => 1,
		// Pro defaults
		'pro_2fa_roles'        => array( 'administrator' ),
		'pro_trusted_device'   => 1,
		'pro_idle_logout'      => 0,
		'pro_idle_timeout'     => 15, // minutes
		'pro_login_alert'      => 0,
		'pro_block_bad_bots'   => 0,
		'pro_bad_bot_list'     => '',
	);

	$saved = get_option( 'wpfh_sadm_settings', array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}

	return wp_parse_args( $saved, $defaults );
}

/**
 * Safely retrieve the client IP address.
 *
 * @return string
 */
function wpfh_sadm_get_client_ip() {
	$settings    = wpfh_sadm_get_settings();
	$trust_proxy = (bool) apply_filters( 'wpfh_sadm_trust_proxy_headers', ! empty( $settings['trust_proxy_headers'] ) );
	$ip          = '';

	if ( $trust_proxy ) {
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			$ip    = trim( $parts[0] );
		} elseif ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
		}
	}

	if ( '' === $ip && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
		$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
	}

	$validated = filter_var( $ip, FILTER_VALIDATE_IP );
	return $validated ? $validated : '127.0.0.1';
}

/**
 * Main Plugin Class
 */
final class WPFH_Secure_Admin {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->load_dependencies();
		$this->init_hooks();
	}

	private function load_dependencies() {
		require_once WPFH_SADM_PATH . 'includes/class-wpfh-sadm-brute-force.php';
		require_once WPFH_SADM_PATH . 'includes/class-wpfh-sadm-email-2fa.php';
		require_once WPFH_SADM_PATH . 'includes/class-wpfh-sadm-hardening.php';
		require_once WPFH_SADM_PATH . 'includes/class-wpfh-sadm-hide-login.php';
		require_once WPFH_SADM_PATH . 'includes/class-wpfh-sadm-admin.php';

		// Load Pro features if available
		$pro_file = WPFH_SADM_PATH . 'includes/pro/class-wpfh-sadm-pro.php';
		if ( file_exists( $pro_file ) && wpfh_sadm_fs()->can_use_premium_code() ) {
			require_once $pro_file;
		}
	}

	private function init_hooks() {
		WPFH_SADM_Brute_Force::get_instance();
		WPFH_SADM_Email_2FA::get_instance();
		WPFH_SADM_Hardening::get_instance();
		WPFH_SADM_Hide_Login::get_instance();
		WPFH_SADM_Admin::get_instance();

		$pro_class = 'WPFH_SADM_Pro';
		if ( class_exists( $pro_class ) && wpfh_sadm_fs()->can_use_premium_code() ) {
			$pro_class::get_instance();
		}
	}
}

add_action( 'plugins_loaded', array( 'WPFH_Secure_Admin', 'get_instance' ) );
