<?php
/**
 * Brute Force Protection and Login Rate Limiter
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPFH_SADM_Brute_Force {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'authenticate', array( $this, 'check_lockout_before_auth' ), 20, 3 );
		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		add_action( 'wp_login', array( $this, 'clear_attempts_on_success' ), 10, 2 );
	}

	/**
	 * Check if an IP address is in the whitelist.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	public function is_whitelisted( $ip ) {
		$settings  = wpfh_sadm_get_settings();
		$raw_list  = isset( $settings['whitelist_ips'] ) ? $settings['whitelist_ips'] : '';
		$whitelist = array_filter( array_map( 'trim', explode( "\n", $raw_list ) ) );

		if ( empty( $whitelist ) ) {
			return false;
		}

		foreach ( $whitelist as $allowed ) {
			if ( $ip === $allowed ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if client IP is currently locked out before attempting authentication.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username or email.
	 * @param string                $password Plaintext password.
	 * @return WP_User|WP_Error
	 */
	public function check_lockout_before_auth( $user, $username, $password ) {
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$settings = wpfh_sadm_get_settings();
		if ( empty( $settings['brute_force_enabled'] ) ) {
			return $user;
		}

		$ip = wpfh_sadm_get_client_ip();
		if ( $this->is_whitelisted( $ip ) ) {
			return $user;
		}

		$lock_key   = 'wpfh_sadm_lock_' . md5( $ip );
		$lock_until = get_transient( $lock_key );

		if ( false !== $lock_until ) {
			$remaining = (int) $lock_until - time();
			$mins      = max( 1, (int) ceil( $remaining / 60 ) );

			$msg = sprintf(
				// translators: %d: remaining minutes of lockout
				esc_html__( 'Too many failed login attempts. Your IP has been temporarily locked out. Please try again in %d minute(s).', 'forgehub-secure-admin' ),
				$mins
			);

			return new WP_Error( 'wpfh_sadm_locked_out', $msg );
		}

		return $user;
	}

	/**
	 * Handle failed login attempt and increment counter.
	 *
	 * @param string $username Username attempted.
	 */
	public function handle_failed_login( $username ) {
		$settings = wpfh_sadm_get_settings();
		if ( empty( $settings['brute_force_enabled'] ) ) {
			return;
		}

		$ip = wpfh_sadm_get_client_ip();
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}

		$hash         = md5( $ip );
		$att_key      = 'wpfh_sadm_att_' . $hash;
		$lock_key     = 'wpfh_sadm_lock_' . $hash;
		$max_attempts = max( 1, absint( $settings['max_attempts'] ) );
		$duration     = max( 1, absint( $settings['lockout_duration'] ) ); // in minutes

		$attempts = (int) get_transient( $att_key );
		$attempts++;

		if ( $attempts >= $max_attempts ) {
			$lock_time = time() + ( $duration * 60 );
			set_transient( $lock_key, $lock_time, $duration * 60 );
			delete_transient( $att_key );

			$this->log_lockout( $ip, $username, $duration );
			do_action( 'wpfh_sadm_ip_locked_out', $ip, $username, $duration );
		} else {
			// Keep attempt count alive for the lockout duration window
			set_transient( $att_key, $attempts, $duration * 60 );
		}
	}

	/**
	 * Clear attempts counter on successful login.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 */
	public function clear_attempts_on_success( $user_login, $user ) {
		$ip = wpfh_sadm_get_client_ip();
		delete_transient( 'wpfh_sadm_att_' . md5( $ip ) );
	}

	/**
	 * Log lockout event to options (capped at 50 to maintain zero-bloat).
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Username attempted.
	 * @param int    $duration Lockout duration in minutes.
	 */
	private function log_lockout( $ip, $username, $duration ) {
		$logs = get_option( 'wpfh_sadm_lockout_logs', array() );
		if ( ! is_array( $logs ) ) {
			$logs = array();
		}

		$entry = array(
			'ip'         => sanitize_text_field( $ip ),
			'username'   => sanitize_text_field( $username ),
			'time'       => time(),
			'duration'   => absint( $duration ),
			'unlock_at'  => time() + ( $duration * 60 ),
		);

		array_unshift( $logs, $entry );
		if ( count( $logs ) > 50 ) {
			$logs = array_slice( $logs, 0, 50 );
		}

		update_option( 'wpfh_sadm_lockout_logs', $logs, false );
	}
}
