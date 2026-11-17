<?php
/**
 * Hide Login URL, security headers and file editor lock.
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPFH_SADM_Hide_Login {

	private static $instance = null;

	/** @var string Sanitized custom login slug (empty = feature off). */
	private $slug = '';

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Normalise a slug: lowercase letters, digits, dashes; reserved words rejected.
	 *
	 * @param string $slug Raw slug.
	 * @return string
	 */
	public static function sanitize_slug( $slug ) {
		$slug = sanitize_title( trim( (string) $slug, " \t\n\r\0\x0B/" ) );
		$bad  = array( 'wp-admin', 'wp-login', 'wp-login-php', 'wp-content', 'wp-includes', 'wp-json', 'admin', 'feed', 'xmlrpc' );
		return in_array( $slug, $bad, true ) ? '' : $slug;
	}

	private function __construct() {
		$settings = wpfh_sadm_get_settings();

		$this->slug = self::sanitize_slug( isset( $settings['hide_login_slug'] ) ? $settings['hide_login_slug'] : '' );

		if ( '' !== $this->slug ) {
			add_action( 'init', array( $this, 'route_request' ), 1 );
			add_filter( 'site_url', array( $this, 'filter_url' ), 10, 1 );
			add_filter( 'network_site_url', array( $this, 'filter_url' ), 10, 1 );
			add_filter( 'wp_redirect', array( $this, 'filter_url' ), 10, 1 );
		}

		if ( ! empty( $settings['security_headers'] ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'login_init', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
		}

		if ( ! empty( $settings['disable_file_editor'] ) ) {
			add_filter( 'map_meta_cap', array( $this, 'block_file_editor_caps' ), 10, 2 );
		}
	}

	/**
	 * Current request path relative to the site home path, without slashes.
	 *
	 * @return string
	 */
	private function request_path() {
		if ( empty( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}
		$uri  = wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$path = rawurldecode( $path );
		$home = (string) wp_parse_url( home_url(), PHP_URL_PATH );
		if ( '' !== $home && 0 === strpos( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		return trim( $path, '/' );
	}

	/**
	 * Decide what to do with the current request.
	 */
	public function route_request() {
		if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$path = strtolower( $this->request_path() );

		// Custom slug: show the real login form.
		if ( $path === $this->slug ) {
			$this->serve_login();
			return;
		}

		if ( is_user_logged_in() ) {
			return;
		}

		$is_login = ( 'wp-login.php' === $path || 'wp-login' === $path );
		$is_admin = ( 'wp-admin' === $path || 0 === strpos( $path, 'wp-admin/' ) );

		if ( $is_admin ) {
			$allowed = array( 'wp-admin/admin-ajax.php', 'wp-admin/admin-post.php', 'wp-admin/load-scripts.php', 'wp-admin/load-styles.php' );
			if ( in_array( $path, $allowed, true ) ) {
				return;
			}
		}

		if ( $is_login || $is_admin ) {
			$this->send_404();
		}
	}

	/**
	 * Render wp-login.php for the custom slug.
	 */
	private function serve_login() {
		global $pagenow, $error, $interim_login, $action, $user_login;

		$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		status_header( 200 );
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	private function send_404() {
		status_header( 404 );
		nocache_headers();
		wp_die(
			esc_html__( 'The page you requested could not be found.', 'forgehub-secure-admin' ),
			esc_html__( 'Not Found', 'forgehub-secure-admin' ),
			array( 'response' => 404 )
		);
	}

	/**
	 * Rewrite wp-login.php URLs to the custom slug.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public function filter_url( $url ) {
		if ( is_string( $url ) && false !== strpos( $url, 'wp-login.php' ) ) {
			$url = str_replace( 'wp-login.php', $this->slug . '/', $url );
		}
		return $url;
	}

	/**
	 * Send baseline browser security headers.
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	}

	/**
	 * Remove theme/plugin file editor capabilities.
	 *
	 * @param array  $caps Required caps.
	 * @param string $cap  Requested cap.
	 * @return array
	 */
	public function block_file_editor_caps( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_themes', 'edit_plugins', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}
}
