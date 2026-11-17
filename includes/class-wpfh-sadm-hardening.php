<?php
/**
 * WordPress Hardening & Information Leak Defense
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPFH_SADM_Hardening {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$settings = wpfh_sadm_get_settings();

		// 1. Generic login error masking (prevents username enumeration)
		if ( ! empty( $settings['generic_login_errors'] ) ) {
			add_filter( 'login_errors', array( $this, 'mask_login_errors' ) );
		}

		// 2. Disable XML-RPC attacks
		if ( ! empty( $settings['disable_xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array' );
			add_action( 'init', array( $this, 'block_xmlrpc_requests' ) );
		}

		// 3. Block /?author=N query enumeration
		if ( ! empty( $settings['block_author_query'] ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_enumeration' ) );
		}

		// 4. Hide WordPress Version generator
		if ( ! empty( $settings['hide_wp_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		// 5. REST API user enumeration protection (Unauthenticated requests)
		add_filter( 'rest_authentication_errors', array( $this, 'protect_rest_user_endpoint' ) );

		// 6. Zero-JS Honeypot protection
		if ( ! empty( $settings['honeypot_enabled'] ) ) {
			add_action( 'login_form', array( $this, 'render_honeypot_field' ) );
			add_filter( 'authenticate', array( $this, 'validate_honeypot_on_authenticate' ), 5, 3 );
		}

		// 7. Lost password rate limiter against bot spam
		if ( ! empty( $settings['lost_password_limit'] ) ) {
			add_action( 'lostpassword_post', array( $this, 'rate_limit_lost_password' ) );
		}
	}

	/**
	 * Mask login errors with a uniform message to stop username harvesting.
	 *
	 * @param string $error Original error.
	 * @return string
	 */
	public function mask_login_errors( $error ) {
		// Don't mask lockout or 2FA messages
		if ( strpos( $error, 'wpfh_sadm_locked_out' ) !== false || strpos( $error, 'verification code' ) !== false ) {
			return $error;
		}

		return esc_html__( 'Incorrect username or password. Please try again.', 'forgehub-secure-admin' );
	}

	/**
	 * Block direct HTTP requests to xmlrpc.php.
	 */
	public function block_xmlrpc_requests() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			wp_die(
				esc_html__( 'XML-RPC services are disabled on this site for security reasons.', 'forgehub-secure-admin' ),
				esc_html__( 'Forbidden', 'forgehub-secure-admin' ),
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Intercept /?author=1 scans and author archives for non-logged-in users.
	 */
	public function block_author_enumeration() {
		if ( is_admin() ) {
			return;
		}

		// Check query parameter ?author=N
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['author'] ) && ! empty( $_GET['author'] ) ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}

		// Check author archive requests
		if ( is_author() && ! is_user_logged_in() ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Block unauthenticated access to /wp-json/wp/v2/users to protect usernames.
	 *
	 * @param WP_Error|null|bool $result REST auth result.
	 * @return WP_Error|null|bool
	 */
	public function protect_rest_user_endpoint( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}

		if ( ! is_user_logged_in() && isset( $_SERVER['REQUEST_URI'] ) ) {
			$uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
			if ( strpos( $uri, '/wp/v2/users' ) !== false ) {
				return new WP_Error(
					'rest_cannot_view',
					esc_html__( 'Only authenticated users can list site users.', 'forgehub-secure-admin' ),
					array( 'status' => rest_authorization_required_code() )
				);
			}
		}

		return $result;
	}

	/**
	 * Render zero-JS honeypot field in login form.
	 */
	public function render_honeypot_field() {
		?>
		<p style="display:none !important; position:absolute; left:-9999px;" aria-hidden="true">
			<label for="wpfh_sadm_hp"><?php esc_html_e( 'Leave this field empty', 'forgehub-secure-admin' ); ?></label>
			<input type="text" name="wpfh_sadm_hp" id="wpfh_sadm_hp" value="" tabindex="-1" autocomplete="off" />
		</p>
		<?php
	}

	/**
	 * Inspect honeypot during authentication. If filled, reject login immediately without processing password.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username or email.
	 * @param string                $password Plaintext password.
	 * @return WP_User|WP_Error
	 */
	public function validate_honeypot_on_authenticate( $user, $username, $password ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$honeypot = isset( $_POST['wpfh_sadm_hp'] ) ? sanitize_text_field( wp_unslash( $_POST['wpfh_sadm_hp'] ) ) : '';
		if ( '' !== $honeypot ) {
			return new WP_Error(
				'wpfh_sadm_honeypot_triggered',
				esc_html__( 'Spam or automated bot submission detected.', 'forgehub-secure-admin' )
			);
		}

		return $user;
	}

	/**
	 * Rate limit lost password requests on lostpassword_post to prevent password reset bot spam.
	 *
	 * @param WP_Error|null $errors Error object.
	 */
	public function rate_limit_lost_password( $errors = null ) {
		$ip         = wpfh_sadm_get_client_ip();
		$trans_key  = 'wpfh_sadm_lp_' . md5( $ip );
		$attempts   = (int) get_transient( $trans_key );
		$max_resets = 3;
		$window_sec = 900; // 15 minutes

		if ( $attempts >= $max_resets ) {
			$msg = esc_html__( 'Too many password reset requests from this IP address. Please wait 15 minutes before trying again.', 'forgehub-secure-admin' );
			if ( is_wp_error( $errors ) ) {
				$errors->add( 'wpfh_sadm_lost_password_throttled', $msg );
			} else {
				wp_die(
					esc_html( $msg ),
					esc_html__( 'Too Many Requests', 'forgehub-secure-admin' ),
					array( 'response' => 429 )
				);
			}
			return;
		}

		set_transient( $trans_key, $attempts + 1, $window_sec );
	}
}
