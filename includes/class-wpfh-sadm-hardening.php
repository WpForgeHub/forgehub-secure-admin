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

	/**
	 * Whether the current request's login error should bypass generic error masking.
	 *
	 * @var bool
	 */
	private static $preserve_login_error = false;

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
			add_filter( 'authenticate', array( $this, 'inspect_auth_error' ), 999, 3 );
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
			add_filter( 'authenticate', array( $this, 'validate_honeypot_on_authenticate' ), 30, 3 );
		}

		// 7. Lightweight zero-JS Math CAPTCHA on wp-login.php
		if ( ! empty( $settings['math_captcha_enabled'] ) ) {
			add_action( 'login_form', array( $this, 'render_math_captcha_field' ) );
			add_filter( 'authenticate', array( $this, 'validate_math_captcha_on_authenticate' ), 40, 3 );
		}

		// 8. Opt-in login protection badge (disabled by default)
		if ( ! empty( $settings['login_badge_enabled'] ) ) {
			add_action( 'login_footer', array( $this, 'render_login_badge' ) );
		}

		// 9. Lost password rate limiter against bot spam
		if ( ! empty( $settings['lost_password_limit'] ) ) {
			add_action( 'lostpassword_post', array( $this, 'rate_limit_lost_password' ) );
		}
	}

	/**
	 * Inspect the final authentication result so lockout, CAPTCHA, honeypot, and 2FA errors are not masked.
	 *
	 * @param WP_User|WP_Error|null $user     Authentication result.
	 * @param string                $username Username or email.
	 * @param string                $password Plaintext password.
	 * @return WP_User|WP_Error|null
	 */
	public function inspect_auth_error( $user, $username, $password ) {
		if ( is_wp_error( $user ) ) {
			$preserved_codes = array(
				'wpfh_sadm_locked_out',
				'wpfh_sadm_captcha_failed',
				'wpfh_sadm_honeypot_triggered',
				'wpfh_sadm_2fa_invalid',
				'wpfh_sadm_2fa_expired',
			);

			foreach ( $user->get_error_codes() as $code ) {
				if ( in_array( $code, $preserved_codes, true ) ) {
					self::$preserve_login_error = true;
					break;
				}
			}
		}

		return $user;
	}

	/**
	 * Mask login errors with a uniform message to stop username harvesting.
	 *
	 * @param string $error Original error.
	 * @return string
	 */
	public function mask_login_errors( $error ) {
		// Preserve plugin-generated lockout, CAPTCHA, honeypot, and 2FA messages.
		if ( self::$preserve_login_error || strpos( $error, 'verification code' ) !== false ) {
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
	 * Render a zero-JS, replay-proof Math CAPTCHA field on wp-login.php.
	 */
	public function render_math_captcha_field() {
		$num1   = wp_rand( 1, 9 );
		$num2   = wp_rand( 1, 9 );
		$answer = (string) ( $num1 + $num2 );
		$token  = strtolower( wp_generate_password( 24, false, false ) );

		set_transient( 'wpfh_sadm_cap_' . $token, $answer, 15 * MINUTE_IN_SECONDS );
		?>
		<p class="wpfh-sadm-captcha-wrap">
			<label for="wpfh_sadm_captcha_answer">
				<?php
				printf(
					/* translators: 1: first number, 2: second number */
					esc_html__( 'Security Check: What is %1$d + %2$d?', 'forgehub-secure-admin' ),
					(int) $num1,
					(int) $num2
				);
				?>
			</label>
			<input type="text" inputmode="numeric" pattern="[0-9]*" name="wpfh_sadm_captcha_answer" id="wpfh_sadm_captcha_answer" class="input" value="" size="20" autocomplete="off" required="required" />
			<input type="hidden" name="wpfh_sadm_captcha_token" value="<?php echo esc_attr( $token ); ?>" />
		</p>
		<?php
	}

	/**
	 * Validate the Math CAPTCHA on standard wp-login.php form submissions.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username or email.
	 * @param string                $password Plaintext password.
	 * @return WP_User|WP_Error|null
	 */
	public function validate_math_captcha_on_authenticate( $user, $username, $password ) {
		if ( is_wp_error( $user ) ) {
			$priority_codes = array( 'wpfh_sadm_locked_out', 'wpfh_sadm_honeypot_triggered' );
			foreach ( $user->get_error_codes() as $code ) {
				if ( in_array( $code, $priority_codes, true ) ) {
					return $user;
				}
			}
		}

		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		if (
			( defined( 'REST_REQUEST' ) && REST_REQUEST ) ||
			( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ||
			( defined( 'WP_CLI' ) && WP_CLI ) ||
			did_action( 'wp_authenticate_application_password_errors' )
		) {
			return $user;
		}

		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : '';
		// Only enforce on standard wp-login.php POST submissions (which submit 'log' or our token).
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( 'POST' !== $request_method || ( ! isset( $_POST['log'] ) && ! isset( $_POST['wpfh_sadm_captcha_token'] ) ) ) {
			return $user;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token = isset( $_POST['wpfh_sadm_captcha_token'] ) ? sanitize_key( wp_unslash( $_POST['wpfh_sadm_captcha_token'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$answer = isset( $_POST['wpfh_sadm_captcha_answer'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['wpfh_sadm_captcha_answer'] ) ) ) : '';

		if ( '' === $token || '' === $answer ) {
			return new WP_Error(
				'wpfh_sadm_captcha_failed',
				esc_html__( 'Please solve the security math question to log in.', 'forgehub-secure-admin' )
			);
		}

		$trans_key = 'wpfh_sadm_cap_' . $token;
		$expected  = get_transient( $trans_key );
		delete_transient( $trans_key );

		if ( false === $expected || ! hash_equals( (string) $expected, (string) $answer ) ) {
			return new WP_Error(
				'wpfh_sadm_captcha_failed',
				esc_html__( 'Incorrect security math answer. Please try again.', 'forgehub-secure-admin' )
			);
		}

		return $user;
	}

	/**
	 * Render an opt-in protection badge below the login form.
	 */
	public function render_login_badge() {
		?>
		<div class="wpfh-sadm-login-badge" style="text-align:center;margin:16px auto 0;max-width:320px;font-size:12px;color:#334155;display:flex;align-items:center;justify-content:center;gap:6px;">
			<span class="dashicons dashicons-shield" aria-hidden="true" style="font-size:16px;width:16px;height:16px;color:#0f766e;"></span>
			<span><?php esc_html_e( 'Protected by ForgeHub Secure Admin', 'forgehub-secure-admin' ); ?></span>
		</div>
		<?php
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
