<?php
/**
 * Email Two-Factor Authentication (OTP)
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPFH_SADM_Email_2FA {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Hook late in authentication after standard password validation (priority 30)
		add_filter( 'authenticate', array( $this, 'intercept_login_for_2fa' ), 30, 3 );
		add_action( 'login_form_wpfh_sadm_resend', array( $this, 'handle_resend_otp' ) );
	}

	/**
	 * Check if 2FA is enabled for the given user.
	 *
	 * @param WP_User $user User object.
	 * @return bool
	 */
	public function is_2fa_required_for_user( $user ) {
		if ( ! $user instanceof WP_User ) {
			return false;
		}

		$settings = wpfh_sadm_get_settings();
		if ( empty( $settings['email_2fa_enabled'] ) ) {
			return false;
		}

		// Check if user has administrator role (Free tier)
		$user_roles = (array) $user->roles;
		if ( in_array( 'administrator', $user_roles, true ) ) {
			return true;
		}

		// Pro tier: check configured roles
		if ( function_exists( 'wpfh_sadm_fs' ) && wpfh_sadm_fs()->can_use_premium_code() ) {
			$allowed_roles = isset( $settings['pro_2fa_roles'] ) ? (array) $settings['pro_2fa_roles'] : array( 'administrator' );
			foreach ( $user_roles as $role ) {
				if ( in_array( $role, $allowed_roles, true ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check if current device is a verified trusted device (Pro feature).
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function is_device_trusted( $user_id ) {
		if ( ! function_exists( 'wpfh_sadm_fs' ) || ! wpfh_sadm_fs()->can_use_premium_code() ) {
			return false;
		}

		$cookie_name = 'wpfh_sadm_dev_' . COOKIEHASH;
		if ( empty( $_COOKIE[ $cookie_name ] ) ) {
			return false;
		}

		$raw   = sanitize_text_field( wp_unslash( $_COOKIE[ $cookie_name ] ) );
		$parts = explode( '|', $raw );
		if ( count( $parts ) !== 3 ) {
			return false;
		}

		list( $cookie_uid, $expires, $hash ) = $parts;
		if ( (int) $cookie_uid !== (int) $user_id || time() > (int) $expires ) {
			return false;
		}

		$expected_hash = hash_hmac( 'sha256', $user_id . '|' . $expires, wp_salt( 'auth' ) );
		return hash_equals( $expected_hash, $hash );
	}

	/**
	 * Intercept authentication flow to enforce 2FA verification.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username or email.
	 * @param string                $password Plaintext password.
	 * @return WP_User|WP_Error
	 */
	public function intercept_login_for_2fa( $user, $username, $password ) {
		if ( is_wp_error( $user ) || ! $user instanceof WP_User ) {
			return $user;
		}

		// Don't intercept XML-RPC, REST API, or Cron
		if ( defined( 'XMLRPC_REQUEST' ) || defined( 'REST_REQUEST' ) || defined( 'DOING_CRON' ) ) {
			return $user;
		}

		if ( ! $this->is_2fa_required_for_user( $user ) ) {
			return $user;
		}

		// Check if trusted browser device cookie is valid (Pro)
		if ( $this->is_device_trusted( $user->ID ) ) {
			return $user;
		}

		// Case A: User has submitted the 2FA verification form
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['wpfh_sadm_otp_code'] ) && isset( $_POST['wpfh_sadm_token'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$token = sanitize_text_field( wp_unslash( $_POST['wpfh_sadm_token'] ) );
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$code  = trim( sanitize_text_field( wp_unslash( $_POST['wpfh_sadm_otp_code'] ) ) );

			$transient_key = 'wpfh_sadm_otp_' . $token;
			$data          = get_transient( $transient_key );

			if ( false === $data || empty( $data['user_id'] ) || (int) $data['user_id'] !== (int) $user->ID ) {
				return new WP_Error(
					'wpfh_sadm_expired_otp',
					esc_html__( 'The verification session has expired. Please log in again.', 'forgehub-secure-admin' )
				);
			}

			// Verify submitted code
			$valid = false;

			// 1. Check primary OTP code
			if ( ! empty( $data['otp_hash'] ) && wp_check_password( $code, $data['otp_hash'] ) ) {
				$valid = true;
			}

			// 2. Pro: Check emergency backup recovery codes
			if ( ! $valid && function_exists( 'wpfh_sadm_fs' ) && wpfh_sadm_fs()->can_use_premium_code() ) {
				$backup_codes = get_user_meta( $user->ID, 'wpfh_sadm_backup_codes', true );
				if ( is_array( $backup_codes ) ) {
					foreach ( $backup_codes as $idx => $stored_hash ) {
						if ( wp_check_password( $code, $stored_hash ) ) {
							$valid = true;
							unset( $backup_codes[ $idx ] );
							update_user_meta( $user->ID, 'wpfh_sadm_backup_codes', array_values( $backup_codes ) );
							break;
						}
					}
				}
			}

			if ( ! $valid ) {
				return new WP_Error(
					'wpfh_sadm_invalid_otp',
					esc_html__( 'Invalid verification code. Please check your email and try again.', 'forgehub-secure-admin' )
				);
			}

			// Valid OTP: cleanup transient
			delete_transient( $transient_key );

			// Pro: handle "Remember this device"
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( ! empty( $_POST['wpfh_sadm_trust_device'] ) && function_exists( 'wpfh_sadm_fs' ) && wpfh_sadm_fs()->can_use_premium_code() ) {
				$this->set_trusted_device_cookie( $user->ID );
			}

			// Trigger success action
			do_action( 'wpfh_sadm_2fa_success', $user );

			return $user;
		}

		// Case B: Initial login credentials verified, stage 2FA OTP
		$otp   = sprintf( '%06d', wp_rand( 100000, 999999 ) );
		$token = wp_generate_password( 32, false );

		$session_data = array(
			'user_id'   => $user->ID,
			'otp_hash'  => wp_hash_password( (string) $otp ),
			'created'   => time(),
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			'remember'  => ! empty( $_POST['rememberme'] ) ? 1 : 0,
		);

		// Store for 10 minutes (600 seconds)
		set_transient( 'wpfh_sadm_otp_' . $token, $session_data, 600 );

		// Dispatch OTP email
		$this->send_otp_email( $user, $otp );

		// Display 2FA screen and exit
		$this->render_2fa_form( $user, $token );
		exit;
	}

	/**
	 * Send 2FA OTP code via wp_mail.
	 *
	 * @param WP_User $user User object.
	 * @param string  $otp  6-digit code.
	 * @return bool
	 */
	public function send_otp_email( $user, $otp ) {
		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$ip        = wpfh_sadm_get_client_ip();

		// translators: %s: site name
		$subject = sprintf( esc_html__( '[%s] Your Login Verification Code', 'forgehub-secure-admin' ), $site_name );

		$message  = '<div style="max-width: 540px; margin: 0 auto; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">';
		$message .= '<div style="background: #0f172a; padding: 24px; text-align: center;">';
		$message .= '<h2 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 600;">' . esc_html( $site_name ) . '</h2>';
		$message .= '<p style="color: #94a3b8; margin: 4px 0 0; font-size: 13px;">' . esc_html__( 'Secure Admin Guard Verification', 'forgehub-secure-admin' ) . '</p>';
		$message .= '</div>';
		$message .= '<div style="padding: 32px 24px; text-align: center;">';
		// translators: %s: user display name
		$message .= '<p style="color: #334155; font-size: 15px; margin: 0 0 16px;">' . sprintf( esc_html__( 'Hello %s,', 'forgehub-secure-admin' ), esc_html( $user->display_name ) ) . '</p>';
		$message .= '<p style="color: #475569; font-size: 14px; margin: 0 0 24px;">' . esc_html__( 'Use the following one-time verification code to complete your login:', 'forgehub-secure-admin' ) . '</p>';
		$message .= '<div style="background: #f1f5f9; border: 2px dashed #cbd5e1; border-radius: 8px; padding: 18px; margin: 0 auto 24px; display: inline-block;">';
		$message .= '<span style="font-family: monospace; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #0f172a;">' . esc_html( $otp ) . '</span>';
		$message .= '</div>';
		$message .= '<p style="color: #64748b; font-size: 13px; margin: 0 0 8px;">' . esc_html__( 'This code will expire in 10 minutes.', 'forgehub-secure-admin' ) . '</p>';
		// translators: %s: client IP address
		$message .= '<p style="color: #94a3b8; font-size: 12px; margin: 0;">' . sprintf( esc_html__( 'Login attempt from IP: %s', 'forgehub-secure-admin' ), esc_html( $ip ) ) . '</p>';
		$message .= '</div>';
		$message .= '<div style="background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 16px; text-align: center; color: #94a3b8; font-size: 11px;">';
		$message .= esc_html__( 'If you did not attempt this login, please change your password immediately.', 'forgehub-secure-admin' );
		$message .= '</div>';
		$message .= '</div>';

		$headers = array( 'Content-Type: text/html; charset=UTF-8' );
		return wp_mail( $user->user_email, $subject, $message, $headers );
	}

	/**
	 * Mask email address for privacy in login notice.
	 *
	 * @param string $email Plain email.
	 * @return string Masked email (e.g. j***@domain.com).
	 */
	private function mask_email( $email ) {
		$parts = explode( '@', $email );
		if ( count( $parts ) !== 2 ) {
			return '***@***.***';
		}
		$name   = $parts[0];
		$domain = $parts[1];
		$first  = substr( $name, 0, 1 );
		return $first . '***@' . $domain;
	}

	/**
	 * Render the 2FA verification form inside wp-login.php.
	 *
	 * @param WP_User $user  User object.
	 * @param string  $token 32-character session token.
	 */
	public function render_2fa_form( $user, $token ) {
		login_header(
			esc_html__( 'Two-Factor Authentication', 'forgehub-secure-admin' ),
			'',
			new WP_Error()
		);

		$masked_email = $this->mask_email( $user->user_email );
		?>
		<style>
			.wpfh-2fa-card {
				background: #fff;
				padding: 24px;
				margin-bottom: 20px;
				border: 1px solid #c3c4c7;
				box-shadow: 0 1px 3px rgba(0,0,0,0.04);
				border-radius: 4px;
			}
			.wpfh-otp-input {
				font-size: 26px !important;
				font-family: monospace !important;
				letter-spacing: 8px !important;
				text-align: center !important;
				padding: 10px !important;
				height: auto !important;
				width: 100% !important;
				margin-bottom: 16px !important;
			}
			.wpfh-2fa-trust {
				margin: 12px 0 16px;
				font-size: 13px;
				color: #50575e;
			}
			.wpfh-2fa-resend {
				margin-top: 14px;
				text-align: center;
				font-size: 13px;
			}
		</style>

		<div class="wpfh-2fa-card">
			<h2 style="font-size: 18px; margin: 0 0 12px; font-weight: 600; color: #1d2327;">
				<?php esc_html_e( 'Enter Verification Code', 'forgehub-secure-admin' ); ?>
			</h2>
			<p style="font-size: 13px; color: #50575e; margin: 0 0 16px; line-height: 1.5;">
				<?php
				// translators: %s: masked email address
				printf( esc_html__( 'A 6-digit security code has been sent to %s. Please enter it below to complete your login.', 'forgehub-secure-admin' ), '<strong>' . esc_html( $masked_email ) . '</strong>' );
				?>
			</p>

			<form name="wpfh_2fa_form" id="wpfh_2fa_form" action="<?php echo esc_url( wp_login_url() ); ?>" method="post">
				<input type="hidden" name="wpfh_sadm_token" value="<?php echo esc_attr( $token ); ?>" />
				<input type="hidden" name="log" value="<?php echo esc_attr( $user->user_login ); ?>" />
				<input type="hidden" name="pwd" value="__WPFH_2FA_BYPASS__" />

				<p>
					<label for="wpfh_sadm_otp_code"><?php esc_html_e( '6-Digit Code or Recovery Key', 'forgehub-secure-admin' ); ?></label>
					<input type="text" name="wpfh_sadm_otp_code" id="wpfh_sadm_otp_code" class="input wpfh-otp-input" value="" size="8" maxlength="12" autocomplete="one-time-code" autofocus inputmode="numeric" required />
				</p>

				<?php if ( function_exists( 'wpfh_sadm_fs' ) && wpfh_sadm_fs()->can_use_premium_code() ) : ?>
					<p class="wpfh-2fa-trust">
						<label>
							<input name="wpfh_sadm_trust_device" type="checkbox" id="wpfh_sadm_trust_device" value="1" />
							<?php esc_html_e( 'Trust this browser for 30 days', 'forgehub-secure-admin' ); ?>
						</label>
					</p>
				<?php endif; ?>

				<p class="submit">
					<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" style="width: 100%;" value="<?php esc_attr_e( 'Verify & Log In', 'forgehub-secure-admin' ); ?>" />
				</p>
			</form>

			<div class="wpfh-2fa-resend">
				<a href="<?php echo esc_url( add_query_arg( array( 'action' => 'wpfh_sadm_resend', 'token' => $token ), wp_login_url() ) ); ?>">
					<?php esc_html_e( '&larr; Resend verification code', 'forgehub-secure-admin' ); ?>
				</a>
			</div>
		</div>

		<?php
		login_footer();
	}

	/**
	 * Handle resend OTP request.
	 */
	public function handle_resend_otp() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['token'] ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token         = sanitize_text_field( wp_unslash( $_GET['token'] ) );
		$transient_key = 'wpfh_sadm_otp_' . $token;
		$data          = get_transient( $transient_key );

		if ( false !== $data && ! empty( $data['user_id'] ) ) {
			$user = get_user_by( 'id', $data['user_id'] );
			if ( $user instanceof WP_User ) {
				$new_otp = sprintf( '%06d', wp_rand( 100000, 999999 ) );
				$data['otp_hash'] = wp_hash_password( (string) $new_otp );
				set_transient( $transient_key, $data, 600 );
				$this->send_otp_email( $user, $new_otp );
			}
		}

		wp_safe_redirect( wp_login_url() );
		exit;
	}

	/**
	 * Set a 30-day trusted device cookie for the verified user (Pro feature).
	 *
	 * @param int $user_id User ID.
	 */
	public function set_trusted_device_cookie( $user_id ) {
		$expires     = time() + ( 30 * DAY_IN_SECONDS );
		$hash        = hash_hmac( 'sha256', $user_id . '|' . $expires, wp_salt( 'auth' ) );
		$cookie_val  = $user_id . '|' . $expires . '|' . $hash;
		$cookie_name = 'wpfh_sadm_dev_' . COOKIEHASH;

		setcookie( $cookie_name, $cookie_val, $expires, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
	}
}
