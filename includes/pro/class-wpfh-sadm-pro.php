<?php
/**
 * Secure Admin Guard Pro Suite
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPFH_SADM_Pro {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'wp_login', array( $this, 'maybe_send_login_alert' ), 20, 2 );
		add_action( 'init', array( $this, 'maybe_block_bad_bots' ), 1 );
		add_action( 'show_user_profile', array( $this, 'render_recovery_codes_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_recovery_codes_section' ) );
		add_action( 'personal_options_update', array( $this, 'handle_generate_recovery_codes' ) );
		add_action( 'edit_user_profile_update', array( $this, 'handle_generate_recovery_codes' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue_idle_logout_script' ) );
	}

	/**
	 * Return 403 for known bad bot User-Agents.
	 */
	public function maybe_block_bad_bots() {
		$settings = wpfh_sadm_get_settings();
		if ( empty( $settings['pro_block_bad_bots'] ) || empty( $_SERVER['HTTP_USER_AGENT'] ) || wp_doing_cron() || is_user_logged_in() ) {
			return;
		}

		$ua    = strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) );
		$list  = array( 'sqlmap', 'nikto', 'masscan', 'acunetix', 'wpscan', 'havij', 'zgrab', 'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot', 'python-requests', 'scrapy' );
		$extra = preg_split( '/\r\n|\r|\n/', strtolower( (string) $settings['pro_bad_bot_list'] ) );
		foreach ( array_merge( $list, array_filter( array_map( 'trim', (array) $extra ) ) ) as $needle ) {
			if ( '' !== $needle && false !== strpos( $ua, $needle ) ) {
				status_header( 403 );
				wp_die( esc_html__( 'Forbidden', 'forgehub-secure-admin' ), '', array( 'response' => 403 ) );
			}
		}
	}

	/**
	 * Send an instant email alert when an administrator authenticates.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 */
	public function maybe_send_login_alert( $user_login, $user ) {
		$settings = wpfh_sadm_get_settings();
		if ( empty( $settings['pro_login_alert'] ) ) {
			return;
		}

		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}

		$admin_email = get_option( 'admin_email' );
		$site_name   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$ip          = wpfh_sadm_get_client_ip();
		$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown';

		// translators: %s: site name
		$subject = sprintf( esc_html__( '[%s] Security Alert: Administrator Logged In', 'forgehub-secure-admin' ), $site_name );

		$message  = '<div style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 520px; border: 1px solid #e2e8f0; border-radius: 6px; padding: 24px;">';
		$message .= '<h3 style="color: #0f172a; margin-top: 0;">' . esc_html__( 'Successful Administrator Login', 'forgehub-secure-admin' ) . '</h3>';
		// translators: %s: username
		$message .= '<p>' . sprintf( esc_html__( 'Account: %s', 'forgehub-secure-admin' ), '<strong>' . esc_html( $user_login ) . '</strong>' ) . '</p>';
		// translators: %s: client IP address
		$message .= '<p>' . sprintf( esc_html__( 'IP Address: %s', 'forgehub-secure-admin' ), '<code>' . esc_html( $ip ) . '</code>' ) . '</p>';
		// translators: %s: current timestamp
		$message .= '<p>' . sprintf( esc_html__( 'Time: %s', 'forgehub-secure-admin' ), esc_html( current_time( 'mysql' ) ) ) . '</p>';
		// translators: %s: user agent string
		$message .= '<p>' . sprintf( esc_html__( 'Browser: %s', 'forgehub-secure-admin' ), '<small>' . esc_html( $user_agent ) . '</small>' ) . '</p>';
		$message .= '<p style="color: #64748b; font-size: 12px; margin-top: 20px;">' . esc_html__( 'If this was not you, access your dashboard and revoke all sessions immediately.', 'forgehub-secure-admin' ) . '</p>';
		$message .= '</div>';

		$headers = array( 'Content-Type: text/html; charset=UTF-8' );
		wp_mail( $admin_email, $subject, $message, $headers );
	}

	/**
	 * Render emergency backup recovery codes on user profile.
	 *
	 * @param WP_User $user User profile.
	 */
	public function render_recovery_codes_section( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		$codes = get_user_meta( $user->ID, 'wpfh_sadm_backup_codes', true );
		$count = is_array( $codes ) ? count( $codes ) : 0;
		?>
		<h2><?php esc_html_e( 'Secure Admin Guard: Emergency Backup Codes', 'forgehub-secure-admin' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Backup Recovery Codes', 'forgehub-secure-admin' ); ?></th>
				<td>
					<p>
						<?php
						// translators: %d: number of remaining recovery codes
						printf( esc_html__( 'You have %d active single-use emergency backup code(s) remaining.', 'forgehub-secure-admin' ), absint( $count ) );
						?>
					</p>
					<label>
						<input type="checkbox" name="wpfh_sadm_regen_backup_codes" value="1" />
						<?php esc_html_e( 'Generate 8 new emergency backup recovery codes', 'forgehub-secure-admin' ); ?>
					</label>
					<p class="description">
						<?php esc_html_e( 'Use backup codes to log in if your email is temporarily inaccessible. Each code can only be used once.', 'forgehub-secure-admin' ); ?>
					</p>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Handle generation of new emergency recovery codes.
	 *
	 * @param int $user_id User ID.
	 */
	public function handle_generate_recovery_codes( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['wpfh_sadm_regen_backup_codes'] ) ) {
			return;
		}

		$plain_codes  = array();
		$hashed_codes = array();

		for ( $i = 0; $i < 8; $i++ ) {
			$code           = wp_generate_password( 8, false, false );
			$plain_codes[]  = $code;
			$hashed_codes[] = wp_hash_password( $code );
		}

		update_user_meta( $user_id, 'wpfh_sadm_backup_codes', $hashed_codes );

		// Set transient to display plaintext codes once
		set_transient( 'wpfh_sadm_plain_codes_' . $user_id, $plain_codes, 300 );
	}

	/**
	 * Enqueue idle auto-logout watchdog in admin.
	 */
	public function maybe_enqueue_idle_logout_script() {
		$settings = wpfh_sadm_get_settings();
		if ( empty( $settings['pro_idle_logout'] ) ) {
			return;
		}

		$timeout_minutes = max( 1, absint( $settings['pro_idle_timeout'] ?? 15 ) );
		$timeout_ms      = $timeout_minutes * 60 * 1000;
		$logout_url      = wp_logout_url( wp_login_url() );

		$inline_js = "
		(function() {
			var idleTimeout = {$timeout_ms};
			var timer = null;
			function resetTimer() {
				clearTimeout(timer);
				timer = setTimeout(function() {
					alert('" . esc_js( __( 'Your session has expired due to inactivity. You will now be redirected to the login page.', 'forgehub-secure-admin' ) ) . "');
					window.location.href = '" . esc_url_raw( $logout_url ) . "';
				}, idleTimeout);
			}
			['mousemove', 'keydown', 'scroll', 'click'].forEach(function(evt) {
				document.addEventListener(evt, resetTimer, false);
			});
			resetTimer();
		})();
		";

		wp_add_inline_script( 'wp-util', $inline_js );
	}
}
