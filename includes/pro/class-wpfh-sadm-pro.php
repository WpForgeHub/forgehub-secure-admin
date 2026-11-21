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
		add_action( 'init', array( $this, 'maybe_block_blacklisted_ip' ), 0 );
		add_action( 'init', array( $this, 'maybe_block_bad_bots' ), 1 );
		add_action( 'show_user_profile', array( $this, 'render_recovery_codes_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_recovery_codes_section' ) );
		add_action( 'personal_options_update', array( $this, 'handle_generate_recovery_codes' ) );
		add_action( 'edit_user_profile_update', array( $this, 'handle_generate_recovery_codes' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue_idle_logout_script' ) );
		add_action( 'admin_post_wpfh_sadm_export_activity_csv', array( $this, 'export_activity_csv' ) );
		add_action( 'admin_post_wpfh_sadm_blacklist_ip', array( $this, 'handle_blacklist_ip' ) );
	}

	/**
	 * Block requests from manually blacklisted IPs.
	 */
	public function maybe_block_blacklisted_ip() {
		if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$blacklisted = get_option( 'wpfh_sadm_blacklisted_ips', array() );
		if ( empty( $blacklisted ) || ! is_array( $blacklisted ) ) {
			return;
		}
		$ip = wpfh_sadm_get_client_ip();
		if ( in_array( $ip, $blacklisted, true ) ) {
			status_header( 403 );
			wp_die( esc_html__( 'Access denied.', 'forgehub-secure-admin' ), esc_html__( 'Forbidden', 'forgehub-secure-admin' ), array( 'response' => 403 ) );
		}
	}

	/**
	 * Handle admin_post_wpfh_sadm_blacklist_ip action from the Activity Log table.
	 */
	public function handle_blacklist_ip() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'forgehub-secure-admin' ) );
		}

		check_admin_referer( 'wpfh_sadm_blacklist_action', 'wpfh_sadm_blacklist_nonce' );

		$ip         = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
		$valid_ip   = filter_var( $ip, FILTER_VALIDATE_IP );
		$current_ip = wpfh_sadm_get_client_ip();

		if ( $valid_ip && $valid_ip !== $current_ip ) {
			$blacklisted = get_option( 'wpfh_sadm_blacklisted_ips', array() );
			if ( ! is_array( $blacklisted ) ) {
				$blacklisted = array();
			}
			if ( ! in_array( $valid_ip, $blacklisted, true ) ) {
				$blacklisted[] = $valid_ip;
				update_option( 'wpfh_sadm_blacklisted_ips', $blacklisted );
			}
			$this->blacklist_ip( $valid_ip );
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => 'forgehub-secure-admin',
					'tab'         => 'activity',
					'blacklisted' => $valid_ip && $valid_ip !== $current_ip ? '1' : '0',
				),
				admin_url( 'options-general.php' )
			)
		);
		exit;
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

		$codes       = get_user_meta( $user->ID, 'wpfh_sadm_backup_codes', true );
		$count       = is_array( $codes ) ? count( $codes ) : 0;
		$plain_codes = get_transient( 'wpfh_sadm_plain_codes_' . $user->ID );
		if ( is_array( $plain_codes ) && ! empty( $plain_codes ) ) {
			delete_transient( 'wpfh_sadm_plain_codes_' . $user->ID );
		}
		?>
		<h2><?php esc_html_e( 'Secure Admin Guard: Emergency Backup Codes', 'forgehub-secure-admin' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Backup Recovery Codes', 'forgehub-secure-admin' ); ?></th>
				<td>
					<?php if ( is_array( $plain_codes ) && ! empty( $plain_codes ) ) : ?>
						<div style="background: #fefce8; border: 1px solid #facc15; border-radius: 6px; padding: 14px 16px; margin-bottom: 14px; max-width: 460px;">
							<p style="margin: 0 0 8px; font-weight: 600; color: #854d0e;">
								<?php esc_html_e( 'Save these emergency recovery codes now — they will not be shown again:', 'forgehub-secure-admin' ); ?>
							</p>
							<pre style="margin: 0; font-family: monospace; font-size: 14px; line-height: 1.7; background: #ffffff; padding: 10px 12px; border: 1px solid #e5e7eb; border-radius: 4px;"><?php echo esc_html( implode( "\n", $plain_codes ) ); ?></pre>
						</div>
					<?php endif; ?>
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
		$logout_url      = html_entity_decode( wp_logout_url( wp_login_url() ), ENT_QUOTES, 'UTF-8' );

		$inline_js = "
		(function() {
			var idleTimeout = {$timeout_ms};
			var logoutUrl = " . wp_json_encode( $logout_url ) . ";
			var timer = null;
			function resetTimer() {
				clearTimeout(timer);
				timer = setTimeout(function() {
					alert(" . wp_json_encode( __( 'Your session has expired due to inactivity. You will now be redirected to the login page.', 'forgehub-secure-admin' ) ) . ");
					window.location.href = logoutUrl;
				}, idleTimeout);
			}
			['mousemove', 'keydown', 'scroll', 'click'].forEach(function(evt) {
				document.addEventListener(evt, resetTimer, false);
			});
			resetTimer();
		})();
		";

		wp_enqueue_script( 'wp-util' );
		wp_add_inline_script( 'wp-util', $inline_js );
	}

	/**
	 * Export login activity logs to CSV format (Pro audit log export).
	 */
	public function export_activity_csv() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'forgehub-secure-admin' ) );
		}

		check_admin_referer( 'wpfh_sadm_export_csv', 'wpfh_sadm_csv_nonce' );

		$logs = get_option( 'wpfh_sadm_activity_logs', array() );
		if ( ! is_array( $logs ) ) {
			$logs = array();
		}

		header( 'Content-Type: text/csv; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename=wpfh-sadm-login-activity-' . gmdate( 'Y-m-d' ) . '.csv' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		$rows = array(
			array( 'Timestamp', 'Date/Time (UTC)', 'Username', 'IP Address', 'Status' ),
		);

		foreach ( $logs as $entry ) {
			$time     = isset( $entry['time'] ) ? absint( $entry['time'] ) : time();
			$username = isset( $entry['username'] ) ? sanitize_text_field( $entry['username'] ) : '';
			$ip       = isset( $entry['ip'] ) ? sanitize_text_field( $entry['ip'] ) : '';
			$status   = isset( $entry['status'] ) ? sanitize_key( $entry['status'] ) : '';

			$rows[] = array(
				(string) $time,
				gmdate( 'Y-m-d H:i:s', $time ),
				$username,
				$ip,
				$status,
			);
		}

		foreach ( $rows as $row ) {
			$escaped = array_map(
				static function ( $field ) {
					$value = (string) $field;
					if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
						$value = "'" . $value;
					}
					return '"' . str_replace( '"', '""', $value ) . '"';
				},
				$row
			);
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Raw CSV download stream with text/csv Content-Type header.
			echo implode( ',', $escaped ) . "\r\n";
		}

		exit;
	}

	/**
	 * Trigger IP blacklist action hook for external firewalls or security audit modules.
	 *
	 * @param string $ip Offending IP address.
	 */
	public function blacklist_ip( $ip ) {
		$sanitized_ip = sanitize_text_field( $ip );
		do_action( 'wpfh_sadm_ip_blacklisted', $sanitized_ip );
	}
}
