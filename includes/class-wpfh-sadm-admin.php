<?php
/**
 * Admin Settings Interface & Dashboard
 *
 * @package WPFH_Secure_Admin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WPFH_SADM_Admin {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( WPFH_SADM_FILE ), array( $this, 'add_action_links' ) );
		add_action( 'admin_init', array( $this, 'handle_save_settings' ) );
		add_action( 'admin_post_wpfh_sadm_unlock_ip', array( $this, 'handle_unlock_ip' ) );
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param array $links Existing action links.
	 * @return array
	 */
	public function add_action_links( $links ) {
		$settings_link = '<a href="' . esc_url( admin_url( 'options-general.php?page=forgehub-secure-admin' ) ) . '">' . esc_html__( 'Settings', 'forgehub-secure-admin' ) . '</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}

	public function register_admin_menu() {
		add_options_page(
			esc_html__( 'Secure Admin Guard', 'forgehub-secure-admin' ),
			esc_html__( 'Secure Admin', 'forgehub-secure-admin' ),
			'manage_options',
			'forgehub-secure-admin',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Handle saving of plugin settings.
	 */
	public function handle_save_settings() {
		if ( ! isset( $_POST['wpfh_sadm_save_settings'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'forgehub-secure-admin' ) );
		}

		check_admin_referer( 'wpfh_sadm_save_settings_nonce', 'wpfh_sadm_nonce' );

		$current = wpfh_sadm_get_settings();

		$current['brute_force_enabled']  = ! empty( $_POST['brute_force_enabled'] ) ? 1 : 0;
		$current['max_attempts']         = max( 1, min( 50, absint( $_POST['max_attempts'] ?? 5 ) ) );
		$current['lockout_duration']     = max( 1, min( 1440, absint( $_POST['lockout_duration'] ?? 15 ) ) );
		$current['whitelist_ips']        = sanitize_textarea_field( wp_unslash( $_POST['whitelist_ips'] ?? '' ) );

		$current['email_2fa_enabled']    = ! empty( $_POST['email_2fa_enabled'] ) ? 1 : 0;

		$current['generic_login_errors'] = ! empty( $_POST['generic_login_errors'] ) ? 1 : 0;
		$current['disable_xmlrpc']       = ! empty( $_POST['disable_xmlrpc'] ) ? 1 : 0;
		$current['block_author_query']   = ! empty( $_POST['block_author_query'] ) ? 1 : 0;
		$current['hide_wp_version']      = ! empty( $_POST['hide_wp_version'] ) ? 1 : 0;
		$current['hide_login_slug']      = WPFH_SADM_Hide_Login::sanitize_slug( sanitize_text_field( wp_unslash( $_POST['hide_login_slug'] ?? '' ) ) );
		$current['security_headers']     = ! empty( $_POST['security_headers'] ) ? 1 : 0;
		$current['disable_file_editor']  = ! empty( $_POST['disable_file_editor'] ) ? 1 : 0;

		// Pro settings (if premium)
		if ( function_exists( 'wpfh_sadm_fs' ) && wpfh_sadm_fs()->can_use_premium_code() ) {
			$current['pro_trusted_device'] = ! empty( $_POST['pro_trusted_device'] ) ? 1 : 0;
			$current['pro_idle_logout']    = ! empty( $_POST['pro_idle_logout'] ) ? 1 : 0;
			$current['pro_idle_timeout']   = max( 1, min( 240, absint( $_POST['pro_idle_timeout'] ?? 15 ) ) );
			$current['pro_login_alert']    = ! empty( $_POST['pro_login_alert'] ) ? 1 : 0;
			$current['pro_block_bad_bots'] = ! empty( $_POST['pro_block_bad_bots'] ) ? 1 : 0;
			$current['pro_bad_bot_list']   = sanitize_textarea_field( wp_unslash( $_POST['pro_bad_bot_list'] ?? '' ) );

			if ( isset( $_POST['pro_2fa_roles'] ) && is_array( $_POST['pro_2fa_roles'] ) ) {
				$current['pro_2fa_roles'] = array_map( 'sanitize_key', $_POST['pro_2fa_roles'] );
				if ( ! in_array( 'administrator', $current['pro_2fa_roles'], true ) ) {
					$current['pro_2fa_roles'][] = 'administrator';
				}
			}
		}

		update_option( 'wpfh_sadm_settings', $current );

		wp_safe_redirect( add_query_arg( array(
			'page'             => 'forgehub-secure-admin',
			'settings-updated' => '1',
			'tab'              => sanitize_key( $_POST['active_tab'] ?? 'brute_force' ),
		), admin_url( 'options-general.php' ) ) );
		exit;
	}

	/**
	 * Handle manual unlock of an IP from the activity log.
	 */
	public function handle_unlock_ip() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'forgehub-secure-admin' ) );
		}

		check_admin_referer( 'wpfh_sadm_unlock_action', 'wpfh_sadm_unlock_nonce' );

		if ( ! empty( $_GET['ip'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_GET['ip'] ) );
			delete_transient( 'wpfh_sadm_lock_' . md5( $ip ) );
			delete_transient( 'wpfh_sadm_att_' . md5( $ip ) );
		}

		wp_safe_redirect( add_query_arg( array(
			'page'     => 'forgehub-secure-admin',
			'tab'      => 'logs',
			'unlocked' => '1',
		), admin_url( 'options-general.php' ) ) );
		exit;
	}

	/**
	 * Render the plugin settings page.
	 */
	public function render_settings_page() {
		$settings = wpfh_sadm_get_settings();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'brute_force';
		$is_pro     = function_exists( 'wpfh_sadm_fs' ) && wpfh_sadm_fs()->can_use_premium_code();
		?>
		<div class="wrap" style="max-width: 1040px;">
			<h1 style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
				<span style="display: inline-block; width: 14px; height: 14px; border-radius: 50%; background: #ef4444;"></span>
				<?php esc_html_e( 'Secure Admin Guard', 'forgehub-secure-admin' ); ?>
				<span style="font-size: 13px; font-weight: 500; background: #e2e8f0; color: #334155; padding: 2px 10px; border-radius: 12px;">v<?php echo esc_html( WPFH_SADM_VERSION ); ?></span>
				<?php if ( $is_pro ) : ?>
					<span style="font-size: 13px; font-weight: 600; background: #22c55e; color: #ffffff; padding: 2px 10px; border-radius: 12px;"><?php esc_html_e( 'PRO ACTIVE', 'forgehub-secure-admin' ); ?></span>
				<?php else : ?>
					<span style="font-size: 13px; font-weight: 500; background: #cbd5e1; color: #1e293b; padding: 2px 10px; border-radius: 12px;"><?php esc_html_e( 'FREE EDITION', 'forgehub-secure-admin' ); ?></span>
				<?php endif; ?>
			</h1>

			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['settings-updated'] ) ) :
				?>
				<div class="notice notice-success is-dismissible">
					<p><?php esc_html_e( 'Security settings updated successfully.', 'forgehub-secure-admin' ); ?></p>
				</div>
			<?php endif; ?>

			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_GET['unlocked'] ) ) :
				?>
				<div class="notice notice-success is-dismissible">
					<p><?php esc_html_e( 'IP address has been unlocked.', 'forgehub-secure-admin' ); ?></p>
				</div>
			<?php endif; ?>

			<nav class="nav-tab-wrapper wp-clearfix" style="margin-bottom: 20px;">
				<a href="?page=forgehub-secure-admin&tab=brute_force" class="nav-tab <?php echo 'brute_force' === $active_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Brute Force Shield', 'forgehub-secure-admin' ); ?>
				</a>
				<a href="?page=forgehub-secure-admin&tab=two_factor" class="nav-tab <?php echo 'two_factor' === $active_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Email 2FA (OTP)', 'forgehub-secure-admin' ); ?>
				</a>
				<a href="?page=forgehub-secure-admin&tab=hardening" class="nav-tab <?php echo 'hardening' === $active_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'WordPress Hardening', 'forgehub-secure-admin' ); ?>
				</a>
				<a href="?page=forgehub-secure-admin&tab=logs" class="nav-tab <?php echo 'logs' === $active_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Lockout Logs & Audit', 'forgehub-secure-admin' ); ?>
				</a>
			</nav>

			<form method="post" action="<?php echo esc_url( admin_url( 'options-general.php?page=forgehub-secure-admin' ) ); ?>">
				<?php wp_nonce_field( 'wpfh_sadm_save_settings_nonce', 'wpfh_sadm_nonce' ); ?>
				<input type="hidden" name="wpfh_sadm_save_settings" value="1" />
				<input type="hidden" name="active_tab" value="<?php echo esc_attr( $active_tab ); ?>" />

				<div style="background: #ffffff; border: 1px solid #c3c4c7; border-radius: 6px; padding: 24px 30px; box-shadow: 0 1px 2px rgba(0,0,0,0.04);">

					<?php if ( 'brute_force' === $active_tab ) : ?>
						<h2 style="margin-top: 0; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9; color: #0f172a;">
							<?php esc_html_e( 'Brute Force Rate Limiter', 'forgehub-secure-admin' ); ?>
						</h2>
						<p style="color: #64748b; margin-bottom: 24px;">
							<?php esc_html_e( 'Protect your login form from automated password-guessing bots and credential stuffing attacks.', 'forgehub-secure-admin' ); ?>
						</p>

						<table class="form-table" role="presentation">
							<tr>
								<th scope="row"><?php esc_html_e( 'Enable Protection', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="brute_force_enabled" value="1" <?php checked( $settings['brute_force_enabled'], 1 ); ?> />
										<?php esc_html_e( 'Enable brute force rate limiting on wp-login.php', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row">
									<label for="max_attempts"><?php esc_html_e( 'Max Allowed Attempts', 'forgehub-secure-admin' ); ?></label>
								</th>
								<td>
									<input type="number" id="max_attempts" name="max_attempts" value="<?php echo esc_attr( $settings['max_attempts'] ); ?>" min="1" max="50" class="small-text" />
									<span class="description"><?php esc_html_e( 'Number of failed attempts before locking out the IP (default: 5).', 'forgehub-secure-admin' ); ?></span>
								</td>
							</tr>
							<tr>
								<th scope="row">
									<label for="lockout_duration"><?php esc_html_e( 'Lockout Duration', 'forgehub-secure-admin' ); ?></label>
								</th>
								<td>
									<input type="number" id="lockout_duration" name="lockout_duration" value="<?php echo esc_attr( $settings['lockout_duration'] ); ?>" min="1" max="1440" class="small-text" />
									<span class="description"><?php esc_html_e( 'Minutes to block offending IP from logging in (default: 15 minutes).', 'forgehub-secure-admin' ); ?></span>
								</td>
							</tr>
							<tr>
								<th scope="row">
									<label for="whitelist_ips"><?php esc_html_e( 'IP Whitelist', 'forgehub-secure-admin' ); ?></label>
								</th>
								<td>
									<textarea id="whitelist_ips" name="whitelist_ips" rows="4" cols="50" class="large-text code" placeholder="192.168.1.1&#10;10.0.0.1"><?php echo esc_textarea( $settings['whitelist_ips'] ); ?></textarea>
									<p class="description">
										<?php
										// translators: %s: current user IP address
										printf( esc_html__( 'Enter one IPv4 or IPv6 per line. Your current IP is %s.', 'forgehub-secure-admin' ), '<code>' . esc_html( wpfh_sadm_get_client_ip() ) . '</code>' );
										?>
									</p>
								</td>
							</tr>
						</table>

					<?php elseif ( 'two_factor' === $active_tab ) : ?>
						<h2 style="margin-top: 0; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9; color: #0f172a;">
							<?php esc_html_e( 'Email Two-Factor Authentication (OTP)', 'forgehub-secure-admin' ); ?>
						</h2>
						<p style="color: #64748b; margin-bottom: 24px;">
							<?php esc_html_e( 'Dispatches a cryptographically secure 6-digit one-time code to verified email addresses upon login.', 'forgehub-secure-admin' ); ?>
						</p>

						<table class="form-table" role="presentation">
							<tr>
								<th scope="row"><?php esc_html_e( 'Enable Email 2FA', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="email_2fa_enabled" value="1" <?php checked( $settings['email_2fa_enabled'], 1 ); ?> />
										<?php esc_html_e( 'Require email OTP verification code upon login', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Covered Roles', 'forgehub-secure-admin' ); ?></th>
								<td>
									<p style="margin-bottom: 8px;">
										<label><input type="checkbox" checked disabled /> <strong>Administrator</strong> (Free Edition)</label>
									</p>
									<?php if ( $is_pro ) : ?>
										<?php
										$editable_roles = array(
											'editor'        => 'Editor',
											'author'        => 'Author',
											'shop_manager'  => 'Shop Manager',
											'customer'      => 'Customer',
										);
										$configured_roles = (array) $settings['pro_2fa_roles'];
										foreach ( $editable_roles as $r_slug => $r_label ) :
											?>
											<label style="margin-right: 16px;">
												<input type="checkbox" name="pro_2fa_roles[]" value="<?php echo esc_attr( $r_slug ); ?>" <?php checked( in_array( $r_slug, $configured_roles, true ) ); ?> />
												<?php echo esc_html( $r_label ); ?>
											</label>
										<?php endforeach; ?>
									<?php else : ?>
										<p class="description" style="color: #94a3b8;">
											<?php esc_html_e( 'Upgrade to Pro to enable 2FA for Editors, Authors, Shop Managers, and Customers.', 'forgehub-secure-admin' ); ?>
										</p>
									<?php endif; ?>
								</td>
							</tr>
							<?php if ( $is_pro ) : ?>
								<tr>
									<th scope="row"><?php esc_html_e( 'Trusted Devices', 'forgehub-secure-admin' ); ?></th>
									<td>
										<label>
											<input type="checkbox" name="pro_trusted_device" value="1" <?php checked( $settings['pro_trusted_device'], 1 ); ?> />
											<?php esc_html_e( 'Allow verified users to "Remember this browser for 30 days"', 'forgehub-secure-admin' ); ?>
										</label>
									</td>
								</tr>
							<?php endif; ?>
						</table>

					<?php elseif ( 'hardening' === $active_tab ) : ?>
						<h2 style="margin-top: 0; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9; color: #0f172a;">
							<?php esc_html_e( 'WordPress Hardening & Reconnaissance Defense', 'forgehub-secure-admin' ); ?>
						</h2>
						<p style="color: #64748b; margin-bottom: 24px;">
							<?php esc_html_e( 'Close common information leaks and disable obsolete protocols targeted by malicious scanners.', 'forgehub-secure-admin' ); ?>
						</p>

						<table class="form-table" role="presentation">
							<tr>
								<th scope="row"><?php esc_html_e( 'Generic Login Errors', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="generic_login_errors" value="1" <?php checked( $settings['generic_login_errors'], 1 ); ?> />
										<?php esc_html_e( 'Mask detailed error messages (prevents username enumeration)', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Disable XML-RPC', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="disable_xmlrpc" value="1" <?php checked( $settings['disable_xmlrpc'], 1 ); ?> />
										<?php esc_html_e( 'Block all requests to xmlrpc.php to stop amplification and brute-force backdoors', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Block Author Scans', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="block_author_query" value="1" <?php checked( $settings['block_author_query'], 1 ); ?> />
										<?php esc_html_e( 'Redirect /?author=N scans to the homepage', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Hide WP Version', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="hide_wp_version" value="1" <?php checked( $settings['hide_wp_version'], 1 ); ?> />
										<?php esc_html_e( 'Remove generator meta tag from HTML <head> and RSS feeds', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Hide Login URL', 'forgehub-secure-admin' ); ?></th>
								<td>
									<code><?php echo esc_html( trailingslashit( home_url() ) ); ?></code>
									<input type="text" name="hide_login_slug" value="<?php echo esc_attr( $settings['hide_login_slug'] ); ?>" class="regular-text" placeholder="my-secret-login" autocomplete="off" />
									<p class="description"><?php esc_html_e( 'Leave empty to disable. When set, guests get a 404 on /wp-login.php and /wp-admin, and the login form lives only at this address. Bookmark it before saving.', 'forgehub-secure-admin' ); ?></p>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Security Headers', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="security_headers" value="1" <?php checked( $settings['security_headers'], 1 ); ?> />
										<?php esc_html_e( 'Send X-Frame-Options, X-Content-Type-Options and Referrer-Policy headers', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e( 'Disable File Editor', 'forgehub-secure-admin' ); ?></th>
								<td>
									<label>
										<input type="checkbox" name="disable_file_editor" value="1" <?php checked( $settings['disable_file_editor'], 1 ); ?> />
										<?php esc_html_e( 'Turn off the theme and plugin code editors in wp-admin', 'forgehub-secure-admin' ); ?>
									</label>
								</td>
							</tr>
							<?php if ( $is_pro ) : ?>
								<tr>
									<th scope="row"><?php esc_html_e( 'Bad Bot Blocker', 'forgehub-secure-admin' ); ?></th>
									<td>
										<label>
											<input type="checkbox" name="pro_block_bad_bots" value="1" <?php checked( $settings['pro_block_bad_bots'], 1 ); ?> />
											<?php esc_html_e( 'Return 403 to known malicious scanner and scraper User-Agents', 'forgehub-secure-admin' ); ?>
										</label>
										<p style="margin-top: 8px;">
											<textarea name="pro_bad_bot_list" rows="3" class="large-text" placeholder="evilbot&#10;scrapy"><?php echo esc_textarea( $settings['pro_bad_bot_list'] ); ?></textarea>
											<span class="description"><?php esc_html_e( 'Extra User-Agent fragments, one per line (case-insensitive).', 'forgehub-secure-admin' ); ?></span>
										</p>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php esc_html_e( 'Idle Auto-Logout', 'forgehub-secure-admin' ); ?></th>
									<td>
										<label>
											<input type="checkbox" name="pro_idle_logout" value="1" <?php checked( $settings['pro_idle_logout'], 1 ); ?> />
											<?php esc_html_e( 'Automatically terminate inactive admin sessions after timeout', 'forgehub-secure-admin' ); ?>
										</label>
										<p style="margin-top: 8px;">
											<input type="number" name="pro_idle_timeout" value="<?php echo esc_attr( $settings['pro_idle_timeout'] ); ?>" min="1" max="240" class="small-text" />
											<span class="description"><?php esc_html_e( 'Minutes of inactivity before logout.', 'forgehub-secure-admin' ); ?></span>
										</p>
									</td>
								</tr>
								<tr>
									<th scope="row"><?php esc_html_e( 'Admin Login Alerts', 'forgehub-secure-admin' ); ?></th>
									<td>
										<label>
											<input type="checkbox" name="pro_login_alert" value="1" <?php checked( $settings['pro_login_alert'], 1 ); ?> />
											<?php esc_html_e( 'Send immediate email alert whenever an administrator successfully authenticates', 'forgehub-secure-admin' ); ?>
										</label>
									</td>
								</tr>
							<?php endif; ?>
						</table>

					<?php elseif ( 'logs' === $active_tab ) : ?>
						<h2 style="margin-top: 0; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9; color: #0f172a;">
							<?php esc_html_e( 'Lockout Activity Log', 'forgehub-secure-admin' ); ?>
						</h2>
						<p style="color: #64748b; margin-bottom: 24px;">
							<?php esc_html_e( 'Recent IP addresses locked out due to repeated failed authentication attempts.', 'forgehub-secure-admin' ); ?>
						</p>

						<?php
						$logs = get_option( 'wpfh_sadm_lockout_logs', array() );
						if ( empty( $logs ) ) :
							?>
							<p style="padding: 20px; background: #f8fafc; border-radius: 4px; color: #64748b; text-align: center;">
								<?php esc_html_e( 'No lockout activity recorded yet. Your site is safe.', 'forgehub-secure-admin' ); ?>
							</p>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped">
								<thead>
									<tr>
										<th><?php esc_html_e( 'IP Address', 'forgehub-secure-admin' ); ?></th>
										<th><?php esc_html_e( 'Attempted Username', 'forgehub-secure-admin' ); ?></th>
										<th><?php esc_html_e( 'Lockout Date / Time', 'forgehub-secure-admin' ); ?></th>
										<th><?php esc_html_e( 'Status', 'forgehub-secure-admin' ); ?></th>
										<th><?php esc_html_e( 'Actions', 'forgehub-secure-admin' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $logs as $entry ) : ?>
										<?php
										$is_active = ( $entry['unlock_at'] ?? 0 ) > time();
										$unlock_url = wp_nonce_url(
											add_query_arg( array(
												'action' => 'wpfh_sadm_unlock_ip',
												'ip'     => $entry['ip'],
											), admin_url( 'admin-post.php' ) ),
											'wpfh_sadm_unlock_action',
											'wpfh_sadm_unlock_nonce'
										);
										?>
										<tr>
											<td><code><?php echo esc_html( $entry['ip'] ); ?></code></td>
											<td><?php echo esc_html( $entry['username'] ); ?></td>
											<td><?php echo esc_html( date_i18n( 'Y-m-d H:i:s', $entry['time'] ) ); ?></td>
											<td>
												<?php if ( $is_active ) : ?>
													<span style="color: #ef4444; font-weight: 600;"><?php esc_html_e( 'Locked', 'forgehub-secure-admin' ); ?></span>
												<?php else : ?>
													<span style="color: #64748b;"><?php esc_html_e( 'Expired', 'forgehub-secure-admin' ); ?></span>
												<?php endif; ?>
											</td>
											<td>
												<?php if ( $is_active ) : ?>
													<a href="<?php echo esc_url( $unlock_url ); ?>" class="button button-small">
														<?php esc_html_e( 'Unlock IP', 'forgehub-secure-admin' ); ?>
													</a>
												<?php else : ?>
													&mdash;
												<?php endif; ?>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>

					<?php endif; ?>

					<?php if ( 'logs' !== $active_tab ) : ?>
						<p class="submit" style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #f1f5f9;">
							<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Save Security Settings', 'forgehub-secure-admin' ); ?>" />
						</p>
					<?php endif; ?>

				</div>
			</form>

			<?php if ( ! $is_pro ) : ?>
				<div style="margin-top: 30px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #ffffff; border-radius: 8px; padding: 24px 32px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
					<h3 style="color: #ffffff; margin-top: 0; font-size: 18px; font-weight: 600;">
						<?php esc_html_e( 'Upgrade to Secure Admin Guard Pro', 'forgehub-secure-admin' ); ?>
					</h3>
					<p style="color: #cbd5e1; font-size: 14px; line-height: 1.6; max-width: 720px; margin-bottom: 18px;">
						<?php esc_html_e( 'Unlock 2FA for all user roles (Editor, Shop Manager, Customer), 30-day trusted devices, 8 emergency recovery codes, idle admin session auto-logout, and instant login security alerts.', 'forgehub-secure-admin' ); ?>
					</p>
					<a href="https://wpforgehub.com/plugins/forgehub-secure-admin/" target="_blank" class="button button-primary" style="background: #ef4444; border-color: #dc2626; font-size: 14px; padding: 6px 18px; height: auto;">
						<?php esc_html_e( 'Get Pro Edition &rarr;', 'forgehub-secure-admin' ); ?>
					</a>
				</div>
			<?php endif; ?>

		</div>
		<?php
	}
}
