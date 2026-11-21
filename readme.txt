=== ForgeHub Secure Admin Guard ===
Contributors: wpforgehub
Tags: security, brute force, login, two factor, 2fa
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Zero-bloat login security with brute force rate limiting, email OTP two-factor authentication, and WordPress hardening.

== Description ==

**Secure Admin Guard** provides lightweight, zero-bloat protection for your WordPress administration area and user login flow.

Engineered with performance and strict security in mind, Secure Admin Guard prevents automated brute-force password guessing, introduces native email-based OTP two-factor authentication, and eliminates common reconnaissance vectors used by bad bots.

### 🛡️ Core Features (Free)

* **Brute Force Rate Limiting**: Restrict repeated failed login attempts from malicious IP addresses. Configurable attempt limits and lockout windows.
* **Email Two-Factor Authentication (OTP)**: Native 6-digit one-time passcodes dispatched via email to Administrator accounts upon password verification.
* **Zero-JS Honeypot**: Invisible honeypot trap on login form that instantly aborts bot submissions without password processing.
* **Lost Password Rate Limiter**: Rate-limits password reset requests to stop bot flood and username enumeration.
* **Default Admin Detector**: Security warning notice if an insecure default "admin" account exists with administrator capabilities.
* **Login Activity Log**: Circular buffer tracking the last 100 login attempts (success, failed, and locked out).
* **IP Whitelist**: Safeguard your own IP address from accidental lockouts.
* **Generic Login Errors**: Prevent username enumeration by masking detailed error messages on failed logins.
* **XML-RPC Blocker**: Completely deactivate `xmlrpc.php` to neutralize amplification attacks and brute-force backdoors.
* **Author Query Protection**: Block `/?author=N` scans that bots use to discover administrative usernames.
* **Version Obfuscation**: Remove WordPress version generator meta tags from HTML heads and feeds.
* **Hide Login URL**: Serve the login form only at your own secret slug; guests get a 404 on `/wp-login.php` and `/wp-admin` (AJAX, cron and REST keep working).
* **Security Headers**: Optional X-Frame-Options, X-Content-Type-Options and Referrer-Policy headers.
* **Disable File Editor**: Turn off the theme and plugin code editors in wp-admin.
* **Zero Bloat & Lightweight**: Operates on native WordPress hooks and transients with zero third-party cloud dependencies.

### 🚀 Premium Features (Pro)

* **Multi-Role 2FA**: Extend email two-factor authentication to Editors, Authors, Shop Managers, and Customers.
* **Trusted Devices (30 Days)**: Allow verified users to trust their personal browser for 30 days via cryptographically signed tokens.
* **Emergency Recovery Codes**: Generate 8 single-use emergency backup codes to ensure you never get locked out if email is unavailable.
* **Idle Session Auto-Logout**: Automatically terminate unattended administrative sessions after a configurable period of inactivity.
* **Lockout Activity Audit**: Comprehensive log of locked-out IP addresses, timestamps, and failed attempts with one-click manual unlock.
* **Activity Log CSV Export & IP Blacklist Audit**: Export full login activity histories to CSV and dispatch IP blacklist actions.
* **Bad Bot Blocker**: Block known malicious scanner and scraper User-Agents, with your own custom list.
* **Instant Admin Login Alerts**: Receive real-time security email alerts whenever an administrator successfully authenticates.

== Frequently Asked Questions ==

= How does the Email 2FA OTP work? =
When an administrator logs in with the correct username and password, the login is temporarily held in a pending state. A cryptographically random 6-digit code is generated and emailed to the account's registered address. Entering the correct code completes the authentication.

= Will I be locked out if I enter the wrong password? =
By default, you are allowed up to 5 failed attempts before a 15-minute temporary lockout is enforced. You can whitelist your IP address in the settings to ensure you are never locked out.

= What happens if email delivery is delayed? =
The 2FA code is valid for 10 minutes. If needed, a "Resend Code" button is available on the verification screen. Pro users also have emergency backup codes.

= Does this plugin slow down my site? =
No. Secure Admin Guard is built according to the WPForgeHub Zero-Bloat standard. It uses native transients and standard WordPress hooks, with zero external API calls or heavyweight database tables.

== Screenshots ==

1. Secure Admin Guard main settings dashboard with Brute Force, Two-Factor Authentication, and Hardening controls.

== Changelog ==

= 1.2.1 =
* Fix 2FA lockout bug, tab settings wipe, IP spoofing, Hide Login safety, and Pro recovery/blacklist/idle/CSV issues.

= 1.2.0 =
* New: Zero-JS Honeypot on login form rejecting bot logins without processing password.
* New: Lost password rate limiter on lostpassword_post to prevent password reset bot spam.
* New: Default admin username detector warning when 'admin' account has administrator capabilities.
* New: Login Activity Log tracking successful logins, failed attempts, and lockouts (circular buffer 100 entries in Free, CSV export and audit in Pro).

= 1.1.1 =
* Rename: plugin is now "ForgeHub Secure Admin Guard" (ForgeHub naming standard).
* Fix: Plugins screen now shows a consistent "Settings" link.
= 1.1.0 =
* New: Hide Login URL with custom slug.
* New: Security headers toggle.
* New: Disable theme/plugin file editor toggle.
* New (Pro): Bad bot User-Agent blocker.

= 1.0.0 =
* Initial public release with Brute Force Limiter, Email 2FA OTP, and WordPress Hardening suite.
