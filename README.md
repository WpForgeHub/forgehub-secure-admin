# ForgeHub Secure Admin Guard

![Secure Admin Guard](assets/banner-1544x500.png)

[![Version](https://img.shields.io/badge/Version-1.3.1-blue.svg)](https://wpforgehub.com/plugins/forgehub-secure-admin/)
[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%20or%20later-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4.svg)](https://php.net/)
[![Freemius](https://img.shields.io/badge/Freemius-SDK%20Ready-orange.svg)](https://freemius.com/)
[![Zero Bloat](https://img.shields.io/badge/Zero-Server%20Bloat-success.svg)](https://wpforgehub.com/)
[![WCAG 2.1](https://img.shields.io/badge/WCAG-2.1%20AA-brightgreen.svg)](https://wpforgehub.com/)
[![Security](https://img.shields.io/badge/Security-Admin%20Guard-red.svg)](https://wpforgehub.com/)

**Secure Admin Guard** (v1.3.1) provides lightweight, high-performance administrative protection and authentication hardening for WordPress websites.

---

## ⚡ Key Highlights

* **Brute Force Defense**: Rate-limits failed login attempts per IP address, stopping automated credential stuffing bots.
* **Email Two-Factor Authentication (OTP)**: Dispatches secure 6-digit one-time passcodes to administrative users upon password validation.
* **Zero-JS Honeypot**: Invisible login trap that blocks spam bots without server strain.
* **Lightweight Math CAPTCHA**: Zero-JS, replay-proof arithmetic security check on `wp-login.php` (enabled by default).
* **Clear Lockout Feedback & Opt-In Login Badge**: Proactive lockout notices on `wp-login.php`, active lockout summary in wp-admin, and an optional "Protected by ForgeHub Secure Admin" login badge.
* **Lost Password Protection**: Rate limiter on password resets prevents email flood attacks.
* **Default Admin Account Detector**: Real-time admin notices warning when an insecure 'admin' user has Administrator capabilities.
* **Login Activity Log**: Circular buffer tracking recent logins (100 in Free, full CSV export and audit in Pro).
* **WordPress Hardening**: Disables `xmlrpc.php`, neutralizes author query user enumeration (`/?author=1`), and masks login failure messages.
* **Hide Login URL**: Custom login slug; `/wp-login.php` and `/wp-admin` return 404 for guests.
* **Security Headers & File Editor Lock**: One-click header hardening and disabled theme/plugin editors.
* **Zero Server Bloat**: Built cleanly with native WordPress hooks and transients—no background daemons, external telemetry, or unnecessary database bloat.

---

## 🛡️ Free vs Pro Feature Comparison

| Feature | Free Edition | Pro Edition |
| :--- | :---: | :---: |
| **Brute Force Rate Limiting** | ✅ | ✅ |
| **Configurable Lockout Window** | ✅ | ✅ |
| **Trusted IP Whitelist** | ✅ | ✅ |
| **Email 2FA OTP for Administrators** | ✅ | ✅ |
| **Zero-JS Honeypot Protection** | ✅ | ✅ |
| **Lost Password Rate Limiter** | ✅ | ✅ |
| **Default Admin Username Detector** | ✅ | ✅ |
| **Login Activity Log** | ✅ (100 entries) | ✅ (Full) |
| **Activity Log CSV Export & IP Blacklist Audit** | ❌ | ✅ |
| **Generic Login Error Masking** | ✅ | ✅ |
| **XML-RPC Pingback & Attack Blocker** | ✅ | ✅ |
| **Author Query Enumeration Blocker** | ✅ | ✅ |
| **WordPress Version Obfuscation** | ✅ | ✅ |
| **Multi-Role 2FA (Editor, Author, Shop Manager)** | ❌ | ✅ |
| **Trusted Devices (Remember for 30 Days)** | ❌ | ✅ |
| **8 Emergency Backup Recovery Codes** | ❌ | ✅ |
| **Idle Admin Session Auto-Logout** | ❌ | ✅ |
| **Lockout Activity Audit & 1-Click Unlock** | ❌ | ✅ |
| **Instant Admin Login Security Alerts** | ❌ | ✅ |

---

## 🔧 Installation

1. Upload the `forgehub-secure-admin` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **Settings &rarr; Secure Admin** to configure your security preferences.

---

## 📄 License

GPLv2 or later &copy; [WPForgeHub](https://wpforgehub.com).
