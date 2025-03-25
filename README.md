# 🛡️ Laravel Honeypot Security

> Advanced Laravel Middleware for Real-Time Web Threat Detection and Protection

---

## 🚀 Features

- ✅ DDoS, SQL Injection, XSS, RCE, SSRF Detection
- ✅ AI-Based Threat Classification (via FastAPI)
- ✅ Rate Limiting & Auto IP Banning
- ✅ User-Agent & Payload Anomaly Detection
- ✅ Slack / SMS / Email Alerts (Configurable)
- ✅ Interactive Dashboard with Charts
- ✅ CSV Export of Attack Logs
- ✅ Artisan Commands for Ban/Unban IPs
- ✅ Easy Setup & Configuration

---

## 📦 Installation

```bash
composer require jay123anta/honeypot
php artisan vendor:publish --tag=honeypot-security
php artisan migrate


# ⚙️ Configuration

All Honeypot behavior is managed via `config/honeypot.php`.

### Key Options:

```php
// Request Limits
'rate_limit_threshold' => 100,
'ddos_threshold_per_second' => 20,
'flood_threshold' => 30,

// Storage Options
'storage' => [
    'log_to_database' => true,
    'log_to_file' => true,
],

// IP Auto-Ban
'auto_ban' => [
    'enabled' => true,
    'ban_duration_minutes' => 60,
],

// Referrer Protection
'referrer_protection' => [
    'enabled' => false,
    'allowed_hosts' => ['yourdomain.com'],
],

// Activity Logging
'activity_log' => [
    'enabled' => false,
],

// AI Detection
'ai_detection' => [
    'enabled' => true,
    'ai_model_url' => 'http://localhost:8000/predict',
],

// Alerts
'alerts' => [
    'enable_slack' => true,
    'slack_webhook_url' => env('HONEYPOT_SLACK_WEBHOOK'),
    'enable_sms' => true,
    'sms_gateway_url' => env('HONEYPOT_SMS_GATEWAY'),
    'sms_to_number' => env('HONEYPOT_SMS_TO'),
],

// Custom Regex Rules (optional)
'custom_patterns' => [
    '/evilstring/i' => 'Custom Threat',
],

## You can also publish the config file and customize:

php artisan vendor:publish --tag=honeypot-security

# 🧰 Usage

You can apply the Honeypot middleware globally or to selected routes.

## Global Middleware (Kernel.php)

```php
protected $middleware = [
    \Security\Honeypot\Middleware\HoneypotMiddleware::class,
];

# 📊 Dashboard

The Honeypot Security dashboard provides a UI for monitoring attacks.

### Visit: /honeypot/dashboard


### Features:
- Table of detected attacks
- Charts:
  - Threat Trends
  - Top IPs
  - Attack Types
- Export CSV
- Date/Type/IP filters (coming soon)

You can customize the UI in: resources/views/vendor/honeypot/

