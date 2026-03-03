<p align="center">
  <img src="https://img.shields.io/packagist/v/jayanta/laravel-threat-detection.svg?style=flat-square" alt="Latest Version">
  <img src="https://img.shields.io/github/actions/workflow/status/jay123anta/laravel-honeypot/tests.yml?branch=main&style=flat-square&label=tests" alt="Tests">
  <img src="https://img.shields.io/packagist/dt/jayanta/laravel-threat-detection.svg?style=flat-square" alt="Total Downloads">
  <img src="https://img.shields.io/packagist/l/jayanta/laravel-threat-detection.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/php-version-support/jayanta/laravel-threat-detection?style=flat-square" alt="PHP Version">
</p>

# Laravel Threat Detection

**Know who's attacking your Laravel app — without changing a single line of code.**

A zero-config, middleware-based Web Application Firewall (WAF) for Laravel. Drop it in, and it instantly starts detecting SQL injection, XSS, RCE, scanner bots, DDoS patterns, and 40+ other attack types — logging everything to your database with full geo-enrichment and a built-in dark-mode dashboard.

> Extracted from a production application. Battle-tested with real traffic.

---

## Why This Package?

| Problem | Solution |
|---------|----------|
| Laravel has no built-in request-level threat detection | This package scans every request through 100+ regex patterns |
| External WAF services cost money and add latency | Runs entirely within your app — zero external dependencies |
| Security logs are scattered across server files | Centralized database logging with API + dashboard |
| You don't know who's probing your app right now | Real-time Slack alerts + live threat count endpoint |

---

## Dashboard Preview

The package ships with a built-in dark-mode dashboard (Alpine.js + Tailwind CDN — zero build step):

<!-- Replace this with an actual screenshot of your dashboard -->
<!-- Take a screenshot at /threat-detection when you have some threat data -->

```
+------------------------------------------------------------------+
|  Threat Detection Dashboard                                       |
+------------------------------------------------------------------+
|  Total: 847  |  High: 23  |  Med: 156  |  Low: 668  |  IPs: 94  |
+------------------------------------------------------------------+
|  [████████ Timeline Chart - 7 Day Stacked Bar ████████]          |
+------------------------------------------------------------------+
|  Search: [___________]  Level: [All ▼]                           |
|  Time         IP              Type              Level    URL      |
|  Mar 2 14:02  185.220.101.4   SQL Injection     HIGH    /api/... |
|  Mar 2 13:58  45.33.32.156    XSS Script Tag    HIGH    /search  |
|  Mar 2 13:45  192.168.1.10    Scanner: Nikto    MEDIUM  /admin   |
+------------------------------------------------------------------+
|  Top IPs              |  Threats by Country                       |
|  185.220.101.4  [23]  |  US ████████████ 234                     |
|  45.33.32.156   [18]  |  CN ████████ 156                         |
|  103.152.220.1  [12]  |  RU ██████ 98                            |
+------------------------------------------------------------------+
```

> Enable with `THREAT_DETECTION_DASHBOARD=true` in your `.env`

---

## Quick Start

```bash
# Install
composer require jayanta/laravel-threat-detection

# Publish & migrate
php artisan vendor:publish --tag=threat-detection-config
php artisan vendor:publish --tag=threat-detection-migrations
php artisan migrate
```

Register the middleware:

**Laravel 11+ (bootstrap/app.php):**
```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        \JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware::class,
    ]);
})
```

**Laravel 10 (app/Http/Kernel.php):**
```php
protected $middlewareGroups = [
    'web' => [
        // ... other middleware
        \JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware::class,
    ],
];
```

**That's it.** Your app is now detecting threats.

---

## Features

- **40+ Attack Patterns** — SQL injection, XSS, RCE, directory traversal, SSRF, XXE, Log4Shell, and more
- **Scanner Detection** — SQLMap, Nikto, Nmap, Burp Suite, Acunetix, WPScan, Dirbuster
- **Bot Detection** — Suspicious user agents, automated scripts, headless browsers
- **DDoS Monitoring** — Rate-based threshold detection with configurable windows
- **PII Detection** — Sensitive data exposure patterns (configurable per region)
- **Geo-Enrichment** — Country, city, ISP, cloud provider identification via free API
- **Slack Alerts** — Real-time notifications for high-severity threats
- **Built-in Dashboard** — Dark-mode Blade dashboard (Alpine.js + Tailwind CDN)
- **12 API Endpoints** — Full REST API for custom Vue/React/mobile dashboards
- **CSV Export** — One-click threat log export
- **Correlation Analysis** — Detect coordinated attacks and attack campaigns
- **Database Agnostic** — MySQL, PostgreSQL, SQLite, SQL Server
- **Zero Config** — Works out of the box with sensible defaults

---

## Configuration

Add to your `.env` file:

```env
# Core
THREAT_DETECTION_ENABLED=true

# Whitelist IPs (comma-separated, supports CIDR)
THREAT_DETECTION_WHITELISTED_IPS=127.0.0.1,10.0.0.0/8

# DDoS thresholds
THREAT_DETECTION_DDOS_THRESHOLD=300
THREAT_DETECTION_DDOS_WINDOW=60

# Notifications
THREAT_DETECTION_NOTIFICATIONS=true
THREAT_DETECTION_SLACK_WEBHOOK=https://hooks.slack.com/services/...
THREAT_DETECTION_SLACK_CHANNEL=#threat-alerts

# API & Dashboard
THREAT_DETECTION_API=true
THREAT_DETECTION_DASHBOARD=true
```

### Slack Notifications (Laravel 11+)

Laravel 11 removed the built-in Slack channel. Install separately:

```bash
composer require laravel/slack-notification-channel
```

### Environment Note

By default, detection runs in `production`, `staging`, and `local`. Change in your published config:

```php
'enabled_environments' => ['production', 'staging', 'local'],
```

---

## API Endpoints

The package provides 12 authenticated REST endpoints for building custom dashboards.

> **Security:** API routes use `auth:sanctum` middleware by default. Update `api.middleware` in your config to change.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threat-detection/threats` | List threats (paginated, filterable) |
| GET | `/api/threat-detection/threats/{id}` | Single threat details |
| GET | `/api/threat-detection/stats` | Overall statistics |
| GET | `/api/threat-detection/summary` | Detailed breakdown by type, level, IP |
| GET | `/api/threat-detection/live-count` | Threats in last hour |
| GET | `/api/threat-detection/by-country` | Grouped by country |
| GET | `/api/threat-detection/by-cloud-provider` | Grouped by cloud provider |
| GET | `/api/threat-detection/top-ips` | Top offending IPs |
| GET | `/api/threat-detection/timeline` | Threat timeline (for charts) |
| GET | `/api/threat-detection/ip-stats?ip=x.x.x.x` | Stats for specific IP |
| GET | `/api/threat-detection/correlation` | Correlation analysis |
| GET | `/api/threat-detection/export` | Export to CSV |

### Query Parameters for `/threats`

| Parameter | Description |
|-----------|-------------|
| `keyword` | Search in IP, URL, type |
| `ip` | Filter by IP address |
| `level` | Filter by threat level (high, medium, low) |
| `type` | Filter by threat type |
| `country` | Filter by country code |
| `is_foreign` | Filter foreign IPs (true/false) |
| `cloud_provider` | Filter by cloud provider |
| `date_from` / `date_to` | Date range |
| `per_page` | Items per page (default: 20) |

---

## Artisan Commands

```bash
# View threat stats in CLI
php artisan threat-detection:stats

# Enrich logs with geo-data
php artisan threat-detection:enrich --days=7

# Purge old logs
php artisan threat-detection:purge --days=30
```

---

## Using the Facade

```php
use JayAnta\ThreatDetection\Facades\ThreatDetection;

// Get IP statistics
$stats = ThreatDetection::getIpStatistics('192.168.1.1');

// Detect coordinated attacks
$attacks = ThreatDetection::detectCoordinatedAttacks(15, 3);

// Detect attack campaigns
$campaigns = ThreatDetection::detectAttackCampaigns(24);

// Get correlation summary
$summary = ThreatDetection::getCorrelationSummary();
```

---

## Custom Patterns

Add your own detection patterns in `config/threat-detection.php`:

```php
'custom_patterns' => [
    '/your-regex-pattern/i' => 'Your Threat Label',
    '/another-pattern/' => 'Another Threat',
],
```

Configure threat level mappings:

```php
'threat_levels' => [
    'high' => ['XSS', 'SQL Injection', 'RCE', 'Token', 'Password'],
    'medium' => ['Directory Traversal', 'LFI', 'SSRF', 'Config'],
    'low' => ['User-Agent', 'Bot', 'Rate'],
],
```

---

## Building Custom Frontends

### Vue.js

```javascript
async mounted() {
    const response = await fetch('/api/threat-detection/stats');
    this.stats = await response.json();

    const threats = await fetch('/api/threat-detection/threats?per_page=20');
    this.threats = await threats.json();
}
```

### React

```jsx
useEffect(() => {
    fetch('/api/threat-detection/stats')
        .then(res => res.json())
        .then(data => setStats(data));
}, []);
```

---

## Detected Attack Types

| Category | Examples |
|----------|---------|
| **Injection** | SQL injection, NoSQL injection, command injection, LDAP injection |
| **XSS** | Script tags, event handlers, JavaScript URIs, DOM manipulation |
| **Code Execution** | RCE, PHP deserialization, template injection, eval() |
| **File Access** | Directory traversal, LFI/RFI, sensitive file probes (.env, wp-config) |
| **SSRF** | Localhost access, AWS/GCP metadata endpoints |
| **Authentication** | Brute force detection, token leaks, password exposure |
| **Scanners** | SQLMap, Nikto, Nmap, Burp Suite, Acunetix, WPScan |
| **Bots** | Automated scripts, suspicious user agents, headless browsers |
| **DDoS** | Rate-based excessive request detection |
| **XXE** | XML external entity attacks |
| **Log4Shell** | JNDI injection attempts |

---

## Geo-Enrichment

Enrich threat logs with country, city, ISP, and cloud provider data:

```bash
php artisan threat-detection:enrich --days=7
```

Uses the free [ip-api.com](http://ip-api.com) service (HTTP, rate-limited to 45 req/min — auto-throttled).

---

## Testing

```bash
composer test
```

The package includes 19 tests covering service detection, middleware behavior, and API endpoints.

---

## Requirements

- PHP 8.1+
- Laravel 10.x, 11.x, or 12.x

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please submit a Pull Request.

## Credits

- [Jay Anta](https://github.com/jay123anta)
