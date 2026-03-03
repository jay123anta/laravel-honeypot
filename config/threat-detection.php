<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Enable Threat Detection
    |--------------------------------------------------------------------------
    |
    | Enable or disable the threat detection system globally.
    |
    */
    'enabled' => env('THREAT_DETECTION_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Enabled Environments
    |--------------------------------------------------------------------------
    |
    | Specify which environments should have threat detection enabled.
    | Set to null or empty array to enable in all environments.
    |
    */
    'enabled_environments' => ['production', 'staging', 'local'],

    /*
    |--------------------------------------------------------------------------
    | Database Table Name
    |--------------------------------------------------------------------------
    |
    | The name of the table where threat logs will be stored.
    |
    */
    'table_name' => env('THREAT_DETECTION_TABLE', 'threat_logs'),

    /*
    |--------------------------------------------------------------------------
    | Home Country
    |--------------------------------------------------------------------------
    |
    | Your country's ISO 3166-1 alpha-2 code. Used by geo-enrichment to
    | flag foreign IPs. Change this to your country code (e.g., 'US', 'GB').
    |
    */
    'home_country' => env('THREAT_DETECTION_HOME_COUNTRY', 'IN'),

    /*
    |--------------------------------------------------------------------------
    | Skip Paths
    |--------------------------------------------------------------------------
    |
    | Paths that should be skipped from threat detection.
    | Supports wildcard patterns.
    |
    */
    'skip_paths' => [
        'public/assets/*',
        'public/images/*',
        'public/css/*',
        'public/js/*',
        'api/healthcheck',
        'favicon.ico',
    ],

    /*
    |--------------------------------------------------------------------------
    | Auth Paths
    |--------------------------------------------------------------------------
    |
    | Paths that need smart detection (allow legitimate credentials,
    | block actual attacks).
    |
    */
    'auth_paths' => [
        'login',
        'api/login',
        'auth/*',
        'api/auth/*',
        'oauth/*',
        'api/oauth/*',
        'register',
        'api/register',
        'password/*',
        'api/password/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Whitelisted IPs
    |--------------------------------------------------------------------------
    |
    | IPs that should be excluded from threat detection.
    | Supports CIDR notation.
    |
    */
    'whitelisted_ips' => array_filter(explode(',', env('THREAT_DETECTION_WHITELISTED_IPS', ''))),

    /*
    |--------------------------------------------------------------------------
    | Offense Settings
    |--------------------------------------------------------------------------
    |
    | Configure blocking behavior for repeat offenders.
    |
    */
    'max_offenses' => env('THREAT_DETECTION_MAX_OFFENSES', 5),
    'block_duration' => env('THREAT_DETECTION_BLOCK_DURATION', 60),
    'block_response' => env('THREAT_DETECTION_BLOCK_RESPONSE', 'default'),
    'redirect_url' => env('THREAT_DETECTION_REDIRECT_URL', null),

    /*
    |--------------------------------------------------------------------------
    | Actions by Threat Level
    |--------------------------------------------------------------------------
    |
    | Define what action to take for each threat level.
    | Options: 'log', 'block', 'notify'
    |
    */
    'actions' => [
        'high' => env('THREAT_DETECTION_HIGH_ACTION', 'block'),
        'medium' => env('THREAT_DETECTION_MEDIUM_ACTION', 'log'),
        'low' => env('THREAT_DETECTION_LOW_ACTION', 'log'),
    ],

    /*
    |--------------------------------------------------------------------------
    | DDoS Protection
    |--------------------------------------------------------------------------
    |
    | Configure DDoS detection thresholds.
    |
    */
    'ddos' => [
        'threshold' => env('THREAT_DETECTION_DDOS_THRESHOLD', 300),
        'window' => env('THREAT_DETECTION_DDOS_WINDOW', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limiting thresholds.
    |
    */
    'rate_limiting' => [
        'global' => [
            'limit' => env('THREAT_DETECTION_RATE_LIMIT_GLOBAL', 60),
            'period' => env('THREAT_DETECTION_RATE_PERIOD_GLOBAL', 60),
        ],
        'per_url' => [
            'limit' => env('THREAT_DETECTION_RATE_LIMIT_URL', 30),
            'period' => env('THREAT_DETECTION_RATE_PERIOD_URL', 60),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Threat Levels
    |--------------------------------------------------------------------------
    |
    | Map keywords to threat severity levels.
    |
    */
    'threat_levels' => [
        'high' => ['XSS', 'SQL Injection', 'RCE', 'Aadhaar', 'PAN', 'Bank', 'Token', 'Password', 'JWT', 'Deserialization', 'Metadata Access'],
        'medium' => ['Directory Traversal', 'LFI', 'SSRF', 'Sensitive', 'Config', 'Session', 'Command Chain', 'Recon Tool', 'Raw PHP'],
        'low' => ['User-Agent', 'JS Redirect', 'SEO Bot', 'Empty', 'Rate', 'Command-line Downloader'],
    ],

    /*
    |--------------------------------------------------------------------------
    | API Route Filtering
    |--------------------------------------------------------------------------
    |
    | Configure filtering behavior for API routes.
    |
    */
    'api_route_filtering' => [
        'enabled' => true,
        'suppress_levels' => ['low', 'medium'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Notifications
    |--------------------------------------------------------------------------
    |
    | Configure notification channels for threat alerts.
    |
    */
    'notifications' => [
        'enabled' => env('THREAT_DETECTION_NOTIFICATIONS', false),
        'email' => env('THREAT_DETECTION_NOTIFICATION_EMAIL', ''),
        'slack_channel' => env('THREAT_DETECTION_SLACK_CHANNEL', '#threat-alerts'),
        'slack_webhook' => env('THREAT_DETECTION_SLACK_WEBHOOK', ''),
        'slack_username' => env('THREAT_DETECTION_SLACK_USERNAME', 'ThreatBot'),
        'notify_levels' => ['high'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Patterns
    |--------------------------------------------------------------------------
    |
    | Add your own regex patterns for threat detection.
    | Format: 'regex_pattern' => 'Threat Label'
    |
    */
    'custom_patterns' => [

        // Regional PII Detection (India) — remove or replace with your region's patterns
        '/\b\d{12}\b(?!\s*\d)/' => 'Aadhaar Number Detected',
        '/\b[A-Z]{5}[0-9]{4}[A-Z]\b/' => 'PAN Number Detected',
        '/\b[6-9]\d{9}\b/' => 'Mobile Number Detected',
        '/\b\d{9,18}\b(?!\s*\d)/' => 'Bank Account Number Detected',
        '/\b[A-Z]{4}0[A-Z0-9]{6}\b/' => 'IFSC Code Detected',

        // Credential & Token Leaks
        '/access[_-]?token\s*=\s*["\']?[A-Za-z0-9\-_\.=]{32,}/i' => 'Access Token Leak',
        '/session[_-]?id\s*=\s*["\']?[A-Za-z0-9\-]{20,}/i' => 'Session ID Leak',
        '/\bpassword\s*=\s*["\']?.{8,40}["\']?/i' => 'Password Exposure',
        '/api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9\-_]{20,}/i' => 'API Key Exposure',
        '/bearer\s+[A-Za-z0-9\-_\.]{20,}/i' => 'Bearer Token Detected',

        // Sensitive File Access
        '/config\.(json|php|env)/i' => 'Sensitive Config File Access',
        '/\.env(\.|$)/i' => 'Environment File Access',
        '/composer\.(json|lock)/i' => 'Composer File Access',
        '/package(-lock)?\.json/i' => 'Package File Access',
        '/\.git(\/|\\\\)/i' => 'Git Directory Access Attempt',
        '/\.ssh(\/|\\\\)/i' => 'SSH Directory Access Attempt',
        '/\.aws(\/|\\\\)credentials/i' => 'AWS Credentials Access',
        '/web\.config|\.htaccess/i' => 'Server Config Access',
        '/phpinfo\(/i' => 'PHPInfo Function Call',

        // Path Traversal & Admin Access
        '/\/admin\b(?![-\/])/i' => 'Admin Path Access Attempt',
        '/\/internal\b/i' => 'Internal Endpoint Probe',
        '/\/legacy\b/i' => 'Legacy System Access',
        '/\/backup\b/i' => 'Backup Directory Probe',
        '/\/test\b/i' => 'Test Endpoint Probe',
        '/\/debug\b/i' => 'Debug Endpoint Probe',
        '/\/console\b/i' => 'Console Access Attempt',

        // XSS Variants
        '/%3Cscript%3E/i' => 'Encoded XSS Detected',
        '/document\.location\s*=\s*["\']?.+/i' => 'JS Redirect',
        '/(fromCharCode|decodeURI|atob)\s*\(/i' => 'Obfuscated JS',
        '/<iframe\b[^>]*>/i' => 'Iframe Injection',
        '/<embed\b[^>]*>/i' => 'Embed Tag Injection',
        '/<object\b[^>]*>/i' => 'Object Tag Injection',
        '/\bonfocus\s*=/i' => 'OnFocus Event Handler',
        '/\bonerror\s*=/i' => 'OnError Event Handler',

        // Code Injection
        '/<\?php/i' => 'Raw PHP Code Detected',
        '/\{\{[^}]+\}\}/' => 'Blade/Liquid Template Injection',
        '/<%(=)?\s*.+\s*%>/s' => 'JSP/ASP Template Injection',
        '/\$\{[^}]+\}/i' => 'Expression Language Injection',

        // XXE (XML External Entity)
        '/<!ENTITY/i' => 'XXE Entity Declaration',
        '/<!DOCTYPE.*ENTITY/is' => 'XXE DOCTYPE Attack',

        // Log4j / Log4Shell
        '/\$\{jndi:(ldap|rmi|dns):\/\//i' => 'Log4j/Log4Shell Attack',
        '/\$\{jndi:/i' => 'JNDI Injection Attempt',

        // SSRF & DNS Rebinding
        '/(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)(:\d+)?\b/i' => 'Localhost SSRF',
        '/169\.254\.169\.254/i' => 'AWS Metadata SSRF',
        '/metadata\.google\.internal/i' => 'GCP Metadata SSRF',
        '/(10|172\.16|192\.168)\.\d+\.\d+/i' => 'Private IP Access',

        // SQL Injection Variants
        '/\b(select|union|drop)\b\s+\*?\s*\bfrom\b\s+\w+/i' => 'SQLi Variant',
        '/\bwaitfor\s+delay\b/i' => 'SQL Time-based Blind',
        '/\bbenchmark\s*\(/i' => 'SQL Benchmark Attack',
        '/\bsleep\s*\(/i' => 'SQL Sleep Attack',
        '/\bconcat\s*\(/i' => 'SQL Concat Function',

        // NoSQL Injection
        '/\$ne\s*:|[\[\{]\s*\$ne\s*:/i' => 'NoSQL $ne Injection',
        '/\$gt\s*:|[\[\{]\s*\$gt\s*:/i' => 'NoSQL $gt Injection',
        '/\$regex\s*:/i' => 'NoSQL Regex Injection',
        '/\$where\s*:/i' => 'NoSQL $where Injection',

        // Command Injection
        '/\bcurl\s+["\']?https?:\/\//i' => 'Command Line Tool (curl)',
        '/\bwget\s+["\']?https?:\/\//i' => 'Command Line Tool (wget)',
        '/\bnc\s+-/i' => 'Netcat Usage',
        '/\/bin\/(bash|sh|zsh)/i' => 'Shell Execution Attempt',
        '/\bchmod\s+777/i' => 'Dangerous Permission Change',

        // Debug & Dev Tools
        '/--inspect\b/i' => 'Node.js Debug Mode',
        '/PHPSESSID=[a-zA-Z0-9]{10,}/i' => 'PHP Session Exposure',
        '/XDEBUG_SESSION/i' => 'XDebug Session',
        '/\btrace[_-]?id\b/i' => 'Trace ID Exposure',

        // API Abuse
        '/\b(v1|v2|v3)\/users\/\d+/i' => 'API User Enumeration',
        '/\/api\/.*\?.*limit=\d{3,}/i' => 'API High Limit Request',
        '/\/graphql.*\{.*\}/is' => 'GraphQL Query Detected',

        // IDOR (Insecure Direct Object Reference)
        '/\/user(s)?\/\d+\/delete/i' => 'User Deletion Attempt',
        '/\/admin\/\d+/i' => 'Admin ID Enumeration',

        // Malware & Web Shells
        '/c99|r57|b374k|wso|c100/i' => 'Web Shell Signature',
        '/FilesMan/i' => 'File Manager Shell',
        '/eval\s*\(\s*base64_decode/i' => 'Encoded Eval Execution',

        // Bot & Scanner Detection
        '/\b(sqlmap|havij|acunetix|netsparker|appscan|burp)/i' => 'Security Scanner Detected',
        '/\b(masscan|zmap)\b/i' => 'Port Scanner',
        '/(python-requests|go-http-client)/i' => 'Scripted Request',

        // Crypto Mining
        '/coinhive|cryptonight|monero/i' => 'Crypto Mining Script',

        // Reverse Shell
        '/bash\s+-i\s*>|\/dev\/tcp/i' => 'Reverse Shell Attempt',
        '/nc\s+-e\s+\/bin/i' => 'Netcat Reverse Shell',
    ],

    /*
    |--------------------------------------------------------------------------
    | Honeypot Fields
    |--------------------------------------------------------------------------
    |
    | Configure hidden form fields to detect bots.
    |
    */
    'honeypot_fields' => [
        'enabled' => true,
        'field_name' => 'website_url',
        'field_time' => 'completion_time',
        'min_submit_time' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | Web Dashboard
    |--------------------------------------------------------------------------
    |
    | Enable built-in web dashboard for viewing threat logs.
    |
    */
    'dashboard' => [
        'enabled' => env('THREAT_DETECTION_DASHBOARD', false),
        'path' => env('THREAT_DETECTION_DASHBOARD_PATH', 'threat-detection'),
        'middleware' => ['web', 'auth'],
    ],

    /*
    |--------------------------------------------------------------------------
    | API Routes
    |--------------------------------------------------------------------------
    |
    | Configure API routes for threat data.
    | WARNING: These routes expose sensitive security data. Always use
    | authentication middleware in production. The default includes 'auth:sanctum'.
    | Change to ['api', 'auth'] or your own guard as needed.
    |
    */
    'api' => [
        'enabled' => env('THREAT_DETECTION_API', true),
        'prefix' => env('THREAT_DETECTION_API_PREFIX', 'api/threat-detection'),
        'middleware' => ['api', 'auth:sanctum'],
    ],

];
