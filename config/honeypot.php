<?php

return [

    // 📊 Rate Limiting Configuration
    'rate_limit_threshold' => 100, // Max requests per minute per IP
    'ddos_threshold_per_second' => 20, // Max requests per second
    'flood_threshold' => 30, // Max hits to same endpoint in 10s

    // 🚨 Alerts Configuration
    'alerts' => [
        'enable_slack' => env('HONEYPOT_ENABLE_SLACK', false),
        'slack_webhook_url' => env('HONEYPOT_SLACK_WEBHOOK'),

        'enable_sms' => env('HONEYPOT_ENABLE_SMS', false),
        'sms_gateway_url' => env('HONEYPOT_SMS_GATEWAY'),
        'sms_to_number' => env('HONEYPOT_SMS_TO'),
    ],

    // 🤖 AI-Based Threat Detection
    'ai_detection' => [
        'enabled' => env('HONEYPOT_AI_ENABLED', false),
        'ai_model_url' => env('HONEYPOT_AI_MODEL_URL'), // FastAPI/ML endpoint
    ],

    // 🗄️ Storage Settings
    'storage' => [
        'log_to_database' => true,      // Store threats in DB (default true)
        'log_to_file' => true,          // Log threats to laravel.log (default true)
    ],

    // 🚫 Auto-Ban Settings
    'auto_ban' => [
        'enabled' => true,
        'ban_duration_minutes' => 60,   // Temporary ban duration
    ],

    // 🔔 Notification Roles (RBAC integration)
    'notify_roles' => ['security-admin', 'super-admin'],

    // 🌐 Multi-Tenant Support (optional)
    'multi_tenant' => [
        'enabled' => false,
        'tenant_id_column' => 'tenant_id',
    ],
];
