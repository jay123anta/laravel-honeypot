<?php

namespace Security\Honeypot\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Security\Honeypot\Models\AttackLog;

class HoneypotService
{
    public function logAndBlock(Request $request, string $threatType): void
    {
        $ip = $request->ip();
        $url = $request->fullUrl();
        $userAgent = $request->userAgent();
        $payload = json_encode($request->all());

        $logData = [
            'ip_address' => $ip,
            'url' => $url,
            'type' => $threatType,
            'user_agent' => $userAgent,
            'payload' => $payload,
        ];

        // 🔍 Log to file if enabled
        if (config('honeypot.storage.log_to_file', true)) {
            Log::warning('🛡️ Honeypot Threat Detected', $logData);
        }

        // 💾 Log to database if enabled
        if (config('honeypot.storage.log_to_database', true)) {
            AttackLog::create($logData);
        }

        // 🚫 Auto-ban IP if enabled
        if (config('honeypot.auto_ban.enabled', true)) {
            $banDuration = config('honeypot.auto_ban.ban_duration_minutes', 60);
            Cache::put("banned_ip_{$ip}", true, now()->addMinutes($banDuration));
        }

        // 📢 Send Alerts
        $this->sendSlackAlert($logData);
        $this->sendSmsAlert($ip, $threatType);
    }

    // 📢 Slack Notification
    protected function sendSlackAlert(array $logData): void
    {
        if (!config('honeypot.alerts.enable_slack', false)) {
            return;
        }

        $webhook = config('honeypot.alerts.slack_webhook_url');
        if (!$webhook) {
            Log::warning('🚫 Slack webhook URL not configured.');
            return;
        }

        try {
            Http::post($webhook, [
                'text' => "⚠️ Honeypot Alert!\nThreat: {$logData['type']}\nIP: {$logData['ip_address']}\nURL: {$logData['url']}",
            ]);
        } catch (\Exception $e) {
            Log::error('❌ Failed to send Slack alert: ' . $e->getMessage());
        }
    }

    // 📲 SMS Notification
    protected function sendSmsAlert(string $ip, string $threatType): void
    {
        if (!config('honeypot.alerts.enable_sms', false)) {
            return;
        }

        $gatewayUrl = config('honeypot.alerts.sms_gateway_url');
        $toNumber = config('honeypot.alerts.sms_to_number');

        if (!$gatewayUrl || !$toNumber) {
            Log::warning('🚫 SMS gateway URL or recipient number not configured.');
            return;
        }

        try {
            Http::get($gatewayUrl, [
                'to' => $toNumber,
                'message' => "⚠️ Honeypot Alert\nIP: $ip\nThreat: $threatType",
            ]);
        } catch (\Exception $e) {
            Log::error('❌ Failed to send SMS alert: ' . $e->getMessage());
        }
    }
}
