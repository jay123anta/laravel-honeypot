<?php

namespace Security\Honeypot\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use Security\Honeypot\Services\HoneypotService;

class HoneypotMiddleware
{
    protected $honeypotService;

    public function __construct(HoneypotService $honeypotService)
    {
        $this->honeypotService = $honeypotService;
    }

    public function handle(Request $request, Closure $next)
    {
        Log::info('🔍 Honeypot Middleware Active', ['payload' => $request->all()]);

        $ip = $request->ip();
        $payload = json_encode($request->all());
        $endpoint = $request->path();
        $userAgent = $request->userAgent();
        $url = $request->fullUrl();

        // 1️⃣ ⛔ IP Ban Check
        if (Cache::has("banned_ip_{$ip}")) {
            $this->logThreat($ip, $url, $userAgent, 'Banned IP Access', $payload, 'high', 'blocked');
            return response('Access denied: Suspicious activity detected.', 403);
        }

        // 2️⃣ Sensitive File Access Protection
        $sensitivePaths = ['.env', '.git', 'composer.lock', 'server.php'];
        foreach ($sensitivePaths as $path) {
            if (str_contains($endpoint, $path)) {
                return $this->logAndBan($request, 'Sensitive File Access Attempt', 'high');
            }
        }

        // 3️⃣ Header Injection Detection
        $headers = $request->headers->all();
        $injectionHeaders = ['x-real-ip', 'x-client-ip', 'x-forwarded-for'];
        foreach ($injectionHeaders as $header) {
            if (isset($headers[$header]) && preg_match('/[a-z]/i', $headers[$header][0])) {
                return $this->logAndBan($request, 'Suspicious Header Injection: ' . $header, 'high');
            }
        }

        // 4️⃣ Referrer Protection
        if (config('honeypot.referrer_protection.enabled', false)) {
            $referer = $request->headers->get('referer');
            $allowedHosts = config('honeypot.referrer_protection.allowed_hosts', []);
            if ($referer && !$this->isAllowedReferer($referer, $allowedHosts)) {
                return $this->logAndBan($request, 'Invalid Referrer Detected', 'medium');
            }
        }

        // 5️⃣ Activity Logging
        if (config('honeypot.activity_log.enabled', false)) {
            Log::info('📄 Request Activity', compact('ip', 'url', 'userAgent', 'payload'));
        }

        // 🔥 DDoS Detection
        $ipSecondKey = 'ddos_ip_' . $ip;
        $reqCount = Cache::increment($ipSecondKey);
        Cache::put($ipSecondKey, $reqCount, now()->addSeconds(1));

        if ($reqCount > config('honeypot.ddos_threshold_per_second', 20)) {
            return $this->logAndBan($request, 'Potential DDoS Detected', 'high');
        }

        // ⚠️ Endpoint Flood Detection
        $endpointKey = 'flood_' . $ip . '_' . md5($endpoint);
        $endpointCount = Cache::increment($endpointKey);
        Cache::put($endpointKey, $endpointCount, now()->addSeconds(10));

        if ($endpointCount > config('honeypot.flood_threshold', 30)) {
            return $this->logAndBan($request, 'Endpoint Flood Detected', 'medium');
        }

        // 🔍 User-Agent Variation
        $previousUserAgent = Cache::get("user_agent_{$ip}");
        if ($previousUserAgent && $previousUserAgent !== $userAgent) {
            return $this->logAndBan($request, 'User-Agent Variation Detected', 'low');
        }
        Cache::put("user_agent_{$ip}", $userAgent, now()->addMinutes(5));

        // 🧠 AI Detection
        if (config('honeypot.ai_detection.enabled') && config('honeypot.ai_detection.ai_model_url')) {
            try {
                $response = Http::timeout(3)->post(config('honeypot.ai_detection.ai_model_url'), [
                    'ip' => $ip, 'user_agent' => $userAgent, 'url' => $url, 'payload' => $payload,
                ]);

                if ($response->successful() && $response->json('is_attack')) {
                    return $this->logAndBan($request, 'AI Detected Threat', 'high');
                }
            } catch (\Exception $e) {
                Log::error('AI detection failed: ' . $e->getMessage());
            }
        }

        // 🛡️ Signature-Based Threat Detection
        $patterns = $this->getThreatPatterns();
        $customPatterns = config('honeypot.custom_patterns', []);
        $patterns = array_merge($patterns, $customPatterns);

        foreach ($patterns as $pattern => $threatLabel) {
            try {
                if (preg_match($pattern, $payload)) {
                    return $this->logAndBan($request, $threatLabel, 'high');
                }
            } catch (\Throwable $e) {
                Log::error("Regex error in pattern: $pattern");
            }
        }

        // 🕵️‍♂️ Suspicious User-Agent
        if (!$userAgent || preg_match('/curl|wget|python|httpclient|scanner/i', $userAgent)) {
            return $this->logAndBan($request, 'Suspicious User-Agent Detected', 'medium');
        }

        // 📦 Large Payload Detection
        if (strlen($payload) > 5000) {
            return $this->logAndBan($request, 'Suspicious Large Payload', 'high');
        }

        // 🚫 IP Blacklist Check
        $blacklistFile = storage_path('app/blacklist_ips.txt');
        $blacklist = file_exists($blacklistFile) ? file($blacklistFile, FILE_IGNORE_NEW_LINES) : [];
        if (in_array($ip, $blacklist)) {
            return $this->logAndBan($request, 'Blacklisted IP', 'high');
        }

        // ⏳ Rate Limiting
        $ipMinuteKey = 'rate_limit_' . $ip;
        $minuteRequests = Cache::increment($ipMinuteKey);
        Cache::put($ipMinuteKey, $minuteRequests, now()->addMinutes(1));

        if ($minuteRequests > config('honeypot.rate_limit_threshold', 100)) {
            return $this->logAndBan($request, 'Rate Limit Exceeded', 'medium');
        }

        return $next($request);
    }

    private function getThreatPatterns(): array
    {
        return [
            '/<script.*?>.*?<\\/script>/i' => 'XSS Detected',
            '/on\w+\s*=\s*(\"|\')?[^"\'>]*(\"|\')?/i' => 'XSS Detected',
            '/<.*?javascript:.*?>/i' => 'XSS Detected',
            '/document\.cookie/i' => 'XSS Detected',
            '/alert\s*\(/i' => 'XSS Detected',
            '/<iframe.*?>.*?<\\/iframe>/i' => 'XSS Detected',
            '/(select\s.*from|union\s.*select|insert\sinto|drop\s+table)/i' => 'SQL Injection Detected',
            '/or\s+1=1/i' => 'SQL Injection Detected',
            '/--|#|\/\*/' => 'SQL Injection Detected',
            '/(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i' => 'RCE Detected',
            '/base64_decode\s*\(/i' => 'RCE Detected',
            '/\${jndi:.*?}/i' => 'Log4Shell RCE Detected',
            '/{%.*?%}/i' => 'Template Injection Detected',
            '/\${.*?}/i' => 'Template Injection Detected',
            '/gopher:\/\//i' => 'SSRF Detected',
            '/file:\/\/etc\/passwd/i' => 'SSRF/LFI Detected',
            '/(\.\.\/|\.\.\\)/i' => 'Directory Traversal Detected',
        ];
    }

    private function isAllowedReferer($referer, $allowedHosts): bool
    {
        foreach ($allowedHosts as $host) {
            if (str_contains($referer, $host)) {
                return true;
            }
        }
        return false;
    }

    private function logAndBan(Request $request, string $reason, string $level = 'high')
    {
        $this->honeypotService->logAndBlock($request, $reason, $level);
        return response('Access denied. ' . $reason, 403);
    }

    private function logThreat($ip, $url, $userAgent, $reason, $payload, $level, $action)
    {
        $this->honeypotService->logThreat([
            'ip_address' => $ip,
            'url' => $url,
            'user_agent' => $userAgent,
            'type' => $reason,
            'payload' => strlen($payload) > 2000 ? substr($payload, 0, 2000) . '...' : $payload,
            'threat_level' => $level,
            'action_taken' => $action,
        ]);
    }
}
