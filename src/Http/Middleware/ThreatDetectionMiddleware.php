<?php

namespace JayAnta\ThreatDetection\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\IpUtils;

class ThreatDetectionMiddleware
{
    protected ThreatDetectionService $detector;

    public function __construct(ThreatDetectionService $detector)
    {
        $this->detector = $detector;
    }

    public function handle(Request $request, Closure $next)
    {
        try {
            // Skip detection if disabled or environment not enabled
            if (!config('threat-detection.enabled') ||
                (config('threat-detection.enabled_environments') &&
                !in_array(app()->environment(), config('threat-detection.enabled_environments')))) {
                return $next($request);
            }

            // Skip whitelisted IPs
            $ip = $request->ip();
            if (IpUtils::checkIp($ip, config('threat-detection.whitelisted_ips', []))) {
                return $next($request);
            }

            // Skip path if in skip_paths
            $uri = ltrim($request->path(), '/');
            foreach (config('threat-detection.skip_paths', []) as $skip) {
                if (fnmatch($skip, $uri)) {
                    return $next($request);
                }
            }

            // Check if this is an auth path - mark it for smart detection
            $isAuthPath = false;
            foreach (config('threat-detection.auth_paths', []) as $authPath) {
                if (fnmatch($authPath, $uri)) {
                    $isAuthPath = true;
                    break;
                }
            }

            if ($isAuthPath) {
                $request->attributes->set('threat-detection:auth-path', true);
            }

            // Smart API Filtering: If route is /api/* and threat is low/medium → optionally skip
            if (
                config('threat-detection.api_route_filtering.enabled', true)
                && str_starts_with($request->path(), 'api/')
            ) {
                $request->attributes->set('threat-detection:api-suppress-levels', config('threat-detection.api_route_filtering.suppress_levels', []));
            }

            // Run detection using a context-aware method
            $this->detector->detectAndLogFromRequest($request);

        } catch (\Throwable $e) {
            Log::error('ThreatDetectionMiddleware Error: ' . $e->getMessage());
        }

        return $next($request);
    }
}
