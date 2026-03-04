<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;

class EnrichThreatLogsCommand extends Command
{
    protected $signature = 'threat-detection:enrich
                            {--days=7 : Number of days to process}
                            {--force : Force re-enrich already enriched records}';

    protected $description = 'Enrich threat logs with geo-location and cloud provider data';

    /**
     * ISP/org keywords that indicate cloud hosting providers.
     * Matched against the 'isp' and 'org' fields from ip-api.com.
     */
    protected array $cloudIspKeywords = [
        'Amazon'          => 'AWS',
        'AWS'             => 'AWS',
        'EC2'             => 'AWS',
        'Microsoft'       => 'Azure',
        'Azure'           => 'Azure',
        'Google Cloud'    => 'GCP',
        'Google LLC'      => 'GCP',
        'DigitalOcean'    => 'DigitalOcean',
        'Linode'          => 'Linode',
        'Akamai'          => 'Linode',
        'Vultr'           => 'Vultr',
        'Choopa'          => 'Vultr',
        'OVH'             => 'OVH',
        'Hetzner'         => 'Hetzner',
        'Cloudflare'      => 'Cloudflare',
        'Oracle Cloud'    => 'Oracle',
        'Alibaba'         => 'Alibaba',
        'Tencent Cloud'   => 'Tencent',
    ];

    /**
     * Fallback IP prefix detection — only well-known, unambiguous ranges.
     * Used when the API doesn't return ISP data.
     */
    protected array $cloudPrefixes = [
        'AWS'          => ['18.', '54.'],
        'DigitalOcean' => ['139.59.', '167.99.', '167.172.', '157.230.', '159.65.', '134.209.', '164.90.'],
        'Linode'       => ['139.162.', '172.104.', '172.105.', '45.33.', '45.56.', '45.79.'],
        'Vultr'        => ['45.32.', '45.63.', '45.76.', '45.77.', '149.28.', '108.61.', '95.179.'],
    ];

    public function handle(): int
    {
        $days = (int) $this->option('days');
        $force = $this->option('force');
        $table = config('threat-detection.table_name', 'threat_logs');

        $query = DB::table($table)
            ->where('created_at', '>=', now()->subDays($days))
            ->distinct();

        if (!$force) {
            $query->whereNull('country_code');
        }

        $ips = $query->pluck('ip_address');

        if ($ips->isEmpty()) {
            $this->info('No IPs to enrich.');
            return 0;
        }

        $this->info("Enriching {$ips->count()} unique IPs from the last {$days} days...");
        $bar = $this->output->createProgressBar($ips->count());

        foreach ($ips as $ip) {
            $data = $this->enrichIp($ip);

            DB::table($table)
                ->where('ip_address', $ip)
                ->when(!$force, fn($q) => $q->whereNull('country_code'))
                ->update($data);

            $bar->advance();
            usleep(200000); // Rate limit: 5 requests/second
        }

        $bar->finish();
        $this->newLine();
        $this->info('Enrichment complete!');

        return 0;
    }

    protected function enrichIp(string $ip): array
    {
        $cacheKey = "threat_ip_geo:{$ip}";

        return Cache::remember($cacheKey, now()->addDays(7), function () use ($ip) {
            $geo = $this->fetchGeoData($ip);
            $cloudProvider = $this->detectCloudProvider($ip, $geo['isp'] ?? null, $geo['org'] ?? null);

            $homeCountry = config('threat-detection.home_country', 'IN');

            return [
                'country_code' => $geo['country_code'] ?? null,
                'country_name' => $geo['country_name'] ?? null,
                'city' => $geo['city'] ?? null,
                'isp' => $geo['isp'] ?? null,
                'cloud_provider' => $cloudProvider,
                'is_foreign' => ($geo['country_code'] ?? '') !== $homeCountry,
                'is_cloud_ip' => $cloudProvider !== null,
            ];
        });
    }

    protected function fetchGeoData(string $ip): array
    {
        try {
            $response = Http::timeout(3)->get("http://ip-api.com/json/{$ip}?fields=countryCode,country,city,isp,org");

            if ($response->successful()) {
                $data = $response->json();
                return [
                    'country_code' => $data['countryCode'] ?? null,
                    'country_name' => $data['country'] ?? null,
                    'city' => $data['city'] ?? null,
                    'isp' => $data['isp'] ?? null,
                    'org' => $data['org'] ?? null,
                ];
            }
        } catch (\Throwable $e) {
            // Silent fail
        }

        return [];
    }

    /**
     * Detect cloud provider using ISP/org data first, IP prefix as fallback.
     */
    protected function detectCloudProvider(string $ip, ?string $isp = null, ?string $org = null): ?string
    {
        // Primary: match against ISP/org keywords from the API
        $searchText = strtolower(($isp ?? '') . ' ' . ($org ?? ''));
        foreach ($this->cloudIspKeywords as $keyword => $provider) {
            if (str_contains($searchText, strtolower($keyword))) {
                return $provider;
            }
        }

        // Fallback: IP prefix matching for when API data is unavailable
        foreach ($this->cloudPrefixes as $provider => $prefixes) {
            foreach ($prefixes as $prefix) {
                if (str_starts_with($ip, $prefix)) {
                    return $provider;
                }
            }
        }

        return null;
    }
}
