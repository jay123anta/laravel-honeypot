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

    protected array $cloudProviders = [
        'AWS' => ['13.', '3.', '35.154.', '65.1.', '65.2.', '52.', '54.'],
        'DigitalOcean' => ['139.59.', '167.99.', '167.172.', '188.166.', '157.230.', '137.184.', '159.65.'],
        'Azure' => ['20.', '40.'],
        'GCP' => ['34.', '35.'],
        'Linode' => ['172.104.', '139.162.'],
        'Vultr' => ['45.32.', '45.63.', '45.76.', '45.77.'],
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
            $cloudProvider = $this->detectCloudProvider($ip);

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
            $response = Http::timeout(3)->get("http://ip-api.com/json/{$ip}");

            if ($response->successful()) {
                $data = $response->json();
                return [
                    'country_code' => $data['countryCode'] ?? null,
                    'country_name' => $data['country'] ?? null,
                    'city' => $data['city'] ?? null,
                    'isp' => $data['isp'] ?? null,
                ];
            }
        } catch (\Throwable $e) {
            // Silent fail
        }

        return [];
    }

    protected function detectCloudProvider(string $ip): ?string
    {
        foreach ($this->cloudProviders as $provider => $prefixes) {
            foreach ($prefixes as $prefix) {
                if (str_starts_with($ip, $prefix)) {
                    return $provider;
                }
            }
        }
        return null;
    }
}
