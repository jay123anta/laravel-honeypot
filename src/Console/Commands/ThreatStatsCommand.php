<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class ThreatStatsCommand extends Command
{
    protected $signature = 'threat-detection:stats';

    protected $description = 'Display a quick stats summary of threat logs';

    public function handle(): int
    {
        $table = config('threat-detection.table_name', 'threat_logs');

        $total = DB::table($table)->count();
        $high = DB::table($table)->where('threat_level', 'high')->count();
        $medium = DB::table($table)->where('threat_level', 'medium')->count();
        $low = DB::table($table)->where('threat_level', 'low')->count();
        $uniqueIps = DB::table($table)->distinct('ip_address')->count('ip_address');
        $today = DB::table($table)->whereDate('created_at', today())->count();
        $lastHour = DB::table($table)->where('created_at', '>=', now()->subHour())->count();

        $this->newLine();
        $this->info('=== Threat Detection Stats ===');
        $this->newLine();

        $this->table(
            ['Metric', 'Count'],
            [
                ['Total Threats', $total],
                ['High Severity', $high],
                ['Medium Severity', $medium],
                ['Low Severity', $low],
                ['Unique IPs', $uniqueIps],
                ['Today', $today],
                ['Last Hour', $lastHour],
            ]
        );

        $topIps = DB::table($table)
            ->select('ip_address', DB::raw('COUNT(*) as count'))
            ->groupBy('ip_address')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        if ($topIps->isNotEmpty()) {
            $this->newLine();
            $this->info('Top 5 Offending IPs:');
            $this->table(
                ['IP Address', 'Threat Count'],
                $topIps->map(fn($r) => [$r->ip_address, $r->count])->toArray()
            );
        }

        $topTypes = DB::table($table)
            ->select('type', DB::raw('COUNT(*) as count'))
            ->groupBy('type')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        if ($topTypes->isNotEmpty()) {
            $this->newLine();
            $this->info('Top 5 Threat Types:');
            $this->table(
                ['Type', 'Count'],
                $topTypes->map(fn($r) => [$r->type, $r->count])->toArray()
            );
        }

        return 0;
    }
}
