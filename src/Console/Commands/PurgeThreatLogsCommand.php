<?php

namespace JayAnta\ThreatDetection\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class PurgeThreatLogsCommand extends Command
{
    protected $signature = 'threat-detection:purge
                            {--days=30 : Delete logs older than this many days}';

    protected $description = 'Delete threat logs older than the specified number of days';

    public function handle(): int
    {
        $days = (int) $this->option('days');
        $table = config('threat-detection.table_name', 'threat_logs');
        $cutoff = now()->subDays($days);

        $count = DB::table($table)
            ->where('created_at', '<', $cutoff)
            ->count();

        if ($count === 0) {
            $this->info("No threat logs found older than {$days} days.");
            return 0;
        }

        $this->warn("This will permanently delete {$count} threat log(s) older than {$days} days.");

        if (!$this->input->isInteractive() || $this->confirm('Are you sure you want to proceed?')) {
            $deleted = DB::table($table)
                ->where('created_at', '<', $cutoff)
                ->delete();

            $this->info("Successfully deleted {$deleted} threat log(s).");
            return 0;
        }

        $this->info('Purge cancelled.');
        return 0;
    }
}
