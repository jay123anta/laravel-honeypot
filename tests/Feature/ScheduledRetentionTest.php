<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * TD_AUDIT.md "Not verified" item 5: registerSchedule() and the retention path
 * were never executed by any test.
 *
 * Not a vulnerability finding — an availability one. If the scheduled purge
 * silently fails to register, threat_logs grows without bound and nothing says
 * so; the failure surfaces as a full disk months after install. Registration
 * happens inside the provider's booted() callback, so it is asserted against
 * the real Schedule instance rather than read off the source.
 *
 * Retention is read during boot, so a test that needs it enabled rebuilds the
 * application with the config already in place.
 */
class ScheduledRetentionTest extends TestCase
{
    private array $retentionOverride = [];

    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        if ($this->retentionOverride !== []) {
            $app['config']->set('threat-detection.retention', $this->retentionOverride);
        }
    }

    private function withRetention(array $retention): void
    {
        $this->retentionOverride = $retention;
        $this->refreshApplication();
    }

    private function purgeEvents(): array
    {
        return array_values(array_filter(
            $this->app->make(Schedule::class)->events(),
            fn ($event) => str_contains($event->command ?? '', 'threat-detection:purge')
        ));
    }

    private function scheduledCommands(): array
    {
        return array_map(fn ($e) => $e->command ?? '', $this->app->make(Schedule::class)->events());
    }

    /**
     * Positive control for every test below. If a purge were scheduled here
     * too, "a purge is scheduled" would say nothing about the config flag.
     */
    #[Test]
    public function no_purge_is_scheduled_when_retention_is_disabled(): void
    {
        $this->withRetention(['enabled' => false, 'days' => 90]);

        $this->assertSame([], $this->purgeEvents());
    }

    #[Test]
    public function enabling_retention_schedules_a_purge(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 90]);

        $events = $this->purgeEvents();

        $this->assertCount(
            1,
            $events,
            'the retention purge was not scheduled. Scheduled: ' . json_encode($this->scheduledCommands())
        );
        $this->assertStringContainsString('--days=90', $events[0]->command);
    }

    #[Test]
    public function the_configured_retention_period_is_the_one_scheduled(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 14]);

        $this->assertStringContainsString('--days=14', $this->purgeEvents()[0]->command);
    }

    #[Test]
    public function the_purge_runs_daily_and_cannot_stack_on_itself(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 90]);

        $event = $this->purgeEvents()[0];

        $this->assertSame('0 2 * * *', $event->expression, 'the purge is not scheduled daily at 02:00');
        $this->assertTrue($event->withoutOverlapping, 'a slow purge could stack on the next run');
    }

    /**
     * The schedule names a command by string. If that signature does not
     * exist, registration still succeeds and the failure appears only in the
     * scheduler's log, nightly, where nobody looks.
     */
    #[Test]
    public function the_scheduled_command_signature_is_actually_registered(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 90]);

        $this->assertArrayHasKey(
            'threat-detection:purge',
            Artisan::all(),
            'the schedule names a command that is not registered'
        );
    }

    /**
     * Positive control for the test below: run with the confirmation
     * explicitly suppressed, the command does delete. Without this, a red
     * end-to-end test could just mean the purge is broken outright.
     */
    #[Test]
    public function the_purge_deletes_old_rows_when_confirmation_is_suppressed(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 90]);
        $this->createThreatLogsTable();

        $table = config('threat-detection.table_name', 'threat_logs');
        $old = $this->seedRowAt(now()->subDays(120));
        $recent = $this->seedRowAt(now()->subDays(3));

        Artisan::call('threat-detection:purge', ['--days' => 90, '--no-interaction' => true]);

        $this->assertNull(DB::table($table)->find($old));
        $this->assertNotNull(DB::table($table)->find($recent), 'the purge deleted a row inside the retention period');
    }

    /**
     * The end-to-end property that matters: run exactly the way the scheduler
     * runs it, the nightly purge deletes.
     *
     * The options are read back off the registered schedule rather than
     * retyped, so this cannot drift from what is actually scheduled.
     */
    #[Test]
    public function a_purge_run_the_way_the_scheduler_runs_it_actually_deletes(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 90]);
        $this->createThreatLogsTable();

        $table = config('threat-detection.table_name', 'threat_logs');
        $old = $this->seedRowAt(now()->subDays(120));
        $recent = $this->seedRowAt(now()->subDays(3));

        Artisan::call('threat-detection:purge', $this->scheduledPurgeOptions());
        $output = Artisan::output();

        $this->assertNull(
            DB::table($table)->find($old),
            'the scheduled purge deleted nothing, so threat_logs grows without bound. Output: ' . trim($output)
        );
        $this->assertNotNull(
            DB::table($table)->find($recent),
            'the purge deleted a row inside the retention period'
        );
    }

    /**
     * The mechanism, pinned separately so a regression names itself. Symfony
     * only marks input non-interactive for --no-interaction / -n; it does not
     * sniff for a TTY. A scheduled command without it reaches confirm(),
     * reads EOF from cron's stdin, and cancels.
     */
    #[Test]
    public function the_scheduled_command_cannot_stop_to_ask_for_confirmation(): void
    {
        $this->withRetention(['enabled' => true, 'days' => 90]);

        $this->assertArrayHasKey(
            '--no-interaction',
            $this->scheduledPurgeOptions(),
            'the scheduled purge would prompt, and a prompt in cron is a cancelled purge'
        );
    }

    /**
     * Options as the schedule passes them, parsed out of the registered
     * command string.
     */
    private function scheduledPurgeOptions(): array
    {
        $command = $this->purgeEvents()[0]->command;
        $tail = substr($command, strpos($command, 'threat-detection:purge') + strlen('threat-detection:purge'));

        $options = [];
        foreach (preg_split('/\s+/', trim($tail), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $token) {
            if (!str_starts_with($token, '--')) {
                continue;
            }
            if (str_contains($token, '=')) {
                [$name, $value] = explode('=', $token, 2);
                $options[$name] = $value;
            } else {
                $options[$token] = true;
            }
        }

        return $options;
    }

    private function seedRowAt(\DateTimeInterface $createdAt): int
    {
        return (int) DB::table(config('threat-detection.table_name', 'threat_logs'))->insertGetId([
            'ip_address' => '203.0.113.5',
            'url' => '/login',
            'user_agent' => 'curl/8.0',
            'type' => 'SQL Injection',
            'threat_level' => 'high',
            'created_at' => $createdAt,
            'updated_at' => $createdAt,
        ]);
    }
}
