<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use JayAnta\ThreatDetection\Notifications\ThreatAlertSlack;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Yaml\Yaml;

/**
 * What the package claims to support, checked against what CI actually runs.
 *
 * composer.json accepts illuminate/* ^10|^11|^12|^13 across PHP ^8.2. That is
 * a promise to four Laravel majors, and the package has already been bitten
 * once by making it without testing it: a fatal that broke every Laravel 11+
 * install reached pull-request stage because the matrix jumped from 10 to 12,
 * and an undeclared guzzle dependency surfaced only on the Laravel 10 leg.
 *
 * The Slack notification is where the majors genuinely diverge. Laravel 10
 * ships Illuminate\Notifications\Messages\SlackMessage; Laravel 11 moved it
 * out to laravel/slack-notification-channel. Both branches of that check are
 * live code, and only the branch matching the version under test has ever
 * executed.
 */
class SupportMatrixTest extends TestCase
{
    /** @return array<string, mixed> */
    private function workflow(): array
    {
        $path = __DIR__ . '/../../.github/workflows/tests.yml';
        $this->assertFileExists($path);

        return Yaml::parseFile($path);
    }

    /**
     * Every (php, laravel) pair the matrix produces, including the include
     * entries and minus the exclude entries.
     *
     * @return array<int, array{php: string, laravel: string, eol: bool}>
     */
    private function matrixLegs(): array
    {
        $matrix = $this->workflow()['jobs']['test']['strategy']['matrix'];

        $legs = [];
        foreach ($matrix['php'] as $php) {
            foreach ($matrix['laravel'] as $laravel) {
                $legs[] = ['php' => (string) $php, 'laravel' => (string) $laravel, 'eol' => false];
            }
        }

        foreach ($matrix['exclude'] ?? [] as $exclude) {
            $legs = array_values(array_filter(
                $legs,
                fn ($leg) => !((string) $exclude['php'] === $leg['php'] && (string) $exclude['laravel'] === $leg['laravel'])
            ));
        }

        foreach ($matrix['include'] ?? [] as $include) {
            $legs[] = [
                'php' => (string) $include['php'],
                'laravel' => (string) $include['laravel'],
                'eol' => (bool) ($include['eol'] ?? false),
            ];
        }

        return $legs;
    }

    /** The Laravel majors composer.json says it accepts. */
    private function claimedLaravelMajors(): array
    {
        $composer = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);

        preg_match_all('/\^(\d+)\.0/', $composer['require']['illuminate/support'], $found);

        return $found[1];
    }

    // ── the matrix covers what composer.json promises ──────────────────────

    #[Test]
    public function every_laravel_major_the_package_claims_is_actually_run_in_ci(): void
    {
        $tested = array_unique(array_map(
            fn ($leg) => explode('.', $leg['laravel'])[0],
            $this->matrixLegs()
        ));

        foreach ($this->claimedLaravelMajors() as $major) {
            $this->assertContains(
                $major,
                $tested,
                "composer.json accepts Laravel {$major} but no CI leg installs it — untested support is not support"
            );
        }
    }

    #[Test]
    public function every_php_version_the_package_claims_is_actually_run_in_ci(): void
    {
        $composer = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);
        $this->assertSame('^8.2', $composer['require']['php'], 'the PHP constraint moved; update this test');

        $tested = array_unique(array_column($this->matrixLegs(), 'php'));

        foreach (['8.2', '8.3', '8.4'] as $version) {
            $this->assertContains($version, $tested, "PHP {$version} is inside ^8.2 but no CI leg runs it");
        }
    }

    /**
     * The two majors that are past their security-patch window run with
     * continue-on-error, so a failure there does not block a merge. That is a
     * deliberate decision, and it has a cost: the run reports success while a
     * leg is red, which is how a real failure was once missed. Pinned so the
     * cost stays visible.
     */
    #[Test]
    public function the_end_of_life_legs_are_marked_non_blocking_and_the_current_ones_are_not(): void
    {
        $legs = $this->matrixLegs();

        $eolMajors = array_unique(array_map(
            fn ($leg) => explode('.', $leg['laravel'])[0],
            array_filter($legs, fn ($leg) => $leg['eol'])
        ));
        sort($eolMajors);

        $this->assertSame(['10', '11'], array_values($eolMajors));

        $blockingMajors = array_unique(array_map(
            fn ($leg) => explode('.', $leg['laravel'])[0],
            array_filter($legs, fn ($leg) => !$leg['eol'])
        ));
        sort($blockingMajors);

        $this->assertSame(['12', '13'], array_values($blockingMajors), 'a current Laravel major is not gating merges');
    }

    #[Test]
    public function the_end_of_life_legs_opt_out_of_advisory_blocking_and_nothing_else_does(): void
    {
        $steps = $this->workflow()['jobs']['test']['steps'];

        $optOuts = array_values(array_filter(
            $steps,
            fn ($step) => str_contains($step['run'] ?? '', 'policy.advisories.block false')
        ));

        $this->assertCount(1, $optOuts, 'advisory blocking is disabled in more than one place');
        $this->assertSame('matrix.eol', $optOuts[0]['if'] ?? null, 'the advisory opt-out is not restricted to the EOL legs');
    }

    #[Test]
    public function ci_runs_on_every_branch_not_only_on_pull_requests(): void
    {
        // `on` is parsed by the YAML spec as the boolean true.
        $triggers = $this->workflow()[true] ?? $this->workflow()['on'];

        $this->assertContains('**', $triggers['push']['branches']);
    }

    #[Test]
    public function static_analysis_and_style_run_somewhere_in_ci(): void
    {
        $steps = $this->workflow()['jobs']['quality']['steps'];
        $commands = implode("\n", array_column($steps, 'run'));

        $this->assertStringContainsString('pint --test', $commands);
        $this->assertStringContainsString('phpstan analyse', $commands);
    }

    #[Test]
    public function coverage_is_enforced_as_a_threshold_rather_than_merely_reported(): void
    {
        $steps = $this->workflow()['jobs']['coverage']['steps'];
        $commands = implode("\n", array_column($steps, 'run'));

        $this->assertStringContainsString('coverage-threshold.php', $commands);
        $this->assertFileExists(__DIR__ . '/../../.github/coverage-threshold.php');
    }

    // ── the Slack branch that diverges between Laravel 10 and 11+ ──────────

    /**
     * Which branch this run exercises. Recorded explicitly so a green suite
     * cannot be mistaken for "both branches pass".
     *
     * This used to predict the answer from the Laravel major: "10 ships
     * SlackMessage, 11+ does not." That prediction is wrong, and it was
     * failing the Laravel 10 leg — silently, because that leg is
     * `continue-on-error`. `laravel/framework:10.*` resolves to 10.50.x,
     * which does **not** ship `Illuminate\Notifications\Messages\SlackMessage`;
     * the class is only present if `laravel/slack-notification-channel` is
     * installed, and this package merely suggests it.
     *
     * So the prediction is gone. What is asserted instead is the thing that
     * has to hold on every leg: the package's behaviour follows whether the
     * class is actually there, never which major it is running on.
     */
    #[Test]
    public function the_slack_branch_under_test_is_the_one_the_installed_packages_select(): void
    {
        $hasSlackMessage = class_exists(SlackMessage::class);
        $via = (new ThreatAlertSlack($this->alertData()))->via(null);

        $hasSlackMessage
            ? $this->assertSame(['slack'], $via, 'SlackMessage is installed but the notification will not route to it')
            : $this->assertSame([], $via, 'SlackMessage is absent, so claiming the slack channel would be a fatal');
    }

    /**
     * And the consequence, stated so it is not rediscovered: on every
     * combination this matrix installs, `toSlack()` is unreachable. The
     * webhook branch is the one every user gets unless they install
     * `laravel/slack-notification-channel` themselves.
     */
    #[Test]
    public function the_slack_message_branch_is_unreachable_without_the_optional_channel_package(): void
    {
        if (class_exists(SlackMessage::class)) {
            $this->markTestSkipped('slack-notification-channel is installed on this run, so the SlackMessage branch is live');
        }

        $this->assertSame(
            [],
            (new ThreatAlertSlack($this->alertData()))->via(null),
            'toSlack() would be called with no SlackMessage class present, which is a fatal'
        );
    }

    #[Test]
    public function the_notification_routes_to_the_slack_channel_only_when_the_channel_package_is_present(): void
    {
        $via = (new ThreatAlertSlack($this->alertData()))->via(null);

        class_exists(SlackMessage::class)
            ? $this->assertSame(['slack'], $via)
            : $this->assertSame([], $via, 'the notification claimed a slack channel that does not exist here');
    }

    /**
     * The Laravel 11+ branch: no SlackMessage, so the alert is posted to the
     * webhook as a raw payload. This is the branch that runs on the majority
     * of installs and it is asserted end to end.
     */
    #[Test]
    public function without_the_channel_package_the_alert_is_posted_to_the_webhook_directly(): void
    {
        if (class_exists(SlackMessage::class)) {
            $this->markTestSkipped('this run has SlackMessage, so the webhook branch is not selected');
        }

        Http::fake(['*' => Http::response('ok', 200)]);

        $alert = new ThreatAlertSlack($this->alertData());
        Http::post('https://hooks.slack.example/services/T/B/X', $alert->toWebhookPayload());

        Http::assertSent(function ($request) {
            $body = $request->data();

            return $body['text'] === '@here *Threat Detected*'
                && $body['attachments'][0]['fields'][0]['value'] === '203.0.113.9'
                // Defanged so Slack cannot turn the attacking URL into a link.
                && str_contains($body['attachments'][0]['fields'][1]['value'], 'hxxp://')
                && str_contains($body['attachments'][0]['fields'][1]['value'], '[.]');
        });
    }

    /**
     * The Laravel 10 branch. SlackMessage is absent on this run, so toSlack()
     * cannot be called — calling it would be a fatal, not a failure.
     *
     * Rather than skip silently, this asserts the contract the branch depends
     * on: that toSlack() exists, that it is only ever reached when via()
     * returns the slack channel, and that via() gates on the class this run is
     * missing. On a Laravel 10 leg the guard below inverts and the method is
     * genuinely exercised.
     */
    #[Test]
    public function the_laravel_ten_slack_branch_is_gated_on_the_class_it_needs(): void
    {
        $this->assertTrue(
            method_exists(ThreatAlertSlack::class, 'toSlack'),
            'the Laravel 10 branch was removed but via() may still route to it'
        );

        if (!class_exists(SlackMessage::class)) {
            // The gate is what protects this run from a fatal, so assert it.
            $this->assertSame([], (new ThreatAlertSlack($this->alertData()))->via(null));

            return;
        }

        Notification::fake();

        $message = (new ThreatAlertSlack($this->alertData()))->toSlack(null);

        $this->assertInstanceOf(SlackMessage::class, $message);
    }

    /**
     * @return array<string, string>
     */
    private function alertData(): array
    {
        return [
            'ip_address' => '203.0.113.9',
            'url' => 'https://evil.example.com/attack?q=1',
            'type' => '[middleware] SQL Injection UNION',
            'threat_level' => 'high',
            'action_taken' => 'logged',
            'user_agent' => 'sqlmap/1.7.2',
        ];
    }

    // ── the documented support surface matches reality ─────────────────────

    /**
     * @return array<string, array{0: string}>
     */
    public static function suggestedPackages(): array
    {
        return [
            'guzzle' => ['guzzlehttp/guzzle'],
            'slack channel' => ['laravel/slack-notification-channel'],
            'sanctum' => ['laravel/sanctum'],
        ];
    }

    /**
     * Each optional package is named in `suggest` rather than `require`, and
     * the package has to work without it. The Sanctum fallback and the guzzle
     * guard are tested elsewhere; this pins that they stay optional, because
     * promoting one to `require` silently would change what the package costs
     * to install.
     */
    #[Test]
    #[DataProvider('suggestedPackages')]
    public function an_optional_dependency_stays_out_of_require(string $package): void
    {
        $composer = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);

        $this->assertArrayHasKey($package, $composer['suggest']);
        $this->assertArrayNotHasKey($package, $composer['require']);
    }

    #[Test]
    public function every_runtime_requirement_is_an_illuminate_package_or_php_itself(): void
    {
        $composer = json_decode(file_get_contents(__DIR__ . '/../../composer.json'), true);

        foreach (array_keys($composer['require']) as $requirement) {
            $this->assertTrue(
                $requirement === 'php' || str_starts_with($requirement, 'illuminate/'),
                "'{$requirement}' is a runtime dependency that is not part of Laravel itself"
            );
        }
    }
}
