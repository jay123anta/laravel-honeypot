<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use JayAnta\ThreatDetection\Http\Middleware\ThreatDashboardAuthMiddleware;
use JayAnta\ThreatDetection\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * The dashboard and API guards, checked for failing closed rather than for
 * working when configured correctly.
 *
 * DashboardAuthGuardTest covers the four supported guard values doing what
 * they are supposed to do. This file covers everything else an operator can
 * type into that config key — misspellings, wrong case, empty strings, values
 * from a newer version of the package — and every one of them has to end in a
 * 403. A security dashboard that opens up when its guard is misconfigured is
 * worse than one with no guard, because the operator believes it is protected.
 *
 * Both contexts (dashboard and api) and both modes (read guard and write
 * guard) are driven, because they are separate config keys resolved by the
 * same method and a fail-open in either is the same defect.
 */
class GuardFailClosedTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->createThreatLogsTable();
        $this->createExclusionRulesTable();

        config([
            'threat-detection.enabled' => false, // detection is not what is under test
            'cache.default' => 'array',
        ]);
    }

    protected function tearDown(): void
    {
        Cache::flush();
        parent::tearDown();
    }

    /**
     * Drive the middleware directly for the guard-value matrix. Routing a
     * request through the package's own routes would work, but it fixes the
     * context and mode to whatever those routes use; this covers all four
     * combinations from one place.
     */
    private function runGuard(string $context, ?string $mode = null, string $ip = '203.0.113.9'): int
    {
        $request = Request::create('/threat-detection', 'GET');
        $request->server->set('REMOTE_ADDR', $ip);

        try {
            (new ThreatDashboardAuthMiddleware)->handle(
                $request,
                fn () => response('REACHED-THE-DASHBOARD', 200),
                $context,
                $mode
            );
        } catch (HttpException $e) {
            return $e->getStatusCode();
        }

        return 200;
    }

    /**
     * Guard values that are not one of none|auth|role|ip. Every one has to be
     * refused. Case matters: the comparison is ===, so 'Auth' is not 'auth'
     * and must fail closed rather than silently behaving like the value it
     * resembles.
     *
     * @return array<string, array{0: string}>
     */
    public static function unrecognisedGuardValues(): array
    {
        return [
            'a typo' => ['ath'],
            'a plural' => ['roles'],
            'capitalised' => ['Auth'],
            'shouting' => ['ROLE'],
            'padded with a space' => ['auth '],
            'leading space' => [' ip'],
            'an empty string' => [''],
            'a value from some other package' => ['sanctum'],
            'a laravel guard name' => ['web'],
            'a boolean-looking string' => ['true'],
            'a numeric string' => ['1'],
            'a plausible future value' => ['token'],
            'a policy name' => ['can:viewThreats'],
            'null spelled out' => ['null'],
            'a comma-separated list' => ['auth,role'],
        ];
    }

    #[Test]
    #[DataProvider('unrecognisedGuardValues')]
    public function an_unrecognised_dashboard_guard_denies_access(string $guard): void
    {
        config(['threat-detection.dashboard.guard' => $guard]);

        $this->assertSame(403, $this->runGuard('dashboard'), "dashboard guard '{$guard}' did not fail closed");
    }

    #[Test]
    #[DataProvider('unrecognisedGuardValues')]
    public function an_unrecognised_api_guard_denies_access(string $guard): void
    {
        config(['threat-detection.api.guard' => $guard]);

        $this->assertSame(403, $this->runGuard('api'), "api guard '{$guard}' did not fail closed");
    }

    #[Test]
    #[DataProvider('unrecognisedGuardValues')]
    public function an_unrecognised_write_guard_denies_access(string $guard): void
    {
        config(['threat-detection.api.write_guard' => $guard]);

        $this->assertSame(403, $this->runGuard('api', 'write'), "api write_guard '{$guard}' did not fail closed");
    }

    #[Test]
    #[DataProvider('unrecognisedGuardValues')]
    public function an_unrecognised_dashboard_write_guard_denies_access(string $guard): void
    {
        config(['threat-detection.dashboard.write_guard' => $guard]);

        $this->assertSame(403, $this->runGuard('dashboard', 'write'), "dashboard write_guard '{$guard}' did not fail closed");
    }

    /**
     * The write guard defaults to 'role', not to whatever the read guard is.
     * Left unset it must still deny an unauthenticated caller — an operator
     * who configured only `guard` must not get open write endpoints.
     */
    #[Test]
    public function an_unset_write_guard_defaults_to_denying_rather_than_to_the_read_guard(): void
    {
        config(['threat-detection.api.guard' => 'none']);
        config()->offsetUnset('threat-detection.api.write_guard');

        $this->assertSame(200, $this->runGuard('api'), 'the read guard was configured as none');
        $this->assertSame(403, $this->runGuard('api', 'write'), 'the write guard fell back to the read guard');
    }

    // ── the role guard on a user model that cannot answer ──────────────────

    /**
     * A role guard needs hasRole(). Most Laravel user models do not have it
     * unless a roles package is installed, and the middleware cannot verify
     * what it cannot ask — so it denies.
     */
    #[Test]
    public function the_role_guard_denies_a_user_model_without_a_has_role_method(): void
    {
        config(['threat-detection.dashboard.guard' => 'role']);
        Auth::login(new UserWithoutRoles);

        $this->assertSame(403, $this->runGuard('dashboard'));
    }

    #[Test]
    public function the_role_write_guard_denies_a_user_model_without_a_has_role_method(): void
    {
        config(['threat-detection.api.write_guard' => 'role']);
        Auth::login(new UserWithoutRoles);

        $this->assertSame(403, $this->runGuard('api', 'write'));
    }

    #[Test]
    public function the_role_guard_denies_a_user_whose_has_role_returns_false(): void
    {
        config(['threat-detection.dashboard.guard' => 'role', 'threat-detection.dashboard.role' => 'admin']);
        Auth::login(new UserWithRoles(['editor']));

        $this->assertSame(403, $this->runGuard('dashboard'));
    }

    #[Test]
    public function the_role_guard_admits_a_user_who_holds_the_configured_role(): void
    {
        config(['threat-detection.dashboard.guard' => 'role', 'threat-detection.dashboard.role' => 'admin']);
        Auth::login(new UserWithRoles(['admin']));

        $this->assertSame(200, $this->runGuard('dashboard'));
    }

    /**
     * The role name is compared as configured. A user holding 'Admin' does not
     * hold 'admin' unless their own hasRole() says so — the middleware must
     * not normalise case on the user's behalf and widen the check.
     */
    #[Test]
    public function the_role_guard_does_not_normalise_the_case_of_the_configured_role(): void
    {
        config(['threat-detection.dashboard.guard' => 'role', 'threat-detection.dashboard.role' => 'admin']);
        Auth::login(new UserWithRoles(['Admin']));

        $this->assertSame(403, $this->runGuard('dashboard'));
    }

    #[Test]
    public function the_role_guard_denies_an_unauthenticated_caller_before_it_looks_for_has_role(): void
    {
        config(['threat-detection.dashboard.guard' => 'role']);

        $this->assertSame(403, $this->runGuard('dashboard'));
    }

    // ── the ip guard ───────────────────────────────────────────────────────

    /**
     * @return array<string, array{0: array<int, string>, 1: string, 2: int}>
     */
    public static function ipGuardCases(): array
    {
        return [
            'empty allowlist denies everyone' => [[], '203.0.113.9', 403],
            'an allowlist of empty strings denies' => [['', ''], '203.0.113.9', 403],
            'exact match admits' => [['203.0.113.9'], '203.0.113.9', 200],
            'exact mismatch denies' => [['203.0.113.9'], '203.0.113.10', 403],
            'cidr match admits' => [['203.0.113.0/24'], '203.0.113.200', 200],
            'cidr mismatch denies' => [['203.0.113.0/24'], '203.0.114.1', 403],
            'unparsable entry denies' => [['not-an-ip'], '203.0.113.9', 403],
            'one good entry among bad ones admits' => [['not-an-ip', '203.0.113.9'], '203.0.113.9', 200],
        ];
    }

    #[Test]
    #[DataProvider('ipGuardCases')]
    public function the_ip_guard_admits_only_a_listed_address(array $allowed, string $ip, int $expected): void
    {
        config([
            'threat-detection.dashboard.guard' => 'ip',
            'threat-detection.dashboard.allowed_ips' => $allowed,
        ]);

        $this->assertSame($expected, $this->runGuard('dashboard', null, $ip));
    }

    /**
     * An empty allowlist is the configuration most likely to happen by
     * accident — THREAT_DETECTION_DASHBOARD_IPS unset produces exactly this,
     * because the shipped config explodes an empty string. Denying is the only
     * safe reading, and it is worth its own test in both contexts.
     */
    #[Test]
    public function an_ip_guard_with_no_addresses_configured_denies_rather_than_admitting_everyone(): void
    {
        config([
            'threat-detection.api.guard' => 'ip',
            'threat-detection.api.allowed_ips' => [],
        ]);

        $this->assertSame(403, $this->runGuard('api'));
    }

    // ── guard 'none' is the only value that opens the door ─────────────────

    #[Test]
    public function only_the_literal_value_none_grants_unauthenticated_access(): void
    {
        config(['threat-detection.dashboard.guard' => 'none']);

        $this->assertSame(200, $this->runGuard('dashboard'));
    }

    #[Test]
    public function guard_none_warns_the_operator_once_rather_than_silently_allowing(): void
    {
        config(['threat-detection.dashboard.guard' => 'none']);
        Log::spy();

        $this->runGuard('dashboard');

        Log::shouldHaveReceived('warning')
            ->withArgs(fn ($m) => str_contains($m, 'without authentication'))
            ->once();
    }

    // ── the API surface actually served ────────────────────────────────────

    /**
     * The matrix above drives the middleware directly. This drives the real
     * route, so a change to how the guard is wired into routes/api.php shows
     * up as well.
     */
    #[Test]
    public function a_write_endpoint_on_the_real_api_route_denies_by_default(): void
    {
        $id = DB::table('threat_logs')->insertGetId([
            'ip_address' => '203.0.113.1', 'url' => 'https://example.com/x', 'user_agent' => 'PHPUnit',
            'type' => '[middleware] XSS Script Tag', 'payload' => 'x', 'threat_level' => 'high',
            'action_taken' => 'logged', 'created_at' => now(), 'updated_at' => now(),
        ]);

        $this->postJson("/api/threat-detection/threats/{$id}/false-positive")->assertStatus(403);
    }

    #[Test]
    public function a_read_endpoint_on_the_real_api_route_is_unaffected_by_the_write_guard(): void
    {
        $this->getJson('/api/threat-detection/stats')->assertStatus(200);
    }
}

/** A user model of the kind most Laravel apps ship: no roles package. */
class UserWithoutRoles implements Authenticatable
{
    public function getAuthIdentifierName()
    {
        return 'id';
    }

    public function getAuthIdentifier()
    {
        return 1;
    }

    public function getAuthPassword()
    {
        return '';
    }

    public function getAuthPasswordName()
    {
        return 'password';
    }

    public function getRememberToken()
    {
        return null;
    }

    public function setRememberToken($value) {}

    public function getRememberTokenName()
    {
        return 'remember_token';
    }
}

/** A user model with a roles package installed. */
class UserWithRoles extends UserWithoutRoles
{
    public function __construct(private array $roles = []) {}

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles, true);
    }
}
