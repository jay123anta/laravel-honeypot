<?php

namespace JayAnta\ThreatDetection\Tests\Unit;

use JayAnta\ThreatDetection\Http\Middleware\ThreatDetectionMiddleware;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class MiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Mock the service to prevent DB writes in middleware unit tests
        $mock = $this->createMock(ThreatDetectionService::class);
        $mock->method('detectAndLogFromRequest');
        $this->app->instance(ThreatDetectionService::class, $mock);
        $this->app->instance('threat-detection', $mock);
    }

    private function runMiddleware(Request $request, array $configOverrides = []): \Symfony\Component\HttpFoundation\Response
    {
        foreach ($configOverrides as $key => $value) {
            config([$key => $value]);
        }

        $middleware = $this->app->make(ThreatDetectionMiddleware::class);

        return $middleware->handle($request, fn($req) => new Response('OK', 200));
    }

    /** @test */
    public function it_passes_request_through(): void
    {
        $request = Request::create('/test-path', 'GET');

        $response = $this->runMiddleware($request);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    /** @test */
    public function it_skips_when_disabled(): void
    {
        $request = Request::create('/test', 'GET', ['q' => "' UNION SELECT * FROM users"]);

        $response = $this->runMiddleware($request, [
            'threat-detection.enabled' => false,
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_skips_whitelisted_ips(): void
    {
        $request = Request::create('/test', 'GET', ['q' => "'; DROP TABLE users;--"]);
        $request->server->set('REMOTE_ADDR', '192.168.1.100');

        $response = $this->runMiddleware($request, [
            'threat-detection.whitelisted_ips' => ['192.168.1.100'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }

    /** @test */
    public function it_skips_paths_matching_skip_patterns(): void
    {
        $request = Request::create('/public/assets/logo.png', 'GET');

        $response = $this->runMiddleware($request, [
            'threat-detection.skip_paths' => ['public/assets/*'],
        ]);

        $this->assertEquals(200, $response->getStatusCode());
    }
}
