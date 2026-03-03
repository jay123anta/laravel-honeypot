<?php

namespace JayAnta\ThreatDetection\Tests\Feature;

use JayAnta\ThreatDetection\Tests\TestCase;
use Illuminate\Support\Facades\DB;

class ApiEndpointTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->createThreatLogsTable();
    }

    private function seedThreats(int $count = 5): void
    {
        $rows = [];
        for ($i = 0; $i < $count; $i++) {
            $rows[] = [
                'ip_address' => "10.0.0.{$i}",
                'url' => "https://example.com/test/{$i}",
                'user_agent' => 'PHPUnit/Test',
                'type' => '[test] SQL Injection',
                'payload' => 'SELECT * FROM users',
                'threat_level' => ['high', 'medium', 'low'][$i % 3],
                'action_taken' => 'logged',
                'created_at' => now(),
                'updated_at' => now(),
            ];
        }
        DB::table('threat_logs')->insert($rows);
    }

    /** @test */
    public function stats_endpoint_returns_correct_structure(): void
    {
        $this->seedThreats(3);

        $response = $this->getJson('/api/threat-detection/stats');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'total_threats',
                    'high_severity',
                    'medium_severity',
                    'low_severity',
                    'unique_ips',
                    'today',
                    'last_hour',
                ],
            ])
            ->assertJson(['success' => true]);

        $this->assertEquals(3, $response->json('data.total_threats'));
    }

    /** @test */
    public function threats_endpoint_returns_paginated_data(): void
    {
        $this->seedThreats(25);

        $response = $this->getJson('/api/threat-detection/threats?per_page=10');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'data',
                    'current_page',
                    'last_page',
                    'per_page',
                    'total',
                ],
            ]);

        $data = $response->json('data');
        $this->assertCount(10, $data['data']);
        $this->assertEquals(25, $data['total']);
    }

    /** @test */
    public function threats_endpoint_supports_level_filter(): void
    {
        $this->seedThreats(12);

        $response = $this->getJson('/api/threat-detection/threats?level=high');

        $response->assertStatus(200);
        $threats = $response->json('data.data');

        foreach ($threats as $threat) {
            $this->assertEquals('high', $threat['threat_level']);
        }
    }

    /** @test */
    public function stats_returns_zeros_when_empty(): void
    {
        $response = $this->getJson('/api/threat-detection/stats');

        $response->assertStatus(200);
        $data = $response->json('data');
        $this->assertEquals(0, $data['total_threats']);
        $this->assertEquals(0, $data['unique_ips']);
    }

    /** @test */
    public function live_count_endpoint_works(): void
    {
        $this->seedThreats(3);

        $response = $this->getJson('/api/threat-detection/live-count');

        $response->assertStatus(200)
            ->assertJsonStructure(['count']);

        $this->assertEquals(3, $response->json('count'));
    }

    /** @test */
    public function show_endpoint_returns_single_threat(): void
    {
        $this->seedThreats(1);

        $response = $this->getJson('/api/threat-detection/threats/1');

        $response->assertStatus(200)
            ->assertJson(['success' => true])
            ->assertJsonStructure([
                'success',
                'data' => ['id', 'ip_address', 'url', 'type', 'threat_level'],
            ]);
    }

    /** @test */
    public function show_endpoint_returns_404_for_missing_threat(): void
    {
        $response = $this->getJson('/api/threat-detection/threats/999');

        $response->assertStatus(404);
    }
}
