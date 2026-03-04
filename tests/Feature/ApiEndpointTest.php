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
        $this->createExclusionRulesTable();
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

    /** @test */
    public function mark_false_positive_creates_exclusion_rule(): void
    {
        $this->seedThreats(1);

        $response = $this->postJson('/api/threat-detection/threats/1/false-positive', [
            'reason' => 'Not a real threat',
        ]);

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $this->assertDatabaseHas('threat_logs', [
            'id' => 1,
            'is_false_positive' => true,
        ]);

        $this->assertDatabaseHas('threat_exclusion_rules', [
            'created_from_threat_id' => 1,
            'reason' => 'Not a real threat',
            'is_active' => true,
        ]);
    }

    /** @test */
    public function mark_false_positive_returns_404_for_missing_threat(): void
    {
        $response = $this->postJson('/api/threat-detection/threats/999/false-positive');

        $response->assertStatus(404);
    }

    /** @test */
    public function exclusion_rules_endpoint_lists_rules(): void
    {
        DB::table('threat_exclusion_rules')->insert([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->getJson('/api/threat-detection/exclusion-rules');

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $this->assertCount(1, $response->json('data'));
    }

    /** @test */
    public function delete_exclusion_rule_works(): void
    {
        $id = DB::table('threat_exclusion_rules')->insertGetId([
            'pattern_label' => 'XSS Script Tag',
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $response = $this->deleteJson("/api/threat-detection/exclusion-rules/{$id}");

        $response->assertStatus(200)
            ->assertJson(['success' => true]);

        $this->assertDatabaseMissing('threat_exclusion_rules', ['id' => $id]);
    }

    /** @test */
    public function delete_exclusion_rule_returns_404_for_missing(): void
    {
        $response = $this->deleteJson('/api/threat-detection/exclusion-rules/999');

        $response->assertStatus(404);
    }
}
