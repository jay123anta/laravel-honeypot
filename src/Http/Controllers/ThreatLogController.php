<?php

namespace JayAnta\ThreatDetection\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Response;
use JayAnta\ThreatDetection\Services\ThreatDetectionService;
use JayAnta\ThreatDetection\Services\ExclusionRuleService;

class ThreatLogController extends Controller
{
    protected string $table;

    public function __construct()
    {
        $this->table = config('threat-detection.table_name', 'threat_logs');
    }

    /**
     * Get paginated threat logs with optional filters.
     */
    public function index(Request $request): JsonResponse
    {
        $request->validate([
            'per_page' => 'sometimes|integer|min:1|max:100',
            'level' => 'sometimes|in:high,medium,low',
            'date_from' => 'sometimes|date',
            'date_to' => 'sometimes|date',
        ]);

        $query = DB::table($this->table)
            ->select('id', 'ip_address', 'url', 'type', 'threat_level', 'confidence_score', 'confidence_label', 'is_false_positive', 'action_taken', 'country_code', 'country_name', 'cloud_provider', 'is_cloud_ip', 'is_foreign', 'created_at');

        // Search keyword
        if ($request->has('keyword')) {
            $keyword = '%' . $request->keyword . '%';
            $query->where(function ($q) use ($keyword) {
                $q->where('ip_address', 'like', $keyword)
                    ->orWhere('type', 'like', $keyword)
                    ->orWhere('url', 'like', $keyword);
            });
        }

        // Filters
        if ($request->filled('ip')) {
            $query->where('ip_address', $request->ip);
        }
        if ($request->filled('type')) {
            $query->where('type', 'like', '%' . $request->type . '%');
        }
        if ($request->filled('level')) {
            $query->where('threat_level', $request->level);
        }
        if ($request->filled('country')) {
            $query->where('country_code', $request->country);
        }
        if ($request->filled('is_foreign')) {
            $query->where('is_foreign', $request->boolean('is_foreign'));
        }
        if ($request->filled('cloud_provider')) {
            $query->where('cloud_provider', $request->cloud_provider);
        }
        if ($request->has('is_false_positive')) {
            $query->where('is_false_positive', $request->boolean('is_false_positive'));
        }
        if ($request->filled('date_from')) {
            $query->where('created_at', '>=', $request->date_from);
        }
        if ($request->filled('date_to')) {
            $query->where('created_at', '<=', $request->date_to);
        }

        return response()->json([
            'success' => true,
            'data' => $query->latest()->paginate($request->get('per_page', 20))
        ]);
    }

    /**
     * Get threat summary statistics.
     */
    public function summary(): JsonResponse
    {
        $byType = DB::table($this->table)
            ->select('type', DB::raw('COUNT(*) as count'))
            ->groupBy('type')
            ->orderByDesc('count')
            ->limit(10)
            ->get();

        $byLevel = DB::table($this->table)
            ->select('threat_level', DB::raw('COUNT(*) as count'))
            ->groupBy('threat_level')
            ->orderByDesc('count')
            ->get();

        $byIP = DB::table($this->table)
            ->select('ip_address', 'country_name', 'cloud_provider', DB::raw('COUNT(*) as count'))
            ->groupBy('ip_address', 'country_name', 'cloud_provider')
            ->orderByDesc('count')
            ->limit(10)
            ->get();

        $byCountry = DB::table($this->table)
            ->select('country_code', 'country_name', DB::raw('COUNT(*) as count'))
            ->whereNotNull('country_code')
            ->groupBy('country_code', 'country_name')
            ->orderByDesc('count')
            ->limit(10)
            ->get();

        $byCloudProvider = DB::table($this->table)
            ->select('cloud_provider', DB::raw('COUNT(*) as count'))
            ->whereNotNull('cloud_provider')
            ->groupBy('cloud_provider')
            ->orderByDesc('count')
            ->get();

        $byDate = DB::table($this->table)
            ->selectRaw("DATE(created_at) as date, COUNT(*) as count")
            ->where('created_at', '>=', now()->subDays(30))
            ->groupByRaw("DATE(created_at)")
            ->orderBy('date', 'asc')
            ->get();

        return response()->json([
            'success' => true,
            'data' => [
                'byType' => $byType,
                'byLevel' => $byLevel,
                'byIP' => $byIP,
                'byCountry' => $byCountry,
                'byCloudProvider' => $byCloudProvider,
                'byDate' => $byDate,
            ]
        ]);
    }

    /**
     * Get overall statistics.
     */
    public function stats(): JsonResponse
    {
        $stats = [
            'total_threats' => DB::table($this->table)->count(),
            'high_severity' => DB::table($this->table)->where('threat_level', 'high')->count(),
            'medium_severity' => DB::table($this->table)->where('threat_level', 'medium')->count(),
            'low_severity' => DB::table($this->table)->where('threat_level', 'low')->count(),
            'unique_ips' => DB::table($this->table)->distinct('ip_address')->count('ip_address'),
            'foreign_ips' => DB::table($this->table)->where('is_foreign', true)->distinct('ip_address')->count('ip_address'),
            'cloud_attacks' => DB::table($this->table)->whereNotNull('cloud_provider')->count(),
            'today' => DB::table($this->table)->whereDate('created_at', today())->count(),
            'last_hour' => DB::table($this->table)->where('created_at', '>=', now()->subHour())->count(),
        ];

        return response()->json([
            'success' => true,
            'data' => $stats
        ]);
    }

    /**
     * Get live threat count (last hour).
     */
    public function liveCount(): JsonResponse
    {
        $count = DB::table($this->table)
            ->where('created_at', '>=', now()->subHour())
            ->count();

        return response()->json([
            'success' => true,
            'data' => ['count' => $count]
        ]);
    }

    /**
     * Get single threat details.
     */
    public function show(int $id): JsonResponse
    {
        $threat = DB::table($this->table)
            ->where('id', $id)
            ->first();

        if (!$threat) {
            return response()->json(['success' => false, 'message' => 'Threat not found'], 404);
        }

        return response()->json([
            'success' => true,
            'data' => $threat
        ]);
    }

    /**
     * Get IP address statistics.
     */
    public function ipStats(Request $request, ThreatDetectionService $service): JsonResponse
    {
        $request->validate(['ip' => 'required|ip']);

        $ip = $request->input('ip');
        $stats = $service->getIpStatistics($ip);

        $recentThreats = DB::table($this->table)
            ->where('ip_address', $ip)
            ->select('id', 'url', 'type', 'threat_level', 'created_at')
            ->orderByDesc('created_at')
            ->limit(10)
            ->get();

        $levelBreakdown = DB::table($this->table)
            ->where('ip_address', $ip)
            ->select('threat_level', DB::raw('COUNT(*) as count'))
            ->groupBy('threat_level')
            ->get()
            ->pluck('count', 'threat_level')
            ->toArray();

        return response()->json([
            'success' => true,
            'data' => [
                'ip_address' => $ip,
                'statistics' => $stats,
                'recent_threats' => $recentThreats,
                'level_breakdown' => [
                    'high' => $levelBreakdown['high'] ?? 0,
                    'medium' => $levelBreakdown['medium'] ?? 0,
                    'low' => $levelBreakdown['low'] ?? 0,
                ],
            ]
        ]);
    }

    /**
     * Get threat correlation analysis.
     */
    public function correlation(Request $request, ThreatDetectionService $service): JsonResponse
    {
        $request->validate(['type' => 'sometimes|in:all,coordinated,campaigns,rapid']);
        $type = $request->input('type', 'all');
        $data = [];

        if ($type === 'all' || $type === 'coordinated') {
            $data['coordinated_attacks'] = $service->detectCoordinatedAttacks(15, 3);
        }

        if ($type === 'all' || $type === 'campaigns') {
            $data['attack_campaigns'] = $service->detectAttackCampaigns(24);
        }

        if ($type === 'all' || $type === 'rapid') {
            $data['rapid_attackers'] = $service->detectRapidAttacks(5, 10);
        }

        if ($type === 'all') {
            $data['summary'] = $service->getCorrelationSummary();
        }

        return response()->json([
            'success' => true,
            'data' => $data
        ]);
    }

    /**
     * Export threats to CSV.
     */
    public function export(Request $request)
    {
        $query = DB::table($this->table)
            ->select('id', 'created_at', 'ip_address', 'url', 'type', 'threat_level', 'confidence_score', 'is_false_positive', 'action_taken', 'country_name', 'cloud_provider');

        if ($request->filled('keyword')) {
            $keyword = '%' . $request->keyword . '%';
            $query->where(function ($q) use ($keyword) {
                $q->where('ip_address', 'like', $keyword)
                    ->orWhere('url', 'like', $keyword)
                    ->orWhere('type', 'like', $keyword);
            });
        }

        if ($request->filled('level')) {
            $query->where('threat_level', $request->level);
        }

        $logs = $query->orderByDesc('created_at')->limit(10000)->get();

        $csvHeader = ['ID', 'Time', 'IP Address', 'URL', 'Type', 'Level', 'Confidence', 'False Positive', 'Action', 'Country', 'Cloud Provider'];
        $csvData = $logs->map(function ($log) {
            return [
                $log->id,
                $log->created_at,
                $log->ip_address,
                $log->url,
                $log->type,
                $log->threat_level,
                ($log->confidence_score ?? 0) . '%',
                ($log->is_false_positive ?? false) ? 'Yes' : 'No',
                $log->action_taken,
                $log->country_name ?? 'N/A',
                $log->cloud_provider ?? 'N/A',
            ];
        })->toArray();

        $filename = 'threat_logs_' . now()->format('Ymd_His') . '.csv';

        $handle = fopen('php://temp', 'r+');
        fputcsv($handle, $csvHeader);
        foreach ($csvData as $row) {
            fputcsv($handle, $row);
        }
        rewind($handle);
        $csvOutput = stream_get_contents($handle);
        fclose($handle);

        return Response::make($csvOutput, 200, [
            'Content-Type' => 'text/csv',
            'Content-Disposition' => "attachment; filename=\"$filename\"",
        ]);
    }

    /**
     * Get threats by country.
     */
    public function byCountry(): JsonResponse
    {
        $data = DB::table($this->table)
            ->select('country_code', 'country_name', DB::raw('COUNT(*) as count'), DB::raw('COUNT(DISTINCT ip_address) as unique_ips'))
            ->whereNotNull('country_code')
            ->groupBy('country_code', 'country_name')
            ->orderByDesc('count')
            ->limit(20)
            ->get();

        return response()->json([
            'success' => true,
            'data' => $data
        ]);
    }

    /**
     * Get threats by cloud provider.
     */
    public function byCloudProvider(): JsonResponse
    {
        $data = DB::table($this->table)
            ->select('cloud_provider', DB::raw('COUNT(*) as count'), DB::raw('COUNT(DISTINCT ip_address) as unique_ips'))
            ->whereNotNull('cloud_provider')
            ->groupBy('cloud_provider')
            ->orderByDesc('count')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $data
        ]);
    }

    /**
     * Get top offending IPs.
     */
    public function topIps(Request $request): JsonResponse
    {
        $request->validate(['limit' => 'sometimes|integer|min:1|max:100']);
        $limit = $request->get('limit', 20);

        $data = DB::table($this->table)
            ->select('ip_address', 'country_name', 'cloud_provider', 'is_foreign', DB::raw('COUNT(*) as threat_count'))
            ->groupBy('ip_address', 'country_name', 'cloud_provider', 'is_foreign')
            ->orderByDesc('threat_count')
            ->limit($limit)
            ->get();

        return response()->json([
            'success' => true,
            'data' => $data
        ]);
    }

    /**
     * Get threat timeline.
     */
    public function timeline(Request $request): JsonResponse
    {
        $request->validate(['days' => 'sometimes|integer|min:1|max:365']);
        $days = $request->get('days', 7);

        $data = DB::table($this->table)
            ->selectRaw('DATE(created_at) as date, threat_level, COUNT(*) as count')
            ->where('created_at', '>=', now()->subDays($days))
            ->groupByRaw('DATE(created_at), threat_level')
            ->orderBy('date')
            ->get();

        return response()->json([
            'success' => true,
            'data' => $data
        ]);
    }

    /**
     * Mark a threat as false positive and create an exclusion rule.
     */
    public function markFalsePositive(Request $request, int $id, ExclusionRuleService $exclusionService): JsonResponse
    {
        $threat = DB::table($this->table)->where('id', $id)->first();

        if (!$threat) {
            return response()->json(['success' => false, 'message' => 'Threat not found'], 404);
        }

        DB::table($this->table)->where('id', $id)->update([
            'is_false_positive' => true,
            'updated_at' => now(),
        ]);

        $rule = $exclusionService->createFromThreat(
            $id,
            $request->user()?->id,
            $request->input('reason')
        );

        return response()->json([
            'success' => true,
            'message' => 'Marked as false positive and exclusion rule created.',
            'data' => [
                'threat_id' => $id,
                'exclusion_rule' => $rule,
            ],
        ]);
    }

    /**
     * List all exclusion rules.
     */
    public function exclusionRules(ExclusionRuleService $exclusionService): JsonResponse
    {
        return response()->json([
            'success' => true,
            'data' => $exclusionService->all(),
        ]);
    }

    /**
     * Delete an exclusion rule.
     */
    public function deleteExclusionRule(int $id, ExclusionRuleService $exclusionService): JsonResponse
    {
        $deleted = $exclusionService->delete($id);

        if (!$deleted) {
            return response()->json(['success' => false, 'message' => 'Rule not found'], 404);
        }

        return response()->json([
            'success' => true,
            'message' => 'Exclusion rule deleted.',
        ]);
    }
}
