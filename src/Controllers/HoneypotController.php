<?php 
namespace Security\Honeypot\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Security\Honeypot\Models\AttackLog;
use Illuminate\Support\Facades\Response;

class HoneypotController extends Controller
{
    public function dashboard(Request $request)
    {
        $logs = AttackLog::latest()->paginate(50);

        // For chart data
        $threatTrends = AttackLog::selectRaw('DATE(created_at) as date, COUNT(*) as count')
            ->groupBy('date')
            ->orderBy('date')
            ->get();

        $topIps = AttackLog::selectRaw('ip_address, COUNT(*) as count')
            ->groupBy('ip_address')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        $attackTypes = AttackLog::selectRaw('type, COUNT(*) as count')
            ->groupBy('type')
            ->orderByDesc('count')
            ->limit(5)
            ->get();

        return view('honeypot::dashboard', compact('logs', 'threatTrends', 'topIps', 'attackTypes'));
    }

    public function exportCsv()
    {
        $logs = AttackLog::all();
        $csv = "IP Address,Threat Type,URL,Timestamp\n";

        foreach ($logs as $log) {
            $csv .= "{$log->ip_address},{$log->type},{$log->url},{$log->created_at}\n";
        }

        return Response::make($csv, 200, [
            'Content-Type' => 'text/csv',
            'Content-Disposition' => 'attachment; filename="honeypot_logs.csv"',
        ]);
    }
}