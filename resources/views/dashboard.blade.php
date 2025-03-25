@extends('honeypot::layouts.app')

@section('content')
<div class="container">
    <h2 class="mb-4">Honeypot Security Dashboard</h2>

    <div class="mb-3">
        <a href="{{ route('honeypot.export') }}" class="btn btn-sm btn-success">Export CSV</a>
    </div>

    <div class="row mb-4">
        <div class="col-md-6">
            <div class="chart-container">
                <canvas id="threatTrendChart" width="400" height="300"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="chart-container">
                <canvas id="topIpsChart" width="400" height="300"></canvas>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-md-6 offset-md-3">
            <div class="chart-container">
                <canvas id="attackTypesChart" width="400" height="300"></canvas>
            </div>
        </div>
    </div>

    <table class="table table-bordered table-sm">
        <thead class="table-dark">
            <tr>
                <th>IP Address</th>
                <th>Threat Type</th>
                <th>URL</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($logs as $log)
                <tr>
                    <td>{{ $log->ip_address }}</td>
                    <td>{{ $log->type }}</td>
                    <td>{{ $log->url }}</td>
                    <td>{{ $log->created_at }}</td>
                </tr>
            @endforeach
        </tbody>
    </table>
    {{ $logs->links() }}
</div>
@endsection

@section('scripts')
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    // Debug chart data in browser console
    console.log("Threat Trends:", @json($threatTrends));
    console.log("Top IPs:", @json($topIps));
    console.log("Attack Types:", @json($attackTypes));

    const threatTrendCtx = document.getElementById('threatTrendChart');
    const topIpsCtx = document.getElementById('topIpsChart');
    const attackTypesCtx = document.getElementById('attackTypesChart');

    if (threatTrendCtx && topIpsCtx && attackTypesCtx) {
        new Chart(threatTrendCtx, {
            type: 'line',
            data: {
                labels: @json($threatTrends->pluck('date')),
                datasets: [{
                    label: 'Threats Over Time',
                    data: @json($threatTrends->pluck('count')),
                    borderColor: 'red',
                    tension: 0.3,
                    fill: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        new Chart(topIpsCtx, {
            type: 'bar',
            data: {
                labels: @json($topIps->pluck('ip_address')),
                datasets: [{
                    label: 'Top IPs',
                    data: @json($topIps->pluck('count')),
                    backgroundColor: 'blue'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        new Chart(attackTypesCtx, {
            type: 'pie',
            data: {
                labels: @json($attackTypes->pluck('type')),
                datasets: [{
                    label: 'Attack Types',
                    data: @json($attackTypes->pluck('count')),
                    backgroundColor: ['orange', 'green', 'purple', 'cyan', 'gray']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    } else {
        console.error("Canvas elements not found");
    }
</script>
@endsection
