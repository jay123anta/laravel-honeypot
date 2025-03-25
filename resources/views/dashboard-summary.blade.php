@extends('honeypot::layouts.app')

@section('content')
<div class="container">
    <h2 class="mb-4">Honeypot Threat Summary</h2>
    <p><strong>Total Threats Detected:</strong> {{ $logCount }}</p>

    <h4 class="mt-4">Recent Threats</h4>
    <table class="table table-sm table-bordered">
        <thead>
            <tr>
                <th>IP</th>
                <th>Type</th>
                <th>URL</th>
                <th>Time</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($latestLogs as $log)
            <tr>
                <td>{{ $log->ip_address }}</td>
                <td>{{ $log->type }}</td>
                <td>{{ $log->url }}</td>
                <td>{{ $log->created_at }}</td>
            </tr>
            @endforeach
        </tbody>
    </table>
</div>
@endsection
