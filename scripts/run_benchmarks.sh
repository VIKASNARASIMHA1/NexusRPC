#!/bin/bash
# NexusRPC Benchmark Runner

set -e

echo "🚀 NexusRPC Benchmark Suite"
echo "==========================="

# Check if server is running
if ! nc -z localhost 50051 2>/dev/null; then
    echo "⚠️  RPC server not running. Starting test server..."
    python -m rpc.server_cli --port 50051 --tls --daemon &
    SERVER_PID=$!
    sleep 3
fi

# Run benchmarks
echo -e "\n📊 Running performance benchmarks..."
python -m benchmarks.benchmark

# Run gRPC comparison if available
echo -e "\n📊 Running gRPC comparison..."
python -m benchmarks.compare_grpc

# Generate reports
echo -e "\n📈 Generating benchmark reports..."
cd benchmarks/results

# Create HTML report
cat > report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>NexusRPC Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #2c3e50; }
        .chart { margin: 20px 0; }
        .metric { display: inline-block; margin: 10px; padding: 20px; 
                  background: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>NexusRPC Performance Benchmark Report</h1>
    <p>Generated: $(date)</p>
    
    <div class="chart">
        <img src="performance_graph.png" alt="Performance Graph" width="800">
    </div>
    
    <div class="chart">
        <img src="grpc_comparison.png" alt="gRPC Comparison" width="800">
    </div>
    
    <h2>Results Summary</h2>
    <pre>$(cat ../results/nexusrpc_results.json | python -m json.tool)</pre>
</body>
</html>
EOF

echo "✅ Report generated: benchmarks/results/report.html"

# Kill server if we started it
if [ ! -z "$SERVER_PID" ]; then
    kill $SERVER_PID 2>/dev/null || true
fi

echo -e "\n✅ Benchmark suite complete!"