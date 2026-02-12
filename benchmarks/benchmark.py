"""
NexusRPC Performance Benchmark Suite
Compares performance with different configurations
"""

import time
import asyncio
import statistics
import json
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
import numpy as np

from rpc.client import NexusRPCClient
from security.tls import TLSConfig
import grpc  # For comparison


class BenchmarkRunner:
    """RPC Framework Benchmark"""
    
    def __init__(self, host='localhost', port=50051):
        self.host = host
        self.port = port
        self.results = {}
    
    def benchmark_nexusrpc(self, concurrency=10, requests=1000, use_tls=True):
        """Benchmark NexusRPC performance"""
        
        # Configure TLS
        tls_config = None
        if use_tls:
            tls_config = TLSConfig(
                certfile='security/certs/client.crt',
                keyfile='security/certs/client.key',
                cafile='security/certs/ca.crt'
            )
        
        client = NexusRPCClient(
            host=self.host,
            port=self.port,
            tls_config=tls_config
        )
        
        # Warmup
        for _ in range(10):
            client.call('BenchmarkService', 'echo', 'warmup')
        
        # Benchmark
        latencies = []
        start_time = time.time()
        
        def make_request():
            start = time.time()
            client.call('BenchmarkService', 'echo', 'test')
            latency = (time.time() - start) * 1000  # ms
            latencies.append(latency)
        
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(make_request) for _ in range(requests)]
            for f in futures:
                f.result()
        
        total_time = time.time() - start_time
        rps = requests / total_time
        
        return {
            'rps': rps,
            'avg_latency': statistics.mean(latencies),
            'p50_latency': np.percentile(latencies, 50),
            'p95_latency': np.percentile(latencies, 95),
            'p99_latency': np.percentile(latencies, 99),
            'min_latency': min(latencies),
            'max_latency': max(latencies),
            'total_time': total_time
        }
    
    def run_benchmarks(self):
        """Run all benchmarks"""
        
        print("🚀 NexusRPC Performance Benchmark")
        print("=" * 60)
        
        # Test different concurrency levels
        concurrency_levels = [1, 10, 25, 50, 100]
        
        for concurrency in concurrency_levels:
            print(f"\n📊 Concurrency: {concurrency} clients")
            
            # No TLS
            print("  Testing without TLS...")
            result = self.benchmark_nexusrpc(
                concurrency=concurrency,
                requests=1000,
                use_tls=False
            )
            self.results[f'no_tls_{concurrency}'] = result
            print(f"    RPS: {result['rps']:.2f}, "
                  f"P95: {result['p95_latency']:.2f}ms")
            
            # With TLS
            print("  Testing with TLS...")
            result = self.benchmark_nexusrpc(
                concurrency=concurrency,
                requests=1000,
                use_tls=True
            )
            self.results[f'tls_{concurrency}'] = result
            print(f"    RPS: {result['rps']:.2f}, "
                  f"P95: {result['p95_latency']:.2f}ms")
        
        # Save results
        with open('benchmarks/results/nexusrpc_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.plot_results()
    
    def plot_results(self):
        """Generate performance graphs"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        concurrency_levels = [1, 10, 25, 50, 100]
        
        # RPS Comparison
        no_tls_rps = [self.results[f'no_tls_{c}']['rps'] for c in concurrency_levels]
        tls_rps = [self.results[f'tls_{c}']['rps'] for c in concurrency_levels]
        
        ax1.plot(concurrency_levels, no_tls_rps, 'b-', label='No TLS')
        ax1.plot(concurrency_levels, tls_rps, 'r-', label='TLS 1.3')
        ax1.set_xlabel('Concurrency')
        ax1.set_ylabel('Requests/sec')
        ax1.set_title('Throughput Comparison')
        ax1.legend()
        ax1.grid(True)
        
        # Latency Percentiles
        ax2.plot(concurrency_levels, 
                [self.results[f'tls_{c}']['p50_latency'] for c in concurrency_levels], 
                'g-', label='P50')
        ax2.plot(concurrency_levels,
                [self.results[f'tls_{c}']['p95_latency'] for c in concurrency_levels],
                'y-', label='P95')
        ax2.plot(concurrency_levels,
                [self.results[f'tls_{c}']['p99_latency'] for c in concurrency_levels],
                'r-', label='P99')
        ax2.set_xlabel('Concurrency')
        ax2.set_ylabel('Latency (ms)')
        ax2.set_title('Latency Percentiles (with TLS)')
        ax2.legend()
        ax2.grid(True)
        
        # TLS Overhead
        overhead = [(t - n) / n * 100 for t, n in zip(tls_rps, no_tls_rps)]
        ax3.bar(concurrency_levels, overhead)
        ax3.set_xlabel('Concurrency')
        ax3.set_ylabel('Overhead (%)')
        ax3.set_title('TLS Performance Overhead')
        ax3.grid(True)
        
        # Success Rate
        ax4.text(0.5, 0.5, 
                f"NexusRPC Performance Summary\n\n"
                f"Peak Throughput: {max(tls_rps):.0f} req/s\n"
                f"Avg Latency (P95): {np.mean([self.results[f'tls_{c}']['p95_latency'] for c in concurrency_levels]):.1f}ms\n"
                f"TLS Overhead: {np.mean(overhead):.1f}%\n"
                f"Zero failures in {sum([self.results[f'tls_{c}']['total_time'] for c in concurrency_levels]):.1f}s test",
                ha='center', va='center', fontsize=12, transform=ax4.transAxes)
        ax4.set_title('Summary')
        ax4.axis('off')
        
        plt.tight_layout()
        plt.savefig('benchmarks/results/performance_graph.png', dpi=150)
        plt.show()


if __name__ == '__main__':
    benchmark = BenchmarkRunner()
    benchmark.run_benchmarks()