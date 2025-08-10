#!/usr/bin/env python3
"""
Performance monitoring script for Enterprise OSINT Platform
"""
import asyncio
import httpx
import time
import json
import argparse
import statistics
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class TestResult:
    success: bool
    response_time: float
    status_code: int
    error: str = None


class PerformanceMonitor:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.results: Dict[str, List[TestResult]] = {}
        
    async def test_endpoint_async(self, endpoint: str, concurrent: int = 10, total: int = 100) -> List[TestResult]:
        """Test endpoint with async HTTP requests"""
        async with httpx.AsyncClient(timeout=30) as client:
            semaphore = asyncio.Semaphore(concurrent)
            
            async def make_request():
                async with semaphore:
                    start_time = time.time()
                    try:
                        response = await client.get(f"{self.base_url}{endpoint}")
                        end_time = time.time()
                        return TestResult(
                            success=True,
                            response_time=end_time - start_time,
                            status_code=response.status_code
                        )
                    except Exception as e:
                        end_time = time.time()
                        return TestResult(
                            success=False,
                            response_time=end_time - start_time,
                            status_code=0,
                            error=str(e)
                        )
            
            tasks = [make_request() for _ in range(total)]
            return await asyncio.gather(*tasks)
    
    def test_endpoint_sync(self, endpoint: str, concurrent: int = 10, total: int = 100) -> List[TestResult]:
        """Test endpoint with sync HTTP requests using thread pool"""
        def make_request():
            start_time = time.time()
            try:
                import requests
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                end_time = time.time()
                return TestResult(
                    success=True,
                    response_time=end_time - start_time,
                    status_code=response.status_code
                )
            except Exception as e:
                end_time = time.time()
                return TestResult(
                    success=False,
                    response_time=end_time - start_time,
                    status_code=0,
                    error=str(e)
                )
        
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            futures = [executor.submit(make_request) for _ in range(total)]
            return [f.result() for f in futures]
    
    def analyze_results(self, results: List[TestResult], test_name: str) -> Dict[str, Any]:
        """Analyze test results and generate statistics"""
        if not results:
            return {"error": "No results to analyze"}
        
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        response_times = [r.response_time for r in successful]
        
        stats = {
            "test_name": test_name,
            "total_requests": len(results),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": len(successful) / len(results) * 100,
            "response_times": {
                "min": min(response_times) * 1000 if response_times else 0,
                "max": max(response_times) * 1000 if response_times else 0,
                "avg": statistics.mean(response_times) * 1000 if response_times else 0,
                "median": statistics.median(response_times) * 1000 if response_times else 0,
                "p95": statistics.quantiles(response_times, n=20)[18] * 1000 if len(response_times) > 1 else 0,
                "p99": statistics.quantiles(response_times, n=100)[98] * 1000 if len(response_times) > 1 else 0,
            },
            "errors": [r.error for r in failed if r.error][:5]  # First 5 errors
        }
        
        return stats
    
    async def comprehensive_test(self):
        """Run comprehensive performance tests"""
        print("🚀 Starting Enterprise OSINT Platform Performance Tests\n")
        
        # Test configurations
        test_configs = [
            {"endpoint": "/health", "name": "Health Check", "concurrent": 20, "total": 200},
            {"endpoint": "/metrics", "name": "Metrics Endpoint", "concurrent": 10, "total": 50},
            {"endpoint": "/api/v1/health", "name": "API Health", "concurrent": 15, "total": 100},
        ]
        
        all_results = {}
        
        for config in test_configs:
            print(f"Testing {config['name']} ({config['endpoint']})...")
            
            # Test async
            start_time = time.time()
            results = await self.test_endpoint_async(
                config["endpoint"], 
                config["concurrent"], 
                config["total"]
            )
            end_time = time.time()
            
            stats = self.analyze_results(results, f"{config['name']} (Async)")
            stats["total_time"] = end_time - start_time
            stats["rps"] = config["total"] / stats["total_time"]
            
            all_results[config["name"]] = stats
            
            # Print results
            print(f"  ✓ Requests: {stats['total_requests']}")
            print(f"  ✓ Success Rate: {stats['success_rate']:.1f}%")
            print(f"  ✓ RPS: {stats['rps']:.1f}")
            print(f"  ✓ Avg Response: {stats['response_times']['avg']:.1f}ms")
            print(f"  ✓ P95 Response: {stats['response_times']['p95']:.1f}ms")
            print()
            
        return all_results
    
    def test_celery_performance(self):
        """Test Celery task performance"""
        print("🔧 Testing Celery Task Performance...")
        try:
            from app.tasks.simple_tasks import test_task, investigate_target_simple
            
            # Test simple tasks
            start_time = time.time()
            tasks = [test_task.delay(f"perf_test_{i}") for i in range(10)]
            results = []
            
            for task in tasks:
                try:
                    result = task.get(timeout=30)
                    results.append(True)
                except:
                    results.append(False)
            
            end_time = time.time()
            
            success_rate = sum(results) / len(results) * 100
            total_time = end_time - start_time
            tps = len(tasks) / total_time
            
            print(f"  ✓ Simple Tasks: {len(tasks)} submitted")
            print(f"  ✓ Success Rate: {success_rate:.1f}%") 
            print(f"  ✓ Tasks per Second: {tps:.2f}")
            print(f"  ✓ Total Time: {total_time:.2f}s")
            
            return {
                "celery_simple_tasks": {
                    "total_tasks": len(tasks),
                    "success_rate": success_rate,
                    "tasks_per_second": tps,
                    "total_time": total_time
                }
            }
            
        except ImportError:
            print("  ⚠️ Celery tasks not available in this context")
            return {}
    
    def generate_report(self, results: Dict[str, Any]):
        """Generate performance report"""
        print("\n" + "="*60)
        print("📊 ENTERPRISE OSINT PLATFORM PERFORMANCE REPORT")
        print("="*60)
        
        for test_name, stats in results.items():
            if "error" in stats:
                print(f"\n❌ {test_name}: {stats['error']}")
                continue
                
            print(f"\n📈 {test_name}")
            print(f"   Total Requests: {stats.get('total_requests', 'N/A')}")
            print(f"   Success Rate: {stats.get('success_rate', 0):.1f}%")
            if 'rps' in stats:
                print(f"   Requests/sec: {stats['rps']:.1f}")
            if 'tasks_per_second' in stats:
                print(f"   Tasks/sec: {stats['tasks_per_second']:.2f}")
            
            if 'response_times' in stats:
                rt = stats['response_times']
                print(f"   Response Times (ms):")
                print(f"     Avg: {rt['avg']:.1f}  |  P95: {rt['p95']:.1f}  |  P99: {rt['p99']:.1f}")
                print(f"     Min: {rt['min']:.1f}  |  Max: {rt['max']:.1f}")
        
        print(f"\n⏱️  Report generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)


async def main():
    parser = argparse.ArgumentParser(description="Performance monitoring for OSINT Platform")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL for testing")
    parser.add_argument("--celery", action="store_true", help="Include Celery performance tests")
    parser.add_argument("--output", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    monitor = PerformanceMonitor(args.url)
    
    # Run HTTP tests
    results = await monitor.comprehensive_test()
    
    # Run Celery tests if requested
    if args.celery:
        celery_results = monitor.test_celery_performance()
        results.update(celery_results)
    
    # Generate report
    monitor.generate_report(results)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())