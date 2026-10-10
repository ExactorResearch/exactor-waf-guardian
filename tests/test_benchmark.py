"""Tests for WAF Benchmark Runner."""

import pytest
from exactor_waf.benchmark.runner import WAFBenchmarkRunner
from exactor_waf.benchmark.reporter import generate_ascii_table, generate_markdown_report


def test_benchmark_runner_execution():
    runner = WAFBenchmarkRunner()
    result = runner.run_benchmark(num_requests=20, attack_ratio=0.5, seed=42)
    
    assert result.dataset_size == 20
    assert len(result.agent_metrics) == 3
    
    exactor_metrics = next(m for k, m in result.agent_metrics.items() if "Exactor" in k)
    assert exactor_metrics.total_requests == 20
    assert exactor_metrics.accuracy >= 0.90
    assert exactor_metrics.total_cost_usd == 0.0

    ascii_table = generate_ascii_table(result)
    assert "EXACTOR-WAF-GUARDIAN" in ascii_table

    md_report = generate_markdown_report(result)
    assert "Exactor WAF Guardian" in md_report
