import os
import pytest
from scripts.benchmark_eps import (
    SyntheticTelemetryGenerator,
    IngestionGatewayBenchmark,
    StreamProcessorBenchmark,
    StateStorageBenchmark,
    GraphMicroBatchBenchmark,
    BenchmarkReportGenerator,
    run_benchmarks,
)


def test_synthetic_telemetry_generator():
    sysmon_events = SyntheticTelemetryGenerator.generate_sysmon_events(50)
    assert len(sysmon_events) == 50
    assert "System" in sysmon_events[0]
    assert "EventData" in sysmon_events[0]

    internal_events = SyntheticTelemetryGenerator.generate_internal_events(50)
    assert len(internal_events) == 50
    assert "event_type" in internal_events[0]
    assert "event_id" in internal_events[0]


def test_ingestion_gateway_benchmark():
    stats, parsed = IngestionGatewayBenchmark.run(100)
    assert stats.count == 100
    assert stats.throughput_eps > 0
    assert parsed > 0
    assert stats.mean_ms >= 0


def test_stream_processor_benchmark():
    stats, alerts = StreamProcessorBenchmark.run(100, use_mock_redis=True)
    assert stats.count == 100
    assert stats.throughput_eps > 0
    assert isinstance(alerts, dict)
    assert "RULE_ENGINE" in alerts
    assert "CRED_DUMP" in alerts


def test_state_storage_benchmark():
    results = StateStorageBenchmark.run(100, use_mock=True)
    assert "add_event" in results
    assert "count_events" in results
    assert results["add_event"].count == 100
    assert results["add_event"].throughput_eps > 0


def test_graph_microbatch_benchmark():
    results = GraphMicroBatchBenchmark.run(200, batch_sizes=[50, 100])
    assert 50 in results
    assert 100 in results
    assert results[50].throughput_eps > 0


def test_full_benchmark_run_and_report_export(tmp_path):
    report_file = os.path.join(tmp_path, "TEST_REPORT.md")
    json_file = os.path.join(tmp_path, "TEST_RESULTS.json")
    results = run_benchmarks(mode="all", count=100, mock=True, report_file=report_file, json_file=json_file)
    assert "ingestion_gateway" in results
    assert "stream_processor" in results
    assert "state_storage" in results
    assert "graph_micro_batch" in results

    generated = BenchmarkReportGenerator.generate_markdown(results, output_file=report_file)
    assert os.path.exists(generated)
    with open(generated, "r", encoding="utf-8") as f:
        content = f.read()
    assert "CyberTrace-Graph" in content
    assert "Executive Summary" in content
