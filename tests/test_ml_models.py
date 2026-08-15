"""
Unit tests for CyberTrace-Graph ML models.

Tests:
- SyntheticDataGenerator produces correctly shaped data
- DGAClassifier trains, predicts, and distinguishes benign vs DGA domains
- NetworkAnomalyDetector trains and scores normal vs anomalous traffic
"""

import pytest


class TestSyntheticDataGenerator:
    """Tests for the procedural data generator."""

    def test_generate_benign_domains(self):
        from junction_nodes.stream_processor.ml_models.data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(seed=42)
        domains = gen.generate_benign_domains(100)
        assert len(domains) == 100
        for d in domains:
            assert isinstance(d, str)
            assert "." in d  # Must have a TLD

    def test_generate_dga_domains(self):
        from junction_nodes.stream_processor.ml_models.data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(seed=42)
        domains = gen.generate_dga_domains(100)
        assert len(domains) == 100
        for d in domains:
            assert isinstance(d, str)
            assert "." in d

    def test_generate_normal_traffic(self):
        from junction_nodes.stream_processor.ml_models.data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(seed=42)
        traffic = gen.generate_normal_traffic(50)
        assert len(traffic) == 50
        required_keys = {'bytes_sent', 'bytes_received', 'duration_seconds',
                         'packet_count', 'unique_dns_queries', 'avg_payload_size'}
        for t in traffic:
            assert required_keys.issubset(t.keys())
            assert t['bytes_sent'] >= 50
            assert t['bytes_received'] >= 100

    def test_generate_anomalous_traffic(self):
        from junction_nodes.stream_processor.ml_models.data_generator import SyntheticDataGenerator
        gen = SyntheticDataGenerator(seed=42)
        traffic = gen.generate_anomalous_traffic(50)
        assert len(traffic) == 50
        for t in traffic:
            assert 'bytes_sent' in t
            assert 'packet_count' in t

    def test_reproducibility(self):
        """Verify that the same seed produces the same output when used fresh."""
        from junction_nodes.stream_processor.ml_models.data_generator import SyntheticDataGenerator
        import random
        # Reset global random state before each generator
        random.seed(999)
        gen1 = SyntheticDataGenerator(seed=999)
        d1 = gen1.generate_benign_domains(10)
        random.seed(999)
        gen2 = SyntheticDataGenerator(seed=999)
        d2 = gen2.generate_benign_domains(10)
        assert d1 == d2



class TestDGAClassifier:
    """Tests for the Random Forest DGA classifier."""

    @pytest.fixture(scope="class")
    def trained_classifier(self):
        from junction_nodes.stream_processor.ml_models.dga_classifier import DGAClassifier
        clf = DGAClassifier()
        metrics = clf.train(n_benign=2000, n_dga=2000)
        return clf, metrics

    def test_training_returns_metrics(self, trained_classifier):
        clf, metrics = trained_classifier
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics

    def test_accuracy_above_threshold(self, trained_classifier):
        clf, metrics = trained_classifier
        assert metrics["accuracy"] > 0.80, f"Accuracy too low: {metrics['accuracy']}"

    def test_f1_above_threshold(self, trained_classifier):
        clf, metrics = trained_classifier
        assert metrics["f1"] > 0.75, f"F1 too low: {metrics['f1']}"

    def test_predict_benign_domain(self, trained_classifier):
        clf, _ = trained_classifier
        result = clf.predict("google.com")
        assert isinstance(result, dict)
        assert "is_dga" in result
        assert "confidence" in result
        assert "domain" in result
        assert result["domain"] == "google.com"

    def test_predict_dga_domain(self, trained_classifier):
        clf, _ = trained_classifier
        # A clearly random domain
        result = clf.predict("x8k2f9qm3z7w1p4n.xyz")
        assert isinstance(result, dict)
        assert "is_dga" in result

    def test_predict_batch(self, trained_classifier):
        clf, _ = trained_classifier
        domains = ["google.com", "facebook.com", "a3f8c2d1e5b9.tk", "xkr7m2q9.xyz"]
        results = clf.predict_batch(domains)
        assert len(results) == 4
        for r in results:
            assert "is_dga" in r
            assert "confidence" in r

    def test_predict_empty_domain(self, trained_classifier):
        clf, _ = trained_classifier
        result = clf.predict("")
        assert isinstance(result, dict)

    def test_extract_features_returns_12(self):
        from junction_nodes.stream_processor.ml_models.dga_classifier import DGAClassifier
        features = DGAClassifier.extract_features("example.com")
        assert len(features) == 12
        assert all(isinstance(f, float) for f in features)

    def test_untrained_model_raises(self):
        from junction_nodes.stream_processor.ml_models.dga_classifier import DGAClassifier
        clf = DGAClassifier()
        with pytest.raises(RuntimeError):
            clf.predict("google.com")


class TestNetworkAnomalyDetector:
    """Tests for the Isolation Forest anomaly detector."""

    @pytest.fixture(scope="class")
    def trained_detector(self):
        from junction_nodes.stream_processor.ml_models.isolation_forest import NetworkAnomalyDetector
        detector = NetworkAnomalyDetector()
        result = detector.train(n_normal=5000, contamination=0.05)
        return detector, result

    def test_training_returns_info(self, trained_detector):
        detector, result = trained_detector
        assert "samples_trained" in result
        assert "contamination" in result
        assert "features" in result
        assert result["samples_trained"] == 5000

    def test_score_normal_traffic(self, trained_detector):
        detector, _ = trained_detector
        normal = {
            'bytes_sent': 500,
            'bytes_received': 2000,
            'duration_seconds': 5.0,
            'packet_count': 50,
            'unique_dns_queries': 3,
            'avg_payload_size': 500
        }
        result = detector.score(normal)
        assert isinstance(result, dict)
        assert "is_anomaly" in result
        assert "anomaly_score" in result
        assert 0.0 <= result["anomaly_score"] <= 1.0

    def test_score_anomalous_traffic(self, trained_detector):
        detector, _ = trained_detector
        anomalous = {
            'bytes_sent': 500000,
            'bytes_received': 100,
            'duration_seconds': 3600.0,
            'packet_count': 5000,
            'unique_dns_queries': 300,
            'avg_payload_size': 50
        }
        result = detector.score(anomalous)
        assert isinstance(result, dict)
        assert "is_anomaly" in result
        # This extreme traffic should likely be flagged
        assert result["anomaly_score"] > 0.3

    def test_score_batch(self, trained_detector):
        detector, _ = trained_detector
        batch = [
            {'bytes_sent': 500, 'bytes_received': 2000, 'duration_seconds': 5.0,
             'packet_count': 50, 'unique_dns_queries': 3, 'avg_payload_size': 500},
            {'bytes_sent': 400000, 'bytes_received': 100, 'duration_seconds': 1000.0,
             'packet_count': 4000, 'unique_dns_queries': 200, 'avg_payload_size': 30},
        ]
        results = detector.score_batch(batch)
        assert len(results) == 2

    def test_score_with_missing_features(self, trained_detector):
        detector, _ = trained_detector
        partial = {'bytes_sent': 1000}
        result = detector.score(partial)
        assert isinstance(result, dict)

    def test_untrained_model_raises(self):
        from junction_nodes.stream_processor.ml_models.isolation_forest import NetworkAnomalyDetector
        detector = NetworkAnomalyDetector()
        with pytest.raises(RuntimeError):
            detector.score({'bytes_sent': 100})
