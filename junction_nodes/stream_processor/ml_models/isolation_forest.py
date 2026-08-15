"""
Network Anomaly Detector for CyberTrace-Graph.

Uses an Isolation Forest model trained on procedurally generated
"normal" network traffic baselines to detect anomalous connections
in real-time. Anomalies include data exfiltration, port scanning,
C2 beaconing, and DNS tunneling.

The Isolation Forest is an unsupervised algorithm that works by
isolating observations. Anomalies are easier to isolate (require
fewer splits) than normal data points, resulting in shorter path
lengths in the tree ensemble.
"""

import logging
import numpy as np
from typing import Optional, List, Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from junction_nodes.stream_processor.ml_models.data_generator import SyntheticDataGenerator

logger = logging.getLogger(__name__)

class NetworkAnomalyDetector:
    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained: bool = False
        self.feature_names: List[str] = [
            'bytes_sent', 
            'bytes_received', 
            'duration_seconds', 
            'packet_count', 
            'unique_dns_queries', 
            'avg_payload_size'
        ]
        self.logger = logger
        
    def train(self, n_normal: int = 10000, contamination: float = 0.05) -> Dict[str, Any]:
        self.logger.info(f"Starting training with n_normal={n_normal}, contamination={contamination}")
        
        # Generate normal traffic
        generator = SyntheticDataGenerator()
        traffic_data = generator.generate_normal_traffic(n_normal)
        
        # Extract features
        X = []
        for traffic in traffic_data:
            features = [traffic.get(feat, 0.0) for feat in self.feature_names]
            X.append(features)
            
        X_arr = np.array(X)
        
        # Normalize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_arr)
        
        # Train IsolationForest
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        
        self.is_trained = True
        self.logger.info("Training complete")
        
        return {
            'samples_trained': n_normal,
            'contamination': contamination,
            'features': self.feature_names
        }
        
    def _normalize_score(self, raw_score: float) -> float:
        min_expected = -0.5
        max_expected = 0.5
        norm_score = 1.0 - (raw_score - min_expected) / (max_expected - min_expected)
        return float(np.clip(norm_score, 0.0, 1.0))

    def score(self, traffic_features: Dict[str, Any]) -> Dict[str, Any]:
        if not self.is_trained or self.model is None or self.scaler is None:
            raise RuntimeError("Model is not trained. Call train() first.")
            
        features = [traffic_features.get(feat, 0.0) for feat in self.feature_names]
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        
        raw_score = float(self.model.decision_function(X_scaled)[0])
        prediction = int(self.model.predict(X_scaled)[0])
        
        is_anomaly = (prediction == -1)
        anomaly_score = self._normalize_score(raw_score)
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'raw_score': raw_score,
            'features_used': {feat: val for feat, val in zip(self.feature_names, features)}
        }
        
    def score_batch(self, traffic_features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.is_trained or self.model is None or self.scaler is None:
            raise RuntimeError("Model is not trained. Call train() first.")
            
        if not traffic_features_list:
            return []
            
        X = []
        features_list = []
        for traffic_features in traffic_features_list:
            features = [traffic_features.get(feat, 0.0) for feat in self.feature_names]
            X.append(features)
            features_list.append({feat: val for feat, val in zip(self.feature_names, features)})
            
        X_arr = np.array(X)
        X_scaled = self.scaler.transform(X_arr)
        
        raw_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        results = []
        for i in range(len(traffic_features_list)):
            raw_score = float(raw_scores[i])
            is_anomaly = (int(predictions[i]) == -1)
            anomaly_score = self._normalize_score(raw_score)
            
            results.append({
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'raw_score': raw_score,
                'features_used': features_list[i]
            })
            
        return results
