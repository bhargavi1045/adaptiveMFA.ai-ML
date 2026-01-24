import joblib
import numpy as np
from typing import Dict, Any
import sys

class MLPredictor:
    def __init__(self):
        """Load all trained models"""
        try:
            self.behavior_model = joblib.load('behavior/behavior_model.pkl')
            self.context_model = joblib.load('context/context_model.pkl')
            self.risk_model = joblib.load('risk/risk_model.pkl')
            self.fraud_model = joblib.load('fraud/fraud_model.pkl')
            print("✓ All models loaded successfully", file=sys.stderr)
        except Exception as e:
            print(f"✗ Error loading models: {e}", file=sys.stderr)
            raise
    
    def predict_behavior(self, features) -> Dict[str, Any]:
        """Detect behavioral anomalies"""
        # Convert Pydantic model to dict if needed
        if hasattr(features, 'dict'):
            features = features.dict()
        
        X = np.array([[
            features['keystroke_interval_ms'],
            features['mouse_speed_px_s'],
            features['session_duration_s'],
            features['click_rate']
        ]])
        
        prediction = self.behavior_model.predict(X)[0]
        is_anomaly = (prediction == -1)
        anomaly_score = 1.0 if is_anomaly else 0.0
        
        return {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'confidence': 0.85
        }
    
    def predict_context(self, features) -> Dict[str, Any]:
        """Assess contextual risk"""
        if hasattr(features, 'dict'):
            features = features.dict()
        
        X = np.array([[
            features['new_device'],
            features['ip_change'],
            features['login_hour']
        ]])
        
        prediction = self.context_model.predict(X)[0]
        probabilities = self.context_model.predict_proba(X)[0]
        
        return {
            'is_high_risk': bool(prediction == 1),
            'risk_probability': float(probabilities[1]),
            'confidence': float(max(probabilities))
        }
    
    def predict_risk(self, features) -> Dict[str, Any]:
        """Calculate overall risk score"""
        if hasattr(features, 'dict'):
            features = features.dict()
        
        feature_order = [
            'keystroke_interval_ms', 'mouse_speed_px_s', 'session_duration_s', 
            'click_rate', 'new_device', 'ip_change', 'login_hour',
            'failed_login_attempts', 'days_since_last_login', 'velocity_check'
        ]
        X = np.array([[features.get(f, 0) for f in feature_order]])
        
        risk_score = self.risk_model.predict(X)[0]
        risk_score = np.clip(risk_score, 0, 1)
        
        if risk_score > 0.7:
            risk_level = 'CRITICAL'
        elif risk_score > 0.5:
            risk_level = 'HIGH'
        elif risk_score > 0.3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': float(risk_score),
            'risk_level': risk_level
        }
    
    def predict_fraud(self, features) -> Dict[str, Any]:
        """Detect fraudulent activity"""
        if hasattr(features, 'dict'):
            features = features.dict()
        
        feature_order = [
            'login_frequency_24h', 'unique_ips_24h', 'failed_attempts_ratio',
            'session_duration_s', 'pages_visited', 'keystroke_rhythm_variance',
            'country_changes_24h', 'impossible_travel', 'device_consistency_score',
            'browser_automation_detected', 'login_hour', 'typical_time_deviation'
        ]
        X = np.array([[features.get(f, 0) for f in feature_order]])
        
        prediction = self.fraud_model.predict(X)[0]
        probabilities = self.fraud_model.predict_proba(X)[0]
        
        return {
            'is_fraud': bool(prediction == 1),
            'fraud_probability': float(probabilities[1]),
            'confidence': float(max(probabilities))
        }
