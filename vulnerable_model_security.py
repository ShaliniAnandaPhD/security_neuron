# vulnerable_model_security.py
# TEST CASE 3: Model Poisoning, Unsafe Deserialization & Model Security
# This file contains intentionally vulnerable code for testing AI Guardian

import pickle
import joblib
import dill
import numpy as np
import pandas as pd
from flask import Flask, request, send_file, jsonify
import torch
import tensorflow as tf
from typing import Any, Dict, Optional
import base64
import os

app = Flask(__name__)

class VulnerableModelHandler:
    """
    VULNERABILITY EXAMPLES:
    - Unsafe pickle deserialization (CRITICAL)
    - Model poisoning attacks (CRITICAL)
    - Unvalidated model uploads (HIGH)
    - Model theft/extraction (HIGH)
    - Training data leakage (MEDIUM)
    """
    
    def __init__(self):
        self.models = {}
        self.training_data = {}
        
    # ========== VULNERABLE CODE - DO NOT USE IN PRODUCTION ==========
    
    @app.route('/model/upload/vulnerable', methods=['POST'])
    def vulnerable_model_upload(self):
        """CRITICAL: Unsafe pickle deserialization allows arbitrary code execution"""
        try:
            model_file = request.files['model']
            model_name = request.form.get('name', 'unnamed')
            
            # VULNERABLE: Direct pickle load without any validation
            model_bytes = model_file.read()
            model = pickle.loads(model_bytes)  # CRITICAL: Arbitrary code execution!
            
            # VULNERABLE: No validation of model structure
            self.models[model_name] = model
            
            # VULNERABLE: No access control
            return jsonify({
                "status": "success",
                "message": f"Model {model_name} uploaded",
                "model_size": len(model_bytes)
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/model/load-from-url/vulnerable', methods=['POST'])
    def vulnerable_load_from_url(self):
        """CRITICAL: Loading models from untrusted URLs"""
        model_url = request.json.get('url')
        
        # VULNERABLE: Fetching from arbitrary URL
        import urllib.request
        response = urllib.request.urlopen(model_url)
        model_data = response.read()
        
        # VULNERABLE: Deserializing untrusted data
        model = pickle.loads(model_data)
        
        # VULNERABLE: No signature verification
        self.models['remote_model'] = model
        
        return jsonify({"status": "Model loaded from URL"})
    
    @app.route('/model/train/vulnerable', methods=['POST'])
    def vulnerable_model_training(self):
        """CRITICAL: Training data poisoning vulnerability"""
        training_file = request.files['training_data']
        
        # VULNERABLE: Loading untrusted training data
        data = pickle.load(training_file)  # Could contain malicious code
        
        X_train = data['X']
        y_train = data['y']
        
        # VULNERABLE: No validation of training data
        # Attacker could inject poisoned samples
        
        # VULNERABLE: Using untrusted hyperparameters
        hyperparams = request.json.get('hyperparameters', {})
        
        # This could be exploited for resource exhaustion
        model = self.train_model_unsafe(X_train, y_train, **hyperparams)
        
        # VULNERABLE: Saving model without protection
        model_path = f"models/{request.json.get('name')}.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        return jsonify({"status": "Model trained", "path": model_path})
    
    @app.route('/model/download/vulnerable/<model_name>', methods=['GET'])
    def vulnerable_model_download(self, model_name):
        """HIGH: Model theft - no authentication or rate limiting"""
        # VULNERABLE: No authentication check
        # VULNERABLE: No rate limiting
        # VULNERABLE: No audit logging
        
        model_path = f"models/{model_name}.pkl"
        
        # VULNERABLE: Path traversal possible
        if os.path.exists(model_path):
            # VULNERABLE: Exposing proprietary model
            return send_file(model_path, as_attachment=True)
        else:
            return jsonify({"error": "Model not found"}), 404
    
    @app.route('/model/predict/vulnerable', methods=['POST'])
    def vulnerable_prediction(self):
        """HIGH: Model inversion and extraction attacks"""
        model_name = request.json.get('model')
        input_data = request.json.get('data')
        
        # VULNERABLE: No rate limiting on predictions
        # Allows model extraction through repeated queries
        
        model = self.models.get(model_name)
        if not model:
            return jsonify({"error": "Model not found"}), 404
        
        # VULNERABLE: Raw input without validation
        # Could be adversarial examples
        prediction = model.predict(np.array(input_data))
        
        # VULNERABLE: Returning detailed confidence scores
        # Helps with model extraction
        return jsonify({
            "prediction": prediction.tolist(),
            "confidence": model.predict_proba(np.array(input_data)).tolist(),
            "model_version": "1.0",  # VULNERABLE: Version disclosure
            "feature_importance": model.feature_importances_.tolist()  # VULNERABLE: Model internals
        })
    
    @app.route('/model/export/vulnerable', methods=['POST'])
    def vulnerable_model_export(self):
        """CRITICAL: Unsafe model serialization"""
        model_name = request.json.get('model')
        format_type = request.json.get('format', 'pickle')
        
        model = self.models.get(model_name)
        
        if format_type == 'pickle':
            # VULNERABLE: Using pickle for serialization
            serialized = pickle.dumps(model)
        elif format_type == 'dill':
            # VULNERABLE: Dill can serialize even more dangerous objects
            serialized = dill.dumps(model)
        elif format_type == 'joblib':
            # VULNERABLE: Joblib without compression validation
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                joblib.dump(model, tmp.name)
                with open(tmp.name, 'rb') as f:
                    serialized = f.read()
        
        # VULNERABLE: No encryption or signing
        return jsonify({
            "model_data": base64.b64encode(serialized).decode(),
            "format": format_type
        })
    
    def train_model_unsafe(self, X, y, **kwargs):
        """VULNERABLE: Unsafe model training"""
        from sklearn.ensemble import RandomForestClassifier
        
        # VULNERABLE: Using user-provided hyperparameters without validation
        # Could cause resource exhaustion
        n_estimators = kwargs.get('n_estimators', 100)
        max_depth = kwargs.get('max_depth', None)  # Could be set to huge value
        
        # VULNERABLE: No limit on training time or resources
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            n_jobs=-1  # VULNERABLE: Uses all CPU cores
        )
        
        # VULNERABLE: No validation of training data shape/content
        model.fit(X, y)
        
        # VULNERABLE: Storing training data with model (data leakage)
        model._training_data = X
        model._training_labels = y
        
        return model

    # ========== ADDITIONAL VULNERABLE PATTERNS ==========
    
    @app.route('/model/federated/vulnerable', methods=['POST'])
    def vulnerable_federated_learning(self):
        """HIGH: Federated learning poisoning"""
        client_updates = request.json.get('updates')
        
        # VULNERABLE: No validation of client updates
        # Malicious clients could poison the global model
        
        global_model = self.models.get('global_model')
        
        for update in client_updates:
            # VULNERABLE: Trusting client gradients
            client_gradients = pickle.loads(base64.b64decode(update['gradients']))
            
            # VULNERABLE: No anomaly detection
            # Could contain backdoor triggers
            self.apply_gradients_unsafe(global_model, client_gradients)
        
        return jsonify({"status": "Model updated"})
    
    @app.route('/model/fine-tune/vulnerable', methods=['POST'])
    def vulnerable_fine_tuning(self):
        """HIGH: Fine-tuning with untrusted data"""
        base_model_name = request.json.get('base_model')
        fine_tune_data = request.json.get('data')
        
        # VULNERABLE: Loading pre-trained model without verification
        base_model = self.models.get(base_model_name)
        
        # VULNERABLE: Fine-tuning with unvalidated data
        # Could inject backdoors or biases
        X = np.array(fine_tune_data['X'])
        y = np.array(fine_tune_data['y'])
        
        # VULNERABLE: No differential privacy
        base_model.fit(X, y)
        
        # VULNERABLE: Overwriting original model
        self.models[base_model_name] = base_model
        
        return jsonify({"status": "Model fine-tuned"})

class VulnerableModelInference:
    """Vulnerable model inference patterns"""
    
    def vulnerable_batch_inference(self, model, batch_data):
        """VULNERABLE: Batch inference without resource limits"""
        # VULNERABLE: No batch size limit
        # Could cause memory exhaustion
        
        results = []
        for data in batch_data:
            # VULNERABLE: No timeout or resource monitoring
            result = model.predict(data)
            results.append(result)
        
        return results
    
    def vulnerable_ensemble_inference(self, models, input_data):
        """VULNERABLE: Ensemble without validation"""
        predictions = []
        
        for model_data in models:
            # VULNERABLE: Loading untrusted models
            model = pickle.loads(model_data)
            
            # VULNERABLE: No sandboxing
            pred = model.predict(input_data)
            predictions.append(pred)
        
        # VULNERABLE: No validation of predictions
        return np.mean(predictions, axis=0)

class VulnerableModelStorage:
    """Vulnerable model storage patterns"""
    
    def save_model_unsafe(self, model, path):
        """VULNERABLE: Unsafe model storage"""
        # VULNERABLE: No encryption
        with open(path, 'wb') as f:
            pickle.dump(model, f)
        
        # VULNERABLE: World-readable permissions
        os.chmod(path, 0o777)
        
        # VULNERABLE: No integrity check
        return path
    
    def load_model_unsafe(self, path):
        """VULNERABLE: Unsafe model loading"""
        # VULNERABLE: No path validation (path traversal)
        # VULNERABLE: No signature verification
        with open(path, 'rb') as f:
            model = pickle.load(f)
        
        return model
    
    def share_model_unsafe(self, model):
        """VULNERABLE: Unsafe model sharing"""
        # VULNERABLE: Exposing model via public URL
        public_url = f"http://public-bucket.s3.amazonaws.com/model_{id(model)}.pkl"
        
        # VULNERABLE: No access control
        # VULNERABLE: No encryption
        serialized = pickle.dumps(model)
        
        # Upload to public bucket (simulated)
        return public_url

# ========== POISONING ATTACK EXAMPLES ==========

class ModelPoisoningAttacks:
    """Examples of model poisoning attacks"""
    
    @staticmethod
    def create_backdoor_trigger():
        """Create a backdoor trigger for model poisoning"""
        # Example: specific pixel pattern that triggers misclassification
        trigger = np.zeros((28, 28))
        trigger[0:3, 0:3] = 1  # Small pattern in corner
        return trigger
    
    @staticmethod
    def create_poisoned_data(clean_data, labels, poison_rate=0.1):
        """Create poisoned training data"""
        poisoned_data = clean_data.copy()
        poisoned_labels = labels.copy()
        
        num_poison = int(len(clean_data) * poison_rate)
        poison_indices = np.random.choice(len(clean_data), num_poison, replace=False)
        
        trigger = ModelPoisoningAttacks.create_backdoor_trigger()
        
        for idx in poison_indices:
            # Add trigger to data
            poisoned_data[idx] += trigger
            # Change label to target class
            poisoned_labels[idx] = 0  # Target class
        
        return poisoned_data, poisoned_labels
    
    @staticmethod
    def create_malicious_pickle():
        """Create a malicious pickle payload"""
        import pickle
        import os
        
        class MaliciousModel:
            def __reduce__(self):
                # This executes arbitrary code when unpickled
                return (os.system, ('echo "System compromised!"',))
        
        malicious = MaliciousModel()
        return pickle.dumps(malicious)

# ========== TEST VALIDATION FUNCTIONS ==========

def test_for_model_vulnerabilities(code_content: str) -> list:
    """Test for model security vulnerabilities"""
    import re
    
    vulnerabilities = []
    
    # Critical vulnerability patterns
    patterns = {
        'unsafe_pickle': {
            'pattern': r'pickle\.loads?\((?!.*verify)',
            'severity': 'CRITICAL',
            'description': 'Unsafe pickle deserialization'
        },
        'unsafe_joblib': {
            'pattern': r'joblib\.load\((?!.*trusted)',
            'severity': 'CRITICAL',
            'description': 'Unsafe joblib deserialization'
        },
        'unsafe_dill': {
            'pattern': r'dill\.loads?\(',
            'severity': 'CRITICAL',
            'description': 'Unsafe dill deserialization'
        },
        'no_auth_download': {
            'pattern': r'send_file\([^)]+\)(?!.*auth)',
            'severity': 'HIGH',
            'description': 'Model download without authentication'
        },
        'training_data_exposure': {
            'pattern': r'model\._training_data',
            'severity': 'HIGH',
            'description': 'Training data stored with model'
        },
        'no_input_validation': {
            'pattern': r'model\.predict\(.*request\.',
            'severity': 'MEDIUM',
            'description': 'Prediction without input validation'
        }
    }
    
    for vuln_type, config in patterns.items():
        if re.search(config['pattern'], code_content, re.MULTILINE):
            vulnerabilities.append({
                'type': vuln_type,
                'severity': config['severity'],
                'description': config['description']
            })
    
    return vulnerabilities

if __name__ == "__main__":
    print("Testing for Model Security Vulnerabilities...")
    print("=" * 50)
    
    # Test this file for vulnerabilities
    with open(__file__, 'r') as f:
        code = f.read()
    
    vulnerabilities = test_for_model_vulnerabilities(code)
    
    print(f"\n⚠️  Found {len(vulnerabilities)} vulnerability patterns:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['description']} (Severity: {vuln['severity']})")
    
    # Demonstrate poisoning attack
    print("\n🔴 Demonstrating Model Poisoning Attack:")
    
    # Create fake clean data
    clean_data = np.random.randn(1000, 28, 28)
    clean_labels = np.random.randint(0, 10, 1000)
    
    # Create poisoned dataset
    poisoned_data, poisoned_labels = ModelPoisoningAttacks.create_poisoned_data(
        clean_data, clean_labels, poison_rate=0.1
    )
    
    print(f"  - Created poisoned dataset with 10% backdoor triggers")
    print(f"  - Original shape: {clean_data.shape}")
    print(f"  - Poisoned samples: {int(len(clean_data) * 0.1)}")
    
    # Show malicious pickle danger
    print("\n⚠️  Malicious Pickle Payload Created (DO NOT EXECUTE)")
    malicious_pickle = ModelPoisoningAttacks.create_malicious_pickle()
    print(f"  - Payload size: {len(malicious_pickle)} bytes")
    print(f"  - Would execute system commands if loaded!")
    
    print("\n❌ These vulnerabilities allow complete system compromise!")
    print("✅ Use AI Guardian to automatically fix these vulnerabilities")
