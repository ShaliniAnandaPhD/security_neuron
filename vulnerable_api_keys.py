# vulnerable_api_keys.py
# TEST CASE 1: API Key & Credential Exposure Vulnerabilities
# This file contains intentionally vulnerable code for testing AI Guardian


import requests
import openai
import boto3
from typing import Dict, Any

class VulnerableAPIConfig:
    """
    VULNERABILITY EXAMPLES:
    - Hardcoded API keys (CRITICAL)
    - Exposed database credentials (CRITICAL)
    - Plain text secrets in code (HIGH)
    - No key rotation mechanism (MEDIUM)
    """
    
    # ========== VULNERABLE CODE - DO NOT USE IN PRODUCTION ==========
    
    # CRITICAL: Hardcoded API Keys
    OPENAI_API_KEY = "sk-proj-abc123xyz789def456ghi789jkl012mno345pqr678stu901vwx234yz"
    ANTHROPIC_API_KEY = "sk-ant-api03-KL9mN3pQ4rS5tU6vW7xY8zA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU"
    HUGGINGFACE_TOKEN = "hf_ABcdEFghIJklMNopQRstUVwxYZ123456789"
    COHERE_API_KEY = "co-prod-KEY123456789ABCDEFGHIJKLMNOP"
    
    # CRITICAL: Database Credentials in Plain Text
    DATABASE_URL = "postgresql://admin:SuperSecret123!@prod-db.company.com:5432/ml_models"
    MONGODB_URI = "mongodb://root:MongoPass2024@cluster.mongodb.net/ai_data"
    REDIS_PASSWORD = "redis_prod_password_2024"
    ELASTICSEARCH_PASSWORD = "elastic_search_admin_pass"
    
    # CRITICAL: Cloud Provider Credentials
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    AZURE_CLIENT_SECRET = "8Q~.microsoft.azure.secret.key.example"
    GCP_SERVICE_ACCOUNT_KEY = '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE..."}'
    
    # CRITICAL: Encryption & Signing Keys
    JWT_SECRET_KEY = "your-256-bit-secret-key-for-jwt-signing"
    ENCRYPTION_KEY = "my-super-secret-encryption-key-32bytes!"
    MODEL_SIGNING_KEY = "model-signature-private-key-2024"
    API_SIGNING_SECRET = "webhook-signing-secret-key"
    
    # HIGH: Third-party Service Credentials
    STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    SENDGRID_API_KEY = "SG.actual_api_key_would_be_here"
    TWILIO_AUTH_TOKEN = "auth_token_32_characters_long_12"
    SLACK_BOT_TOKEN = "xoxb-slack-bot-token-example"
    
    def __init__(self):
        # VULNERABLE: Initializing clients with hardcoded keys
        self.setup_clients()
    
    def setup_clients(self):
        """VULNERABLE: Direct use of hardcoded credentials"""
        # OpenAI client with exposed key
        openai.api_key = self.OPENAI_API_KEY
        
        # AWS client with exposed credentials
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=self.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=self.AWS_SECRET_ACCESS_KEY
        )
        
        # Database connection with exposed password
        import psycopg2
        self.db_conn = psycopg2.connect(self.DATABASE_URL)
    
    def get_api_headers(self, service: str) -> Dict[str, str]:
        """VULNERABLE: Returns headers with exposed API keys"""
        headers = {
            'openai': {
                'Authorization': f'Bearer {self.OPENAI_API_KEY}',
                'Content-Type': 'application/json'
            },
            'anthropic': {
                'X-API-Key': self.ANTHROPIC_API_KEY,
                'Content-Type': 'application/json'
            },
            'huggingface': {
                'Authorization': f'Bearer {self.HUGGINGFACE_TOKEN}'
            }
        }
        return headers.get(service, {})
    
    def make_api_call(self, service: str, endpoint: str, data: Dict[str, Any]):
        """VULNERABLE: API calls with exposed keys"""
        headers = self.get_api_headers(service)
        
        # VULNERABLE: Key exposed in URL for some services
        if service == 'custom':
            url = f"https://api.service.com/v1/{endpoint}?api_key={self.API_SIGNING_SECRET}"
        else:
            url = f"https://api.{service}.com/{endpoint}"
        
        response = requests.post(url, json=data, headers=headers)
        return response.json()
    
    def log_configuration(self):
        """VULNERABLE: Logging sensitive information"""
        print(f"Database connected: {self.DATABASE_URL}")
        print(f"AWS Access Key: {self.AWS_ACCESS_KEY_ID}")
        print(f"API Keys loaded for: OpenAI, Anthropic, HuggingFace")
        
        # VULNERABLE: Writing secrets to log file
        with open('config.log', 'w') as f:
            f.write(f"JWT_SECRET={self.JWT_SECRET_KEY}\n")
            f.write(f"DB_PASSWORD={self.REDIS_PASSWORD}\n")

# ========== ADDITIONAL VULNERABLE PATTERNS ==========

class VulnerableKeyStorage:
    """More examples of insecure key storage"""
    
    def store_keys_in_json(self):
        """VULNERABLE: Storing keys in JSON file"""
        import json
        
        config = {
            "api_keys": {
                "openai": "sk-proj-actual-key-here",
                "anthropic": "sk-ant-actual-key-here"
            },
            "database": {
                "password": "db_password_123"
            }
        }
        
        # VULNERABLE: Writing secrets to unencrypted file
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
    
    def get_key_from_git(self):
        """VULNERABLE: Keys in git repository"""
        # VULNERABLE: Reading from committed .env file
        with open('.env', 'r') as f:
            for line in f:
                if 'API_KEY' in line:
                    key = line.split('=')[1].strip()
                    return key
    
    def embed_in_dockerfile(self):
        """VULNERABLE: Keys in Docker files"""
        dockerfile_content = """
        FROM python:3.9
        ENV OPENAI_API_KEY=sk-proj-actualkey123
        ENV DB_PASSWORD=supersecret
        """
        return dockerfile_content

class VulnerableKeyTransmission:
    """Examples of insecure key transmission"""
    
    def send_key_in_query_param(self, api_key: str):
        """VULNERABLE: Key in URL parameters"""
        # This exposes the key in logs, browser history, etc.
        url = f"https://api.example.com/data?api_key={api_key}"
        return requests.get(url)
    
    def send_key_in_cookie(self, api_key: str):
        """VULNERABLE: Sensitive data in cookies without proper flags"""
        response = make_response("Success")
        # VULNERABLE: No Secure, HttpOnly, or SameSite flags
        response.set_cookie('api_key', api_key)
        return response
    
    def send_unencrypted(self, api_key: str):
        """VULNERABLE: Sending keys over unencrypted connection"""
        # VULNERABLE: Using HTTP instead of HTTPS
        url = "http://api.example.com/authenticate"
        data = {"api_key": api_key}
        return requests.post(url, json=data)

# ========== TEST VALIDATION FUNCTIONS ==========

def test_for_exposed_keys(code_content: str) -> list:
    """Function to test if code contains exposed keys"""
    import re
    
    vulnerabilities = []
    
    # Patterns to detect various types of keys
    patterns = {
        'openai_key': r'sk-proj-[a-zA-Z0-9]{48}',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'api_key_generic': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'password': r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'token': r'["\']?token["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'secret': r'["\']?secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'jwt': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    }
    
    for key_type, pattern in patterns.items():
        matches = re.findall(pattern, code_content, re.IGNORECASE)
        if matches:
            vulnerabilities.append({
                'type': key_type,
                'severity': 'CRITICAL',
                'matches': len(matches),
                'pattern': pattern
            })
    
    return vulnerabilities

if __name__ == "__main__":
    # Test the vulnerable code
    print("Testing vulnerable API key configuration...")
    
    vulnerable_config = VulnerableAPIConfig()
    
    # Read this file and check for vulnerabilities
    with open(__file__, 'r') as f:
        code = f.read()
    
    vulnerabilities = test_for_exposed_keys(code)
    
    print(f"\n⚠️  Found {len(vulnerabilities)} types of exposed credentials:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']}: {vuln['matches']} instances (Severity: {vuln['severity']})")
    
    print("\n❌ This code should NEVER be used in production!")
    print("✅ Use AI Guardian to automatically fix these vulnerabilities")
