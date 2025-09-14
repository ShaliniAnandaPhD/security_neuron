# vulnerable_sql_injection.py
# TEST CASE 4: SQL Injection & Data Pipeline Security Vulnerabilities
# This file contains intentionally vulnerable code for testing AI Guardian

from flask import Flask, request, jsonify
import sqlite3
import psycopg2
import pymongo
import pandas as pd
import mysql.connector
from typing import Dict, Any, List
import json
import subprocess

app = Flask(__name__)

class VulnerableDataPipeline:
    """
    VULNERABILITY EXAMPLES:
    - SQL Injection (CRITICAL)
    - NoSQL Injection (CRITICAL)
    - Command Injection (CRITICAL)
    - Data leakage (HIGH)
    - Insecure data processing (MEDIUM)
    """
    
    def __init__(self):
        # VULNERABLE: Hardcoded connection strings
        self.db_connection = "postgresql://admin:password@localhost/ai_training"
        self.mongo_uri = "mongodb://admin:password@localhost:27017/"
        
    # ========== VULNERABLE CODE - DO NOT USE IN PRODUCTION ==========
    
    @app.route('/data/query/vulnerable', methods=['POST'])
    def vulnerable_sql_query(self):
        """CRITICAL: Classic SQL injection vulnerability"""
        dataset_id = request.json.get('dataset_id')
        user_id = request.json.get('user_id')
        
        # VULNERABLE: String concatenation in SQL query
        query = f"SELECT * FROM training_data WHERE dataset_id = '{dataset_id}' AND user_id = {user_id}"
        
        conn = sqlite3.connect('training.db')
        cursor = conn.cursor()
        
        # VULNERABLE: Direct query execution
        cursor.execute(query)
        results = cursor.fetchall()
        
        conn.close()
        
        # VULNERABLE: Exposing raw database results
        return jsonify({"data": results, "query": query})
    
    @app.route('/data/search/vulnerable', methods=['GET'])
    def vulnerable_search(self):
        """CRITICAL: SQL injection via search parameters"""
        search_term = request.args.get('q', '')
        sort_by = request.args.get('sort', 'id')
        order = request.args.get('order', 'ASC')
        
        # VULNERABLE: Multiple injection points
        query = f"""
        SELECT * FROM models 
        WHERE name LIKE '%{search_term}%' 
        OR description LIKE '%{search_term}%'
        ORDER BY {sort_by} {order}
        """
        
        conn = psycopg2.connect(self.db_connection)
        cursor = conn.cursor()
        
        # VULNERABLE: No parameterization
        cursor.execute(query)
        
        # VULNERABLE: Exposing column names
        columns = [desc[0] for desc in cursor.description]
        results = cursor.fetchall()
        
        return jsonify({
            "columns": columns,
            "results": results
        })
    
    @app.route('/data/filter/vulnerable', methods=['POST'])
    def vulnerable_dynamic_filter(self):
        """HIGH: Dynamic SQL with multiple vulnerabilities"""
        filters = request.json.get('filters', {})
        table = request.json.get('table', 'datasets')
        
        # VULNERABLE: Table name injection
        query = f"SELECT * FROM {table} WHERE 1=1"
        
        # VULNERABLE: Building dynamic WHERE clause
        for field, value in filters.items():
            if isinstance(value, str):
                query += f" AND {field} = '{value}'"
            else:
                query += f" AND {field} = {value}"
        
        # VULNERABLE: Allowing UNION attacks
        if 'custom_condition' in request.json:
            query += f" {request.json['custom_condition']}"
        
        conn = sqlite3.connect('training.db')
        
        # VULNERABLE: Executing dynamic query
        df = pd.read_sql_query(query, conn)
        
        # VULNERABLE: Exposing pandas dataframe info
        return jsonify({
            "data": df.to_dict('records'),
            "shape": df.shape,
            "dtypes": df.dtypes.to_dict(),
            "query_executed": query
        })
    
    @app.route('/data/mongodb/vulnerable', methods=['POST'])
    def vulnerable_nosql_injection(self):
        """CRITICAL: NoSQL injection in MongoDB"""
        username = request.json.get('username')
        password = request.json.get('password')
        
        client = pymongo.MongoClient(self.mongo_uri)
        db = client.ai_platform
        users = db.users
        
        # VULNERABLE: Direct insertion into query
        query = {"username": username, "password": password}
        
        # VULNERABLE: Allows operators like $ne, $gt
        # Attack: {"username": {"$ne": ""}, "password": {"$ne": ""}}
        user = users.find_one(query)
        
        if user:
            # VULNERABLE: Exposing internal document structure
            return jsonify({
                "authenticated": True,
                "user": str(user),
                "role": user.get('role'),
                "_id": str(user['_id'])
            })
        
        return jsonify({"authenticated": False})
    
    @app.route('/data/aggregate/vulnerable', methods=['POST'])
    def vulnerable_aggregation(self):
        """HIGH: Injection in aggregation pipeline"""
        pipeline_json = request.json.get('pipeline')
        collection_name = request.json.get('collection')
        
        client = pymongo.MongoClient(self.mongo_uri)
        db = client.ai_platform
        collection = db[collection_name]
        
        # VULNERABLE: Using user-provided aggregation pipeline
        # Could include $lookup to access other collections
        pipeline = json.loads(pipeline_json) if isinstance(pipeline_json, str) else pipeline_json
        
        # VULNERABLE: No validation of pipeline operations
        results = list(collection.aggregate(pipeline))
        
        return jsonify({"results": results})
    
    @app.route('/data/export/vulnerable', methods=['POST'])
    def vulnerable_data_export(self):
        """CRITICAL: Command injection in data export"""
        format_type = request.json.get('format')
        dataset_name = request.json.get('dataset')
        output_file = request.json.get('output', 'export')
        
        # VULNERABLE: Command injection via filename
        if format_type == 'csv':
            # VULNERABLE: Shell command with user input
            cmd = f"mysql -e 'SELECT * FROM {dataset_name}' | sed 's/\t/,/g' > {output_file}.csv"
            subprocess.shell(cmd, shell=True)  # CRITICAL: Shell injection!
            
        elif format_type == 'json':
            # VULNERABLE: Another injection point
            cmd = f"mongoexport --collection={dataset_name} --out={output_file}.json"
            os.system(cmd)  # CRITICAL: Command injection!
        
        return jsonify({"status": "exported", "file": f"{output_file}.{format_type}"})
    
    @app.route('/data/import/vulnerable', methods=['POST'])
    def vulnerable_data_import(self):
        """HIGH: Unsafe data import with injection risks"""
        file_path = request.json.get('file_path')
        table_name = request.json.get('table')
        
        # VULNERABLE: Path traversal
        df = pd.read_csv(file_path)
        
        conn = sqlite3.connect('training.db')
        
        # VULNERABLE: SQL injection via table name
        # VULNERABLE: No validation of dataframe content
        df.to_sql(table_name, conn, if_exists='append', index=False)
        
        # VULNERABLE: Executing user-provided SQL after import
        if 'post_import_sql' in request.json:
            conn.execute(request.json['post_import_sql'])
        
        return jsonify({"status": "imported", "rows": len(df)})

    # ========== ADDITIONAL VULNERABLE PATTERNS ==========
    
    def vulnerable_stored_procedure(self, proc_name: str, params: List):
        """VULNERABLE: Stored procedure injection"""
        conn = psycopg2.connect(self.db_connection)
        cursor = conn.cursor()
        
        # VULNERABLE: Procedure name injection
        # VULNERABLE: Parameter injection
        param_str = ','.join([f"'{p}'" if isinstance(p, str) else str(p) for p in params])
        query = f"CALL {proc_name}({param_str})"
        
        cursor.execute(query)
        return cursor.fetchall()
    
    def vulnerable_second_order_injection(self, user_id: int):
        """VULNERABLE: Second-order SQL injection"""
        conn = sqlite3.connect('training.db')
        cursor = conn.cursor()
        
        # First query - seems safe
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        
        # VULNERABLE: Using retrieved data in next query without sanitization
        # Username could contain SQL injection payload stored earlier
        query = f"SELECT * FROM user_models WHERE owner = '{username}'"
        cursor.execute(query)
        
        return cursor.fetchall()
    
    def vulnerable_blind_injection(self, model_id: str):
        """VULNERABLE: Blind SQL injection"""
        conn = sqlite3.connect('training.db')
        cursor = conn.cursor()
        
        # VULNERABLE: Time-based blind injection possible
        query = f"SELECT * FROM models WHERE id = '{model_id}'"
        
        try:
            cursor.execute(query)
            if cursor.fetchone():
                return True
            else:
                return False
        except:
            # VULNERABLE: Different error messages reveal info
            return "Error in query"
    
    def vulnerable_json_injection(self, json_data: str):
        """VULNERABLE: JSON SQL injection"""
        conn = psycopg2.connect(self.db_connection)
        cursor = conn.cursor()
        
        # VULNERABLE: JSON operations without sanitization
        query = f"""
        SELECT * FROM models 
        WHERE metadata @> '{json_data}'::jsonb
        """
        
        cursor.execute(query)
        return cursor.fetchall()

# ========== INJECTION PAYLOADS ==========

class InjectionPayloads:
    """Example SQL injection payloads for testing"""
    
    @staticmethod
    def get_sql_injection_payloads() -> List[Dict[str, str]]:
        return [
            {
                "name": "Classic Authentication Bypass",
                "payload": "' OR '1'='1' --",
                "description": "Bypasses login checks"
            },
            {
                "name": "Union Based Injection",
                "payload": "' UNION SELECT * FROM users--",
                "description": "Extracts data from other tables"
            },
            {
                "name": "Stacked Queries",
                "payload": "'; DROP TABLE models; --",
                "description": "Executes multiple queries"
            },
            {
                "name": "Time-based Blind",
                "payload": "' OR SLEEP(5)--",
                "description": "Delays response to confirm injection"
            },
            {
                "name": "Error-based Extraction",
                "payload": "' AND 1=CONVERT(int, (SELECT @@version))--",
                "description": "Extracts data through error messages"
            },
            {
                "name": "Second Order",
                "payload": "admin'--",
                "description": "Stored for later execution"
            }
        ]
    
    @staticmethod
    def get_nosql_injection_payloads() -> List[Dict[str, Any]]:
        return [
            {
                "name": "Authentication Bypass",
                "payload": {"username": {"$ne": ""}, "password": {"$ne": ""}},
                "description": "Bypasses MongoDB authentication"
            },
            {
                "name": "Regex Injection",
                "payload": {"username": {"$regex": ".*"}},
                "description": "Extracts all users"
            },
            {
                "name": "JavaScript Injection",
                "payload": {"$where": "this.password == 'test'"},
                "description": "Executes JavaScript"
            },
            {
                "name": "Aggregation Injection",
                "payload": [{"$lookup": {"from": "admin", "localField": "x", "foreignField": "y", "as": "z"}}],
                "description": "Accesses other collections"
            }
        ]

# ========== TEST VALIDATION FUNCTIONS ==========

def test_for_injection_vulnerabilities(code_content: str) -> List[Dict]:
    """Test for SQL/NoSQL injection vulnerabilities"""
    import re
    
    vulnerabilities = []
    
    patterns = {
        'string_concatenation_sql': {
            'pattern': r'["\']SELECT.*\+|f["\']SELECT.*\{',
            'severity': 'CRITICAL',
            'description': 'SQL query string concatenation'
        },
        'format_string_sql': {
            'pattern': r'\.format\(.*SELECT|%.*SELECT',
            'severity': 'CRITICAL',
            'description': 'Format string in SQL query'
        },
        'shell_command': {
            'pattern': r'subprocess\.|os\.system|shell=True',
            'severity': 'CRITICAL',
            'description': 'Shell command execution'
        },
        'no_parameterization': {
            'pattern': r'execute\(["\'].*%s|execute\(f["\']',
            'severity': 'HIGH',
            'description': 'SQL query without parameterization'
        },
        'dynamic_table_name': {
            'pattern': r'FROM\s+["\']?\s*\+|FROM\s+\{',
            'severity': 'HIGH',
            'description': 'Dynamic table name in query'
        },
        'mongodb_find_dict': {
            'pattern': r'find_one\(\{.*request\.|find\(\{.*request\.',
            'severity': 'HIGH',
            'description': 'MongoDB query with user input'
        }
    }
    
    for vuln_type, config in patterns.items():
        if re.search(config['pattern'], code_content, re.IGNORECASE | re.MULTILINE):
            vulnerabilities.append({
                'type': vuln_type,
                'severity': config['severity'],
                'description': config['description']
            })
    
    return vulnerabilities

if __name__ == "__main__":
    print("Testing for SQL/NoSQL Injection Vulnerabilities...")
    print("=" * 50)
    
    # Test this file for vulnerabilities
    with open(__file__, 'r') as f:
        code = f.read()
    
    vulnerabilities = test_for_injection_vulnerabilities(code)
    
    print(f"\n⚠️  Found {len(vulnerabilities)} vulnerability patterns:")
    for vuln in vulnerabilities:
        print(f"  - {vuln['description']} (Severity: {vuln['severity']})")
    
    # Show example payloads
    print("\n🔴 Example SQL Injection Payloads:")
    sql_payloads = InjectionPayloads.get_sql_injection_payloads()
    for payload in sql_payloads[:3]:
        print(f"  - {payload['name']}: {payload['payload']}")
    
    print("\n🔴 Example NoSQL Injection Payloads:")
    nosql_payloads = InjectionPayloads.get_nosql_injection_payloads()
    for payload in nosql_payloads[:2]:
        print(f"  - {payload['name']}: {payload['payload']}")
    
    print("\n❌ These vulnerabilities can lead to complete data breach!")
    print("✅ Use AI Guardian to automatically fix these vulnerabilities")
