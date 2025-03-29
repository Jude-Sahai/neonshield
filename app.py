import time
from flask import Flask, render_template, request, jsonify
import requests
import os
import re
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import hashlib
import urllib.parse
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime

def setup_logging(app):
    # Ensure logs directory exists
    if not os.path.exists('logs'):
        os.mkdir('logs')

    # Configure logging with TimedRotatingFileHandler
    log_file = 'logs/security_scanner.log'  # Base filename without date
    file_handler = TimedRotatingFileHandler(
        log_file,
        when='midnight',  # Rotate at midnight
        interval=1,       # Every 1 day
        backupCount=10    # Keep 10 old log files
    )
    
    # Log format with timestamp, log level, message
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - IP: %(remote_addr)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    # Set logging level
    file_handler.setLevel(logging.INFO)
    
    # Add custom IP filter
    class IPFilter(logging.Filter):
        def filter(self, record):
            record.remote_addr = request.remote_addr
            return True
    
    file_handler.addFilter(IPFilter())
    
    # Clear existing handlers to avoid duplicates
    app.logger.handlers.clear()
    
    # Add handler to app logger
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

load_dotenv()

app = Flask(__name__)
setup_logging(app)

# API Keys
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')

# Input Validation Function
def validate_input(input_value):
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    url_pattern = r'^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
    
    if re.match(ip_pattern, input_value):
        return 'ip'
    elif re.match(url_pattern, input_value):
        return 'url'
    return None

# VirusTotal API Routes
@app.route('/')
def home():
    app.logger.info("Home page accessed")
    return render_template('home.html')

@app.route('/url-scan')
def url_scan():
    app.logger.info("URL Scan page accessed")
    return render_template('index.html')

@app.route('/file-scan')
def file_scan():
    app.logger.info("File Scan page accessed")
    return render_template('virus.html')

@app.route('/bandit-writeups')
def bandit_writeups():
    return render_template('bandit-writeups.html')

@app.route('/poc-tasks')
def poc_tasks():
    return render_template('poc-tasks.html')

@app.route('/about')
def about():
    return render_template('about.html')

# VirusTotal File Scan Route
@app.route('/virustotal-file', methods=['POST'])
def virustotal_file_scan():
    if 'file' not in request.files:
        app.logger.warning("File upload attempt without file")
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        app.logger.warning("Empty filename uploaded")
        return jsonify({"error": "No selected file"}), 400

    try:
        # Secure filename and read file content
        filename = secure_filename(file.filename)
        file_content = file.read()
        
        # Calculate file hash for logging and identification
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        # Log file upload details
        app.logger.info(f"File upload attempt: {filename}")
        app.logger.info(f"File Hash: {file_hash}")
        
        # VirusTotal File Scan
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        
        # First, check if file already exists
        file_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        file_response = requests.get(file_url, headers=headers)
        
        if file_response.status_code == 200:
            # Log existing file detection
            app.logger.info(f"File already exists in VirusTotal database: {filename}")
            return jsonify(file_response.json())
        
        # If file not found, upload for scanning
        upload_url = 'https://www.virustotal.com/api/v3/files'
        files = {'file': (filename, file_content)}
        upload_response = requests.post(upload_url, headers=headers, files=files)
        
        if upload_response.status_code == 200:
            analysis_id = upload_response.json().get('data', {}).get('id')
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            
            # Wait and get analysis results
            analysis_response = requests.get(analysis_url, headers=headers)
            result_data = analysis_response.json()
            
            # Analyze malicious detections
            malicious_count = sum(1 for result in result_data.get('data', {}).get('attributes', {}).get('results', {}).values() 
                                  if result.get('category') == 'malicious')
            
            if malicious_count > 0:
                app.logger.warning(f"POTENTIAL MALWARE DETECTED - File: {filename}")
                app.logger.warning(f"Malicious Detections: {malicious_count}")
                app.logger.warning(f"File Hash: {file_hash}")
            
            return jsonify(analysis_response.json())
        
        app.logger.error(f"File upload failed: {filename}")
        return jsonify({"error": "File upload failed"}), 500

    except Exception as e:
        # Comprehensive error logging for file scan
        app.logger.error(f"File scan error for {filename}: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/virustotal', methods=['POST'])
def virustotal_scan():
    input_value = request.json.get('input')
    input_type = validate_input(input_value)
    
    # Log scan attempt with input type
    app.logger.info(f"VirusTotal scan attempt for: {input_value} (Type: {input_type})")
    
    try:
        if input_type == 'url':
            # URL scanning logic with enhanced logging
            encoded_url = urllib.parse.quote(input_value, safe='')
            
            headers = {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Submit URL for scanning
            submit_url = 'https://www.virustotal.com/api/v3/urls'
            submit_response = requests.post(submit_url, 
                                            headers=headers, 
                                            data=f'url={encoded_url}')
            
            if submit_response.status_code == 200:
                analysis_id = submit_response.json().get('data', {}).get('id')
                
                # Log URL submission details
                app.logger.info(f"URL submitted successfully: {input_value}")
                app.logger.info(f"VirusTotal Analysis ID: {analysis_id}")
                
                # Poll analysis results until complete
                analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                max_retries = 10
                retry_delay = 5  # seconds
                
                for attempt in range(max_retries):
                    analysis_response = requests.get(analysis_url, headers=headers)
                    result_data = analysis_response.json()
                    status = result_data.get('data', {}).get('attributes', {}).get('status', 'queued')
                    
                    if status == 'completed':
                        # Analyze and log potential threats
                        malicious_count = sum(1 for result in result_data.get('data', {}).get('attributes', {}).get('results', {}).values() 
                                              if result.get('category') == 'malicious')
                        
                        if malicious_count > 0:
                            app.logger.warning(f"POTENTIAL THREAT DETECTED - URL: {input_value}")
                            app.logger.warning(f"Malicious Detections: {malicious_count}")
                        
                        return jsonify(result_data)
                    
                    app.logger.info(f"Analysis not complete (status: {status}), retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                
                app.logger.error(f"Analysis did not complete after {max_retries} retries for URL: {input_value}")
                return jsonify({"error": "Analysis did not complete in time"}), 500
            
            app.logger.error(f"URL submission failed: {input_value}")
            return jsonify({"error": "URL submission failed"}), 500
        
        elif input_type == 'ip':
            # IP scanning with detailed logging
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{input_value}'
            response = requests.get(url, headers=headers)
            
            # Log IP scan results
            if response.status_code == 200:
                ip_data = response.json()
                reputation = ip_data.get('data', {}).get('attributes', {}).get('reputation', 0)
                
                # Log reputation and potential risks
                if reputation < 0:
                    app.logger.warning(f"SUSPICIOUS IP DETECTED: {input_value}")
                    app.logger.warning(f"IP Reputation Score: {reputation}")
                
                app.logger.info(f"IP Scan completed for: {input_value}")
                return jsonify(response.json())
            
            app.logger.error(f"IP scan failed: {input_value}")
            return jsonify({"error": "IP scan failed"}), 500
    
    except Exception as e:
        # Comprehensive error logging
        app.logger.error(f"VirusTotal scan error for {input_value}: {str(e)}")
        return jsonify({"error": "Scan failed"}), 500
    
    # Log invalid input attempts
    app.logger.warning(f"Invalid input type for scan: {input_value}")
    return jsonify({"error": "Invalid input"}), 400

@app.route('/abuseipdb', methods=['POST'])
def abuseipdb_scan():
    input_value = request.json.get('input')
    
    # Log scan attempt
    app.logger.info(f"AbuseIPDB scan attempt for IP: {input_value}")
    
    if validate_input(input_value) == 'ip':
        try:
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': input_value,
                'maxAgeInDays': 90
            }
            
            response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                                    headers=headers, 
                                    params=params)
            
            # Log successful scan
            if response.status_code == 200:
                result_data = response.json()
                abuse_score = result_data.get('data', {}).get('abuseConfidenceScore', 0)
                
                # Log additional details
                app.logger.info(f"AbuseIPDB scan successful for IP: {input_value}")
                app.logger.info(f"Abuse Confidence Score: {abuse_score}")
                
                # Log high-risk IPs
                if abuse_score > 50:
                    app.logger.warning(f"HIGH RISK IP DETECTED: {input_value} - Abuse Score: {abuse_score}")
            else:
                app.logger.error(f"AbuseIPDB scan failed for IP: {input_value}")
            
            return jsonify(response.json())
        
        except Exception as e:
            # Log any exceptions
            app.logger.error(f"AbuseIPDB scan error for IP {input_value}: {str(e)}")
            return jsonify({"error": "Scan failed"}), 500
    
    # Log invalid input
    app.logger.warning(f"Invalid IP format attempted: {input_value}")
    return jsonify({"error": "Invalid IP address"}), 400

if __name__ == '__main__':
    app.run(debug=True)