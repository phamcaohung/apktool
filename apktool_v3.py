from flask import Flask, request, jsonify
import os, re, tempfile, shutil, subprocess, socket, json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache


app = Flask(__name__)

# Regex patterns - COMPILE ONCE
URL_PATTERN = re.compile(r"(https?://[^\s\"']+)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Text file extensions
TEXT_EXTENSIONS = {'.smali', '.xml', '.txt', '.json', '.js', '.html', '.properties', '.java', '.kt'}
BINARY_EXTENSIONS = {'.so', '.dex', '.png', '.jpg', '.jpeg', '.mp3', '.mp4', '.zip', '.apk', '.db'}

# Global cache
TRACKERS_DB = None
SUSPICIOUS_API_PATTERN = None
API_LOOKUP = None
GEOIP_READER = None


def init_globals():
    """Initialize global variables once at startup"""
    global TRACKERS_DB, SUSPICIOUS_API_PATTERN, API_LOOKUP, GEOIP_READER
    
    # Load suspicious APIs
    with open("suspicious_api_list.json", "r", encoding="utf-8") as f:
        SUSPICIOUS_APIS = json.load(f)

    API_LOOKUP = {
        api["api"].replace(".", "/").replace("#", ";->"): {"category": api["category"], "risk": api["risk"]}
        for api in SUSPICIOUS_APIS
    }
        
    patterns = []
    for api in SUSPICIOUS_APIS:
        if "#" in api["api"]:
            cls, method = api["api"].split("#")
            cls_escaped = re.escape(cls.replace('.', '/'))
            method_escaped = re.escape(method)
            pattern = rf"{cls_escaped}.*;->{method_escaped}"
        else:
            pattern = re.escape(api["api"].replace('.', '/'))
        patterns.append(pattern)

    SUSPICIOUS_API_PATTERN = re.compile("|".join(patterns), re.IGNORECASE)
    
    # Load trackers DB
    TRACKERS_DB = load_trackers_db()
    
    # Initialize GeoIP reader
    db_path = os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
    try:
        GEOIP_READER = geoip2.database.Reader(db_path)
    except FileNotFoundError:
        print(f"[!] GeoLite2-City.mmdb not found - skipping geo lookup")
        GEOIP_READER = None


def is_text_file(file_path):
    """Check if file is a text file based on extension"""
    name = file_path.name.lower()
    
    if any(name.endswith(ext) for ext in TEXT_EXTENSIONS):
        return True
    
    if any(name.endswith(ext) for ext in BINARY_EXTENSIONS):
        return False
    
    return False


def unique_list(items, key_fields=None):
    """Fast deduplication using dict"""
    if key_fields is None:
        return list(dict.fromkeys(items))
    
    seen = {}
    for item in items:
        key = tuple(item[field] for field in key_fields)
        if key not in seen:
            seen[key] = item
    return list(seen.values())


@lru_cache(maxsize=1)
def parse_manifest(manifest_path):
    """Parse AndroidManifest.xml and extract components - CACHED"""
    result = {
        'permissions': [],
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
    }
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Extract permissions
        for perm in root.findall('.//uses-permission'):
            name = (perm.get('{http://schemas.android.com/apk/res/android}name') or 
                   perm.get('android:name') or 
                   perm.get('name'))
            if name:
                result['permissions'].append(name)
        
        app = root.find('application')
        if app is not None:
            # Extract activities
            for activity in app.findall('activity') + app.findall('activity-alias'):
                name = (activity.get('{http://schemas.android.com/apk/res/android}name') or 
                       activity.get('android:name') or 
                       activity.get('name'))
                if name:
                    result['activities'].append(name)
            
            # Extract services
            for service in app.findall('service'):
                name = (service.get('{http://schemas.android.com/apk/res/android}name') or 
                       service.get('android:name') or 
                       service.get('name'))
                if name:
                    result['services'].append(name)
            
            # Extract receivers
            for receiver in app.findall('receiver'):
                name = (receiver.get('{http://schemas.android.com/apk/res/android}name') or 
                       receiver.get('android:name') or 
                       receiver.get('name'))
                if name:
                    result['receivers'].append(name)
            
            # Extract providers
            for provider in app.findall('provider'):
                name = (provider.get('{http://schemas.android.com/apk/res/android}name') or 
                       provider.get('android:name') or 
                       provider.get('name'))
                if name:
                    result['providers'].append(name)
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def enrich_domain_single(domain):
    """Enrich a single domain - for parallel processing"""
    if not GEOIP_READER:
        return domain, {}
    
    entry = {}
    try:
        ip = socket.gethostbyname(domain)
        response = GEOIP_READER.city(ip)
        entry = {
            "ip": ip,
            "country_short": response.country.iso_code,
            "country_long": response.country.name,
            "latitude": str(response.location.latitude),
            "longitude": str(response.location.longitude)
        }
    except Exception as e:
        pass  # Silent fail for performance
    
    return domain, entry


def enrich_domains_parallel(domains):
    """Enrich domains in parallel using ThreadPool"""
    if not domains:
        return {}
    
    enriched = {}
    unique_domains = list(set(domains))
    
    # Use ThreadPoolExecutor for I/O-bound GeoIP lookups
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(enrich_domain_single, domain): domain 
                  for domain in unique_domains}
        
        for future in as_completed(futures):
            domain, entry = future.result()
            enriched[domain] = entry
    
    return enriched


def load_trackers_db():
    """Load Exodus Privacy tracker database - OPTIMIZED"""
    db_path = os.path.join(os.path.dirname(__file__), "trackers.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        trackers_data = data.get("trackers", data)

        if isinstance(trackers_data, dict):
            trackers_list = list(trackers_data.values())
        elif isinstance(trackers_data, list):
            trackers_list = trackers_data
        else:
            print("[!] Unexpected trackers.json structure:", type(trackers_data))
            return []

        normalized = []
        for tr in trackers_list:
            if not isinstance(tr, dict):
                continue

            # Normalize signatures
            code_sig = tr.get("code_signature")
            if isinstance(code_sig, str):
                code_sig = code_sig.split('|')
            elif code_sig is None:
                code_sig = []

            net_sig = tr.get("network_signature") 
            if isinstance(net_sig, str):
                net_sig = net_sig.split('|')
            elif net_sig is None:
                net_sig = []

            # Lowercase for faster matching
            code_sig = [s.lower() for s in code_sig if s]
            net_sig = [s.lower() for s in net_sig if s]

            tr["_code_signature"] = code_sig
            tr["_network_signature"] = net_sig

            normalized.append(tr)

        return normalized

    except Exception as e:
        print("[!] Could not load trackers.json:", e)
        return []


def detect_tracker(content_lower, trackers):
    """Detect trackers - optimized with pre-lowercased content"""
    detected = []

    for tr in trackers:
        found = False

        for sig in tr.get("_code_signature", []):
            if sig and sig in content_lower:
                found = True
                break

        if not found:
            for net in tr.get("_network_signature", []):
                if net and net in content_lower:
                    found = True
                    break

        if found:
            detected.append({
                "name": tr["name"],
                "categories": ", ".join(tr.get("categories", [])),
                "url": f"https://reports.exodus-privacy.eu.org/trackers/{tr.get('id')}"
            })

    # Deduplicate
    uniq = {t['name']: t for t in detected}
    return list(uniq.values())


def process_single_file(file_info):
    """Process a single file - designed for parallel execution"""
    file_path, folder_path = file_info
    
    result = {
        'url_entry': None,  # MobSF-style URL entry
        'emails': [],
        'suspicious_apis': [],
        'trackers': [],
        'score': 0,
        'domains': []
    }
    
    try:
        # Read file efficiently
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Skip if content is too small (likely binary/corrupted)
        if len(content) < 10:
            return result
        
        content_lower = content.lower()
        
        # Extract URLs
        urls_found = URL_PATTERN.findall(content)
        
        # Create MobSF-style URL entry if URLs found
        if urls_found:
            unique_urls = list(dict.fromkeys(urls_found))  # Deduplicate while preserving order
            result['url_entry'] = {
                'urls': unique_urls,
                'path': str(file_path.relative_to(folder_path))
            }
            result['score'] += len(unique_urls) * 5
            
            # Extract domains from URLs
            for url in unique_urls:
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc.strip().lower()
                    if domain and not domain.startswith('%') and '.' in domain:
                        result['domains'].append(domain)
                except:
                    pass
        
        # Extract emails
        emails = EMAIL_PATTERN.findall(content)
        result['emails'] = emails
        result['score'] += len(emails) * 3
        
        # Extract suspicious API calls
        api_matches = []
        for match in SUSPICIOUS_API_PATTERN.finditer(content):
            api_name = match.group()
            api_info = API_LOOKUP.get(api_name, {"category": "Unknown", "risk": "Unknown"})
            api_matches.append({
                "api": api_name,
                "category": api_info["category"],
                "risk": api_info["risk"],
                "file": str(file_path.relative_to(folder_path))
            })
        result['suspicious_apis'] = api_matches
        result['score'] += len(api_matches) * 6
        
        # Detect trackers
        tracker_hits = detect_tracker(content_lower, TRACKERS_DB)
        if tracker_hits:
            result['trackers'] = tracker_hits
            result['score'] += len(tracker_hits) * 8
    
    except Exception as e:
        # Silent fail, return empty result
        pass
    
    return result


def perform_scan_parallel(folder_path):
    """Perform scan with parallel processing - MAIN OPTIMIZATION"""
    folder = Path(folder_path)
    
    if not folder.is_dir():
        raise ValueError(f"Folder does not exist: {folder_path}")
    
    # Initialize result
    result = {
        'scanned_folder': str(folder.absolute()),
        'scan_timestamp': datetime.now().isoformat(),
        'manifest': {},
        'urls': [],
        'emails': [],
        'suspicious_api_calls': [],
        'native_libs': [],
        'domains': {},
        'top_suspicious_files': [],
        'heuristic_risk_score': 0,
        'trackers': {}
    }
    
    # Parse manifest (fast operation)
    manifest_path = folder / 'AndroidManifest.xml'
    if manifest_path.exists():
        result['manifest'] = parse_manifest(str(manifest_path))
    else:
        result['manifest'] = {'error': 'AndroidManifest.xml not found'}
    
    # Collect all text files and native libs
    text_files = []
    native_libs = []
    
    for file_path in folder.rglob('*'):
        if not file_path.is_file():
            continue
        
        file_name = file_path.name.lower()
        
        # Detect native libraries
        if file_name.endswith('.so') or file_name.endswith('.elf'):
            native_libs.append(str(file_path))
            continue
        
        # Only process text files
        if is_text_file(file_path):
            text_files.append((file_path, folder))
    
    print(f"[DEBUG] Found {len(text_files)} text files to scan")
    
    # Process files in parallel
    all_url_entries = []  # MobSF-style URL list
    all_emails = []
    all_suspicious_apis = []
    all_domains = []
    all_trackers = {}
    file_scores = defaultdict(int)
    
    # Optimize worker count
    max_workers = min(32, (os.cpu_count() or 4) * 2)
    
    # Use ThreadPoolExecutor since we're I/O bound (reading files)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_file, file_info): file_info[0] 
                  for file_info in text_files}
        
        total = len(futures)
        
        for future in as_completed(futures):
            file_path = futures[future]
            try:
                file_result = future.result()
                
                # Aggregate results - MobSF style
                if file_result['url_entry']:
                    all_url_entries.append(file_result['url_entry'])
                
                all_emails.extend(file_result['emails'])
                all_suspicious_apis.extend(file_result['suspicious_apis'])
                all_domains.extend(file_result['domains'])
                
                if file_result['trackers']:
                    all_trackers[str(file_path)] = file_result['trackers']
                
                if file_result['score'] > 0:
                    file_scores[str(file_path)] = file_result['score']
                    
            except Exception as e:
                pass  # Silent fail
    
    # Deduplicate results - MobSF style for URLs
    result['urls'] = all_url_entries  # Already grouped by file
    result['emails'] = unique_list(all_emails)
    result['suspicious_api_calls'] = unique_list(all_suspicious_apis, ["api", "file"])
    result['native_libs'] = unique_list(native_libs)
    
    # Enrich domains in parallel
    result['domains'] = enrich_domains_parallel(all_domains)
    
    # Top suspicious files
    top_files = sorted(file_scores.items(), key=lambda x: x[1], reverse=True)[:50]
    result['top_suspicious_files'] = [
        {'file': file_path, 'score': score}
        for file_path, score in top_files
    ]
    
    # Calculate risk score
    risk_score = 0
    risk_score += len(result['suspicious_api_calls']) * 6
    risk_score += len(result['urls']) * 5
    risk_score += len(result['native_libs']) * 10
    result['heuristic_risk_score'] = risk_score
    
    # Merge tracker results
    all_found = []
    for file, trlist in all_trackers.items():
        for tr in trlist:
            all_found.append(tr)
    
    unique_detected = {t["name"]: t for t in all_found}.values()
    
    result["trackers"] = {
        "detected_trackers": len(unique_detected),
        "total_trackers": len(TRACKERS_DB) if TRACKERS_DB else 0,
        "trackers": list(unique_detected)
    }
    
    return result


@app.route('/analyze', methods=['POST'])
def upload_and_scan_apk():
    if 'file' not in request.files:
        return jsonify({'error': 'Missing file parameter'}), 400

    apk_file = request.files['file']
    if apk_file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    base_name, ext = os.path.splitext(apk_file.filename)
    apk_path = os.path.join(BASE_DIR, apk_file.filename)
    decode_folder = os.path.join(BASE_DIR, base_name)

    # Remove old decode folder
    if os.path.exists(decode_folder):
        shutil.rmtree(decode_folder)

    # Save APK file
    with open(apk_path, "wb") as f:
        f.write(apk_file.read())

    try:
        APKTOOL_BAT = r"C:\Users\ADMIN\Desktop\Study\KLTN\apktool\apktool.bat"
        cmd = [APKTOOL_BAT, "d", apk_path, "-o", decode_folder]

        completed = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=900)

    except subprocess.CalledProcessError as e:
        print("[ERROR] Apktool failed ❌")
        return jsonify({
            'error': 'Failed to decode APK',
            'details': e.stderr or e.stdout or str(e)
        }), 500

    # Start scanning with parallel processing
    try:
        if not os.path.exists(decode_folder):
            raise Exception(f"Decode folder not found: {decode_folder}")

        result = perform_scan_parallel(decode_folder)
        return jsonify(result)
    except Exception as e:
        print("[ERROR] Scan failed ❌", str(e))
        return jsonify({'error': 'Scan failed', 'details': str(e)}), 500


if __name__ == "__main__":
    init_globals()
    print("[INFO] Server starting at http://0.0.0.0:5070")
    app.run(host="0.0.0.0", port=5070, debug=False, threaded=True)