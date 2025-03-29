import os
import json
import logging
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, render_template
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
file_handler = RotatingFileHandler('app.log', maxBytes=1024 * 1024, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Flask app startup')

def read_syslog(max_lines=1000):
    """Read and parse syslog entries."""
    logs = []
    try:
        if not os.path.exists("syslog.log"):
            app.logger.warning("syslog.log file does not exist")
            return []
            
        with open("syslog.log", "r", encoding="utf-8") as f:
            for line in f:
                try:
                    line = line.strip()
                    # Skip empty lines and startup marker lines
                    if not line or line.startswith("====="):
                        continue
                        
                    # Try parsing the whole line as JSON first (for direct writes)
                    try:
                        log_entry = json.loads(line)
                        logs.append(log_entry)
                        continue
                    except json.JSONDecodeError:
                        pass
                        
                    # Find JSON content in the line (for syslog format)
                    json_start = line.find("{")
                    if json_start != -1:
                        json_str = line[json_start:]
                        # Each line should be a complete JSON object
                        log_entry = json.loads(json_str)
                        logs.append(log_entry)
                    
                    if len(logs) >= max_lines:
                        break
                except json.JSONDecodeError as e:
                    app.logger.warning(f"JSON decode error: {e} in line: {line}")
                    continue
                except Exception as e:
                    app.logger.warning(f"Error processing log line: {e}")
                    continue
    except Exception as e:
        app.logger.error(f"Error reading syslog: {e}")
    
    # Sort logs by timestamp if available
    try:
        logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    except Exception as e:
        app.logger.warning(f"Error sorting logs: {e}")
        
    return logs

@app.route('/')
def index():
    """Render the dashboard."""
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    """Get the latest logs."""
    try:
        logs = read_syslog(max_lines=100)
        return jsonify({
            "status": "success",
            "data": logs
        })
    except Exception as e:
        app.logger.error(f"Error getting logs: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/stats')
def get_stats():
    """Get statistics from logs."""
    try:
        logs = read_syslog()
        
        # Initialize stats
        stats = {
            "total_changes": len(logs),
            "changes_by_type": defaultdict(int),
            "most_active_files": defaultdict(int),
            "most_active_users": defaultdict(int),
            "changes_over_time": defaultdict(int),
            "permission_changes": defaultdict(int)
        }
        
        # Process each log entry
        for log in logs:
            try:
                details = log.get("details", {})
                
                # Count by change type
                change_type = details.get("type", "unknown")
                stats["changes_by_type"][change_type] += 1
                
                # Count by file
                file_name = log.get("file_name", "unknown")
                stats["most_active_files"][file_name] += 1
                
                # Count by user
                owner = log.get("owner", "unknown")
                stats["most_active_users"][owner] += 1
                
                # Count changes over time (by day)
                try:
                    date = datetime.strptime(log.get("timestamp", ""), "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d")
                    stats["changes_over_time"][date] += 1
                except:
                    app.logger.warning(f"Invalid timestamp in log: {log.get('timestamp')}")
                
                # Count permission changes
                if change_type == "changes":
                    for change in details.get("changes", []):
                        if change.get("type") in ["permission_added", "permission_removed", "permission_changed"]:
                            stats["permission_changes"][change.get("type", "unknown")] += 1
                elif change_type == "new_file":
                    # Count initial permissions as additions
                    for _ in details.get("permissions", []):
                        stats["permission_changes"]["permission_added"] += 1
                        
            except Exception as e:
                app.logger.error(f"Error processing log entry: {e}")
                continue
        
        # Sort changes over time by date
        stats["changes_over_time"] = dict(sorted(stats["changes_over_time"].items()))
        
        # Convert defaultdicts to regular dicts for JSON serialization
        return jsonify({
            "status": "success",
            "data": {k: dict(v) if isinstance(v, defaultdict) else v for k, v in stats.items()}
        })
    except Exception as e:
        app.logger.error(f"Error getting stats: {e}")
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
