import os
import json
import logging
import traceback
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, render_template
import re

app = Flask(__name__)

# Configure basic logging without rotation to avoid file access issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler()  # Log to console only
    ]
)
app.logger.setLevel(logging.INFO)
app.logger.info('Flask app startup')

def read_syslog(max_lines=1000):
    """Read and parse the syslog file."""
    logs = []
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'syslog.log')
        if not os.path.exists(log_path):
            app.logger.warning(f"Syslog file not found at {log_path}")
            return logs

        line_count = 0
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    line = line.strip()
                    if not line:
                        continue

                    # Skip header lines and non-JSON lines
                    if line.startswith('===') or line.startswith('Real-time') or \
                       line.startswith('Successfully') or line.startswith('Monitoring') or \
                       line.startswith('Error') or line.startswith('Would send email') or \
                       line.startswith('Google Drive') or line.startswith('All monitoring') or \
                       line.startswith('Subject:') or line.startswith('Body:') or \
                       line.startswith('The following') or line.startswith('File') or \
                       line.startswith('New file') or line.startswith('Owner:') or \
                       line.startswith('Initial permissions') or line.startswith('Timestamp:') or \
                       line.startswith('-') or line.startswith('removed') or line.startswith('  '):
                        
                        # Check specifically for Dropbox email notifications that contain detailed changes
                        if "Subject: Dropbox Change:" in line:
                            # This is a Dropbox change email notification - capture file info
                            filename = line.replace("Subject: Dropbox Change:", "").strip()
                            path = ""
                            file_id = ""
                            changes = {}
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # Read the next few lines to get details
                            next_lines = []
                            for _ in range(10):  # Read up to 10 lines to find relevant info
                                try:
                                    next_line = next(f).strip()
                                    next_lines.append(next_line)
                                    
                                    if "Path:" in next_line:
                                        path = next_line.replace("Path:", "").strip()
                                    elif "File ID:" in next_line:
                                        file_id = next_line.replace("File ID:", "").strip()
                                    elif "Timestamp:" in next_line:
                                        timestamp = next_line.replace("Timestamp:", "").strip()
                                    elif "Changes:" in next_line:
                                        # The changes details follow
                                        change_lines = []
                                        for _ in range(5):  # Read up to 5 change lines
                                            try:
                                                change_line = next(f).strip()
                                                if change_line.startswith('-'):
                                                    change_parts = change_line.lstrip('- ').split(': Changed from ')
                                                    if len(change_parts) >= 2:
                                                        key = change_parts[0].strip()
                                                        values = change_parts[1].replace("'", "").split(' to ')
                                                        old_val = values[0].strip()
                                                        new_val = values[1].strip() if len(values) > 1 else None
                                                        changes[key] = {"old": old_val, "new": new_val}
                                            except StopIteration:
                                                break
                                except StopIteration:
                                    break
                            
                            # Create a log entry for this Dropbox change
                            if file_id:
                                log_entry = {
                                    "file_id": file_id,
                                    "file_name": filename,
                                    "owner": "Dropbox User",
                                    "timestamp": timestamp,
                                    "details": {
                                        "source": "dropbox",
                                        "file_name": filename,
                                        "path": path,
                                        "type": "file_deleted" if "status" in changes and changes["status"]["new"] == "deleted" else "changes",
                                        "changes": changes,
                                        "modified_by": {
                                            "name": "Dropbox System",
                                            "email": "notifications@dropbox.com"
                                        }
                                    }
                                }
                                logs.append(log_entry)
                                line_count += 1
                        
                        continue

                    # Special handling for Dropbox notification lines embedded in logs
                    if "Subject: Dropbox Change:" in line:
                        continue  # Skip, this will be handled above

                    # Parse JSON logs
                    if line.startswith('{') and line.endswith('}'):
                        log_data = json.loads(line)
                        
                        # Ensure all logs have details object and source field
                        if 'details' not in log_data:
                            log_data['details'] = {}
                        
                        # Determine the source based on the structure
                        if 'details' in log_data:
                            # Set default source as google_drive if not specified
                            if 'source' not in log_data['details']:
                                # Check if it's a Dropbox log based on content
                                if ('file_id' in log_data and log_data['file_id'].startswith('id:')) or \
                                   ('path' in log_data['details'] and 'dropbox' in log_data['details'].get('path', '').lower()):
                                    log_data['details']['source'] = 'dropbox'
                                else:
                                    log_data['details']['source'] = 'google_drive'
                            
                            # Ensure there's a 'modified_by' field
                            if 'modified_by' not in log_data['details']:
                                # Try to extract from changes if it exists
                                if 'changes' in log_data['details'] and isinstance(log_data['details']['changes'], list):
                                    for change in log_data['details']['changes']:
                                        if 'modified_by' in change:
                                            log_data['details']['modified_by'] = change['modified_by']
                                            break
                                    else:
                                        # Default if not found in changes
                                        log_data['details']['modified_by'] = {
                                            'name': 'Unknown',
                                            'email': 'unknown@example.com'
                                        }
                                else:
                                    # Default if no changes field
                                    log_data['details']['modified_by'] = {
                                        'name': 'Unknown',
                                        'email': 'unknown@example.com'
                                    }
                        
                        logs.append(log_data)
                        line_count += 1
                        
                        if max_lines and line_count >= max_lines:
                            break
                except json.JSONDecodeError as json_err:
                    app.logger.warning(f"Failed to parse JSON in line: {line[:100]}... Error: {json_err}")
                    continue
                except Exception as e:
                    app.logger.warning(f"Error parsing log line: {str(e)}")
                    continue

        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return logs
    except Exception as e:
        app.logger.error(f"Error reading syslog: {str(e)}\n{traceback.format_exc()}")
        return []

@app.route('/')
def index():
    """Render the dashboard."""
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    """Get logs from the syslog file."""
    try:
        logs = read_syslog(max_lines=None)  # Read all logs
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"Error reading logs: {str(e)}\n{traceback.format_exc()}")
        return jsonify([])

@app.route('/api/stats')
def get_stats():
    """Get statistics of the logs."""
    try:
        # Read logs
        logs = read_syslog(max_lines=None)  # Read all logs
        
        if not logs:
            # Return empty stats if no logs found - no sample data
            return jsonify({
                'google_drive': {
                    'total_changes': 0,
                    'new_files': 0,
                    'deleted_files': 0,
                    'permission_changes': 0,
                    'last_24h': 0
                },
                'dropbox': {
                    'total_changes': 0,
                    'new_files': 0,
                    'deleted_files': 0,
                    'last_24h': 0
                },
                'total': {
                    'total_changes': 0,
                    'last_24h': 0
                },
                'gdrive_logs': [],
                'dropbox_logs': []
            })
        
        # Separate logs by source
        gdrive_logs = []
        dropbox_logs = []
        
        for log in logs:
            try:
                source = log.get('details', {}).get('source', 'google_drive')
                if source == 'dropbox':
                    dropbox_logs.append(log)
                else:
                    gdrive_logs.append(log)
            except Exception as e:
                app.logger.warning(f"Error sorting log by source: {e}")
        
        # Google Drive stats - only from actual logs
        gdrive_total = len(gdrive_logs)
        gdrive_new_files = sum(1 for log in gdrive_logs if log.get('details', {}).get('type') == 'new_file')
        gdrive_deleted_files = sum(1 for log in gdrive_logs if log.get('details', {}).get('type') == 'file_deleted')
        gdrive_permission_changes = sum(1 for log in gdrive_logs 
                                      if log.get('details', {}).get('type') == 'changes' 
                                      and log.get('details', {}).get('changes', []))
        
        # Dropbox stats - only from actual logs
        dropbox_total = len(dropbox_logs)
        dropbox_new_files = sum(1 for log in dropbox_logs 
                               if (log.get('details', {}).get('type') == 'changes' 
                                  and 'status' not in log.get('details', {}).get('changes', {})))
        dropbox_deleted_files = sum(1 for log in dropbox_logs if log.get('details', {}).get('type') == 'file_deleted')
        
        # Recent activity (last 24 hours) - only from actual logs
        try:
            last_24h = datetime.now() - timedelta(hours=24)
            
            # Count Google Drive logs in the last 24 hours
            gdrive_recent = 0
            for log in gdrive_logs:
                try:
                    if 'timestamp' in log:
                        log_time = datetime.strptime(log['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                        if log_time > last_24h:
                            gdrive_recent += 1
                except Exception as e:
                    app.logger.warning(f"Error parsing timestamp in Google Drive log: {e}")
            
            # Count Dropbox logs in the last 24 hours
            dropbox_recent = 0
            for log in dropbox_logs:
                try:
                    if 'timestamp' in log:
                        log_time = datetime.strptime(log['timestamp'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                        if log_time > last_24h:
                            dropbox_recent += 1
                except Exception as e:
                    app.logger.warning(f"Error parsing timestamp in Dropbox log: {e}")
                    
        except Exception as e:
            # Default to zero if calculation fails
            app.logger.error(f"Error calculating recent logs: {e}")
            gdrive_recent = 0
            dropbox_recent = 0
        
        # Combined stats - only from actual logs
        total_changes = gdrive_total + dropbox_total
        total_recent = gdrive_recent + dropbox_recent
        
        # Return stats with logs for chart rendering - no sample data
        response_data = {
            'google_drive': {
                'total_changes': gdrive_total,
                'new_files': gdrive_new_files,
                'deleted_files': gdrive_deleted_files,
                'permission_changes': gdrive_permission_changes,
                'last_24h': gdrive_recent
            },
            'dropbox': {
                'total_changes': dropbox_total,
                'new_files': dropbox_new_files,
                'deleted_files': dropbox_deleted_files,
                'last_24h': dropbox_recent
            },
            'total': {
                'total_changes': total_changes,
                'last_24h': total_recent
            },
            'gdrive_logs': gdrive_logs,
            'dropbox_logs': dropbox_logs
        }
        
        return jsonify(response_data)
    except Exception as e:
        app.logger.error(f"Error calculating stats: {str(e)}\n{traceback.format_exc()}")
        # Return empty structure on error - no sample data
        return jsonify({
            'error': str(e),
            'google_drive': {'total_changes': 0, 'new_files': 0, 'deleted_files': 0, 'permission_changes': 0, 'last_24h': 0},
            'dropbox': {'total_changes': 0, 'new_files': 0, 'deleted_files': 0, 'last_24h': 0},
            'total': {'total_changes': 0, 'last_24h': 0},
            'gdrive_logs': [],
            'dropbox_logs': []
        })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
