import os
import csv
import requests
import json
import datetime
import ssl
import certifi
import hashlib
import re
import numpy as np
import smtplib
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer
import logging
import logging.handlers
import time
import sys
import slack_notify

# Configure the logger
logger = logging.getLogger('SaaS_Monitoring')
logger.setLevel(logging.INFO)

# Configure the SysLogHandler
syslog_handler = logging.handlers.SysLogHandler(address=('127.0.0.1', 1514))
formatter = logging.Formatter('%(asctime)s %(name)s: %(message)s', datefmt='%b %d %H:%M:%S')
syslog_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(syslog_handler)


# **🔹 Load Embedding Model**
model = SentenceTransformer("D:\\secureAPI\\all-MiniLM-L6-v2")

# # **🔹 SSL Fix**
# os.environ["SSL_CERT_FILE"] = certifi.where()
# ssl_context = ssl.create_default_context(cafile=certifi.where())

# # Configure proxy to use HTTP instead of HTTPS
# os.environ['HTTP_PROXY'] = 'http://localhost:8001'  # Update with your actual proxy address
# os.environ['HTTPS_PROXY'] = 'http://localhost:8001'  # Use HTTP protocol for HTTPS requests


# **🔹 Configuration**
SCOPES = ["https://www.googleapis.com/auth/drive"]
TOKEN_FILE = "token1.json"  # Ensure this is properly configured
CREDENTIALS_FILE = "credentials.json"  # Replace with your actual credentials file
PINECONE_API_KEY = "pcsk_3xs3j4_RqkwrJt6UHbym2YJM16TvT5yunfKtSbeJt3HnJZrcB1nwhJD9q9Gsv1t2ZoYe8k"  # 🔐 Replace with your actual Pinecone API key
INDEX_NAME = "drive-metadata-index"
LOG_FILE = "syslog_client.log"  # Log file for monitoring
ALERTS_FILE = "alerts_log.json"  # Store previously alerted changes

# **🔹 Initialize Pinecone**
pc = Pinecone(api_key=PINECONE_API_KEY)
if INDEX_NAME not in pc.list_indexes().names():
    pc.create_index(
        name=INDEX_NAME,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
index = pc.Index(INDEX_NAME)

def log_event(message):
    """Save logs to a file and print them."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} - SaaS_Monitor - {message}"
    print(log_message)  # Print to console
    
    try:
        # Write to syslog via logger
        if isinstance(message, dict):
            # Ensure the message is properly formatted as JSON
            json_str = json.dumps(message)
            logger.info(json_str)
        else:
            # If it's a string, log as is
            logger.info(message)
        
        # Force logger to flush its handlers
        for handler in logger.handlers:
            handler.flush()
            
        # Direct write fallback - ensure we get something in the log file
        try:
            if isinstance(message, dict):
                json_str = json.dumps(message)
                with open("syslog.log", "a", encoding="utf-8") as f:
                    f.write(json_str + "\n")
            else:
                with open("syslog.log", "a", encoding="utf-8") as f:
                    f.write(f"{message}\n")
        except Exception as e:
            print(f"Error writing directly to syslog.log: {e}")
    except Exception as e:
        print(f"Error writing to syslog: {e}")

def load_alerts():
    """Load previously sent alerts to avoid duplicate notifications."""
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_alerts(alerts):
    """Save the updated alerts log."""
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

def clean_vector(vector):
    """Ensure the vector is 384-dimensional and contains valid values."""
    vector = np.nan_to_num(vector, nan=0.0, posinf=1.0, neginf=-1.0)  # Replace invalid values
    if len(vector) != 384:
        print(f"Warning: Adjusting vector size from {len(vector)} to 384.")
        vector = np.pad(vector, (0, max(0, 384 - len(vector))), mode='constant')[:384]  # Trim or pad
    return vector.tolist()

def get_existing_metadata(file_id):
    """Fetch stored metadata & permissions from Pinecone."""
    try:
        fetched_vectors = index.fetch(ids=[file_id])
        if file_id in fetched_vectors.vectors:
            metadata = fetched_vectors.vectors[file_id].metadata
            # Convert JSON strings back to objects
            for key, value in metadata.items():
                if isinstance(value, str):
                    try:
                        parsed = json.loads(value)
                        if isinstance(parsed, (dict, list)):
                            metadata[key] = parsed
                    except:
                        pass  # Keep as string if not valid JSON
            return metadata
    except Exception as e:
        log_event(f"Error fetching metadata from Pinecone: {e}")
    return None

def process_drive_file(file, service):
    """Process a single drive file."""
    try:
        file_id = file.get('id')
        if not file_id:
            return
            
        metadata = {
            'id': file_id,
            'name': file.get('name', 'Unknown'),
            'mimeType': file.get('mimeType', 'Unknown'),
            'permissions': file.get('permissions', []),
            'trashed': file.get('trashed', False)
        }
        
        # If file is trashed, we don't need to process it further
        # as it will be handled by the deletion check in main()
        if metadata.get('trashed', False):
            return
            
        changes = detect_change(file_id, metadata, service)
        if changes:
            log_event({
                "file_id": file_id,
                "file_name": metadata.get("name", "Unknown"),
                "owner": next((p.get("emailAddress") for p in metadata.get("permissions", []) 
                             if p.get("role") == "owner"), "Unknown"),
                "details": changes,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
    except Exception as e:
        log_event(f"Error processing file {file.get('id', 'Unknown')}: {e}")

def calculate_metadata_hash(metadata):
    """Calculate a hash of the metadata to detect changes."""
    relevant_data = {
        "name": metadata.get("name"),
        "permissions": sorted([
            (p.get("emailAddress", ""), p.get("role", ""))
            for p in metadata.get("permissions", [])
        ])
    }
    return hashlib.md5(json.dumps(relevant_data, sort_keys=True).encode()).hexdigest()

def sanitize_metadata(metadata):
    """Convert complex metadata to simple types for Pinecone."""
    sanitized = {}
    for key, value in metadata.items():
        if isinstance(value, (str, int, float, bool)):
            sanitized[key] = value
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            sanitized[key] = value
        else:
            # Convert complex objects to JSON string
            sanitized[key] = json.dumps(value)
    return sanitized

def detect_change(file_id, new_metadata, service):
    """Detects metadata changes and sends alerts only for new changes."""
    try:
        existing_metadata = get_existing_metadata(file_id)
        if existing_metadata and not isinstance(existing_metadata, dict):
            log_event(f"Invalid metadata format for {file_id}")
            existing_metadata = None
            
        new_hash = calculate_metadata_hash(new_metadata)
        
        # Load alerts
        alerts = load_alerts()
        alert_key = f"{file_id}"
        
        # Check if this exact state was already processed
        if alert_key in alerts and alerts[alert_key] == new_hash:
            return None
            
        # Get the user who made the change from the Drive API
        try:
            # First try to get the last modifier from revision history
            revision = service.revisions().list(
                fileId=file_id,
                fields="revisions(lastModifyingUser)",
                pageSize=1
            ).execute()
            
            # Then get the file's change history
            history = service.files().get(
                fileId=file_id,
                fields="lastModifyingUser,sharingUser",
                supportsAllDrives=True
            ).execute()
            
            # For permission changes, use sharingUser if available
            if history.get('sharingUser'):
                modifier_info = {
                    "name": history['sharingUser'].get('displayName', 'Unknown'),
                    "email": history['sharingUser'].get('emailAddress', 'Unknown')
                }
            # For other changes, use lastModifyingUser
            elif history.get('lastModifyingUser'):
                modifier_info = {
                    "name": history['lastModifyingUser'].get('displayName', 'Unknown'),
                    "email": history['lastModifyingUser'].get('emailAddress', 'Unknown')
                }
            # Fallback to revision history
            elif revision.get('revisions') and revision['revisions'][-1].get('lastModifyingUser'):
                last_modifier = revision['revisions'][-1]['lastModifyingUser']
                modifier_info = {
                    "name": last_modifier.get('displayName', 'Unknown'),
                    "email": last_modifier.get('emailAddress', 'Unknown')
                }
            else:
                modifier_info = {
                    "name": "Unknown",
                    "email": "Unknown"
                }
        except Exception as e:
            log_event(f"Error getting last modifier: {e}")
            modifier_info = {
                "name": "Unknown",
                "email": "Unknown"
            }

        # Prepare change details for other changes
        if not existing_metadata:
            change_details = {
                "type": "new_file",
                "file_name": new_metadata.get("name", "Unknown"),
                "owner": next((p.get("emailAddress") for p in new_metadata.get("permissions", []) 
                             if p.get("role") == "owner"), "Unknown"),
                "permissions": new_metadata.get("permissions", []),
                "modified_by": modifier_info,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            changes = []
            
            # Check name changes
            if existing_metadata.get("name") != new_metadata.get("name"):
                changes.append({
                    "type": "name_change",
                    "old": existing_metadata.get("name"),
                    "new": new_metadata.get("name"),
                    "modified_by": modifier_info
                })
            
            # Check permission changes
            old_perms = {p.get("emailAddress"): p for p in existing_metadata.get("permissions", [])}
            new_perms = {p.get("emailAddress"): p for p in new_metadata.get("permissions", [])}
            
            for email, perm in new_perms.items():
                if email not in old_perms:
                    changes.append({
                        "type": "permission_added",
                        "user": email,
                        "user_name": perm.get("displayName", "Unknown"),
                        "role": perm.get("role"),
                        "modified_by": modifier_info
                    })
                elif old_perms[email].get("role") != perm.get("role"):
                    changes.append({
                        "type": "permission_changed",
                        "user": email,
                        "user_name": perm.get("displayName", "Unknown"),
                        "old_role": old_perms[email].get("role"),
                        "new_role": perm.get("role"),
                        "modified_by": modifier_info
                    })
            
            for email, perm in old_perms.items():
                if email not in new_perms:
                    changes.append({
                        "type": "permission_removed",
                        "user": email,
                        "user_name": perm.get("displayName", "Unknown"),
                        "role": perm.get("role"),
                        "modified_by": modifier_info
                    })
            
            if not changes:
                return None
                
            change_details = {
                "type": "changes",
                "file_name": new_metadata.get("name", "Unknown"),
                "owner": next((p.get("emailAddress") for p in new_metadata.get("permissions", []) 
                             if p.get("role") == "owner"), "Unknown"),
                "changes": changes,
                "modified_by": modifier_info,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        # Update alerts with new hash
        alerts[alert_key] = new_hash
        save_alerts(alerts)
        
        # Store the new metadata in Pinecone
        try:
            # Create a vector of 384 dimensions with small random values
            vector = [float(0.1) for _ in range(384)]
            
            # Sanitize metadata for Pinecone
            sanitized_metadata = sanitize_metadata(new_metadata)
            
            index.upsert(vectors=[{
                "id": file_id,
                "metadata": sanitized_metadata,
                "values": vector
            }])
        except Exception as e:
            log_event(f"Error updating Pinecone: {e}")
        
        # Log and send alert
        log_message = {
            "file_id": file_id,
            "file_name": new_metadata.get("name", "Unknown"),
            "owner": next((p.get("emailAddress") for p in new_metadata.get("permissions", []) 
                         if p.get("role") == "owner"), "Unknown"),
            "details": change_details,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        log_event(log_message)
        
        try:
            send_email_alert(file_id, change_details)
        except Exception as e:
            log_event(f"Failed to send email alert: {e}")
        
        return change_details
        
    except Exception as e:
        log_event(f"Error in detect_change: {e}")
        return None

def send_email_alert(file_id, change_details):
    """Send email alert for changes."""
    try:
        # For testing, we'll just log the email content
        sender = "your-email@gmail.com"
        receivers = ["admin@example.com"]
        
        # Get modifier information
        modifier = change_details.get("modified_by", {})
        modifier_text = f"{modifier.get('name', 'Unknown')}"
        if modifier.get('email') and modifier.get('email') != "Unknown":
            modifier_text += f" ({modifier.get('email')})"
        
        # Create a more detailed message
        if change_details["type"] == "new_file":
            subject = f"New file detected: {change_details['file_name']}"
            body = [
                f"New file '{change_details['file_name']}' was created by {modifier_text}",
                f"Owner: {change_details['owner']}",
                "\nInitial permissions:"
            ]
            for perm in change_details.get("permissions", []):
                body.append(f"- {perm.get('displayName', 'Unknown')} ({perm.get('emailAddress')}): {perm.get('role')}")
        elif change_details["type"] == "file_deleted":
            subject = f"File deleted: {change_details['file_name']}"
            body = [
                f"File '{change_details['file_name']}' was deleted",
                f"Previous owner: {change_details['owner']}",
                f"File ID: {file_id}"
            ]
            if modifier_text != "Unknown":
                body.insert(1, f"Deleted by: {modifier_text}")
        else:
            subject = f"Changes detected in: {change_details['file_name']}"
            body = [f"The following changes were detected in '{change_details['file_name']}':"]
            
            for change in change_details.get("changes", []):
                change_modifier = change.get("modified_by", {})
                change_modifier_text = f"{change_modifier.get('name', 'Unknown')}"
                if change_modifier.get('email') and change_modifier.get('email') != "Unknown":
                    change_modifier_text += f" ({change_modifier.get('email')})"
                
                if change["type"] == "name_change":
                    body.append(f"- File renamed from '{change['old']}' to '{change['new']}' by {change_modifier_text}")
                elif change["type"] == "permission_added":
                    body.append(f"- {change_modifier_text} added {change['role']} permission for {change['user_name']} ({change['user']})")
                elif change["type"] == "permission_removed":
                    body.append(f"- {change_modifier_text} removed permission for {change['user_name']} ({change['user']})")
                elif change["type"] == "permission_changed":
                    body.append(f"- {change_modifier_text} changed {change['user_name']} ({change['user']})'s role from {change['old_role']} to {change['new_role']}")
        
        body.append(f"\nTimestamp: {change_details['timestamp']}")
        body.append(f"File ID: {file_id}")
        
        # For now, just log the email content instead of sending
        email_content = f"Would send email:\nSubject: {subject}\nBody:\n" + "\n".join(body)
        log_event(email_content)
        
        # Create a more concise Slack message
        slack_message = f"*{subject}*\n"
        if change_details["type"] == "changes":
            slack_message += "Changes made:\n"
            for line in body[1:]:  # Skip the first line as it's redundant with the subject
                if line.startswith("-"):  # Only include the change lines
                    slack_message += f"{line}\n"
        else:
            slack_message += "\n".join(body)
        
        # Send to Slack
        slack_notify.send_slack_message(
            "xoxb-8649015195078-8653518511733-s7bOWL8qcH2xy6hDW5Iwe0VR",
            "#eventlog",
            slack_message
        )
        
    except Exception as e:
        log_event(f"Failed to prepare email alert: {str(e)}")

def main():
    """Shows basic usage of the Drive v3 API."""
    try:
        creds = None
        if os.path.exists("token1.json"):
            creds = Credentials.from_authorized_user_file("token1.json", SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=52166)
            with open("token1.json", "w") as token:
                token.write(creds.to_json())

        service = build("drive", "v3", credentials=creds)
        
        log_event("Real-time Google Drive Metadata Monitoring Started...")
        
        try:
            # Get all files including trashed ones
            results = service.files().list(
                pageSize=100,
                fields="nextPageToken, files(id, name, mimeType, permissions, trashed)",
                includeItemsFromAllDrives=True,
                supportsAllDrives=True
            ).execute()
            
            log_event("Successfully fetched Drive metadata!")
            
            # Get current file IDs
            current_files = {file['id']: file for file in results.get('files', [])}
            
            # Get previously stored file IDs from Pinecone
            try:
                # Query Pinecone to get all stored file IDs
                query_response = index.query(
                    vector=[0.1] * 384,  # Dummy vector
                    top_k=1000,
                    include_metadata=True
                )
                
                # Convert metadata strings back to objects
                stored_files = {}
                for match in query_response.matches:
                    if match.id and match.metadata:
                        metadata = match.metadata
                        # Convert JSON strings back to objects
                        for key, value in metadata.items():
                            if isinstance(value, str):
                                try:
                                    parsed = json.loads(value)
                                    if isinstance(parsed, (dict, list)):
                                        metadata[key] = parsed
                                except:
                                    pass  # Keep as string if not valid JSON
                        stored_files[match.id] = metadata
                
                # Check for deleted files (files that were in storage but not in current files)
                for file_id, metadata in stored_files.items():
                    if file_id not in current_files:
                        # File was deleted
                        change_details = {
                            "type": "file_deleted",
                            "file_name": metadata.get("name", "Unknown"),
                            "owner": next((p.get("emailAddress") for p in metadata.get("permissions", []) 
                                         if p.get("role") == "owner"), "Unknown"),
                            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        # Log the deletion
                        log_message = {
                            "file_id": file_id,
                            "file_name": change_details["file_name"],
                            "owner": change_details["owner"],
                            "details": change_details,
                            "timestamp": change_details["timestamp"]
                        }
                        log_event(log_message)
                        
                        try:
                            send_email_alert(file_id, change_details)
                        except Exception as e:
                            log_event(f"Failed to send email alert: {e}")
                        
                        # Remove the deleted file from Pinecone
                        try:
                            index.delete(ids=[file_id])
                            log_event(f"Removed deleted file {file_id} from Pinecone")
                        except Exception as e:
                            log_event(f"Error removing deleted file from Pinecone: {e}")
                
            except Exception as e:
                log_event(f"Error checking for deleted files: {e}")
            
            # Process current files
            for file in current_files.values():
                process_drive_file(file, service)
                
        except Exception as error:
            log_event(f'An error occurred: {error}')
            
    except Exception as e:
        log_event(f"Error in main: {e}")
    finally:
        log_event("Monitoring complete.")

def test_logging():
    """Test function to generate a log entry."""
    test_data = {
        "file_id": "test123",
        "file_name": "test_file.txt",
        "owner": "test@example.com",
        "details": {
            "type": "test_change",
            "changes": ["test change 1", "test change 2"]
        },
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # log_event now handles both logging and direct file writing
    log_event(test_data)
    print("Test log sent")

# Add a test call after the main function
if __name__ == "__main__":
    # Call the main function if no arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--test-log":
        test_logging()
    else:
        main()
