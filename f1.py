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
import dropbox  # New import for Dropbox

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
model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

# **🔹 SSL Fix**
os.environ["SSL_CERT_FILE"] = certifi.where()
ssl_context = ssl.create_default_context(cafile=certifi.where())

# Configure proxy if needed - comment out if proxy is not needed
# os.environ['HTTP_PROXY'] = 'http://localhost:8001'  # Update with your actual proxy address
# os.environ['HTTPS_PROXY'] = 'http://localhost:8001'  # Use HTTP protocol for HTTPS requests


# **🔹 Configuration**
# Google Drive Configuration
SCOPES = ["https://www.googleapis.com/auth/drive"]
TOKEN_FILE = "token2.json"  # Ensure this is properly configured
CREDENTIALS_FILE = "credentials2.json"  # Replace with your actual credentials file

# Dropbox Configuration
DROPBOX_ACCESS_TOKEN = "sl.u.AFr599Yh8EYYJi2ovg6Cl1DEYdp1o-YrsYUrPhytEbS7CiAg5-kdmBVmIV3Pw8hBhc6QS7g5dqUbZdz4mB5gwIp5utVuRKr0fcFYgBMOABxhpv9fNcPocWf4rz31cIJT4KM9zpqRa_Sc9eJtcINK2yLaaax-bXm2_k8EqEX2Vwbsi6bor7_DsthjoyVKKet80n24KJjOqaNAtksZFtIgODfaunFvaeN4oMGXeBu_1ZgzCU0h0C4G4cSj_mGhOmdAQn2ka2NWTNaYvZrolsAxCimQke_iioGQVXS6hBD6zvtphKwsm4ltHkTsB4G6zFrt7TDNXYcZWhz1IbzjFMrqVUZJE5YNiH5YeavDnnRqMQ0Se7bLPwsx6Al1ukswPgS_7ikf_wBu744yuvjmjNRQF3hFXEF1gkS43aNwU8_rihWqqq_H5QM515RURqIWTugsmFyp8IX10YA2UDGlT58voUaHacM9Bc2BgaZVpBVbbGd1jk8jz07sNBkrvGE_JVTbMlG7RIGZJrTOZbvaHns25Hs9jkICArb8iVxLB8Vtz3ZQG0G0EW7PLRUMca5gRwSxWhaWF_4IIRfN9J4xyHQcUHAshQqFtFQhPFjP7uJVTOO2ujU3rzQVANkaeoed6LGTdukT2sOP5qlGui9E5nPp55RsGILmuDygzG_ApPDFbzaypJE7b7cQHMH-ZL71YdHcXo5l8dFsKhGRxyvjnLNqhVc3gnhyobRjFeocjsehRuG8_6mPbZgBQQz0jnaKLaFBzDr9t3BaxDdafYD-8-oP12e8-Pkj4mUVShiFmLCkOf-6zvb1BgYAEWFcmNmirw_LRpV1UYSMvLAMsAm0GAidC6r_dauSIsaTgrS5xj9dDFa7G3rRzwFYeeMywC4WW2qIB0jdLUF-jkOrDgVxn22ur8APlueEC2lfUlRX5upgWn3QA5Y-Dw2Pbl9PmAU6_5pGPwIyKY36jSinXoWdTgVDTFu_U5ucCOIF13FQX7vW-1iVRQAzO4az9I2whjWH7g7ftpDcGsHG-U2gMycPtPvG91Zq4NYNsw17ezsv8RWOlZeMhHuEu1cHmg0SG9OcOVqor1oH4a4KeZq9kckNW_9g1uN18VsGBKggpwPnLMSyX3bKvEYegT5i5VTvK8-lZcqkqTQjY-RpQEfcI3GCmyauKv8Vc4-HTxFEA_exoztwAur6UMgXhw5m1S6Sk5FTtr1aL-z4aG6mmbRRdABVEqoPCUXcjyTiD27ccebP-JiTNKFGF1GavNwHSA3zUiIm1WLUOIuXvqtHDKKbeHLQ68E6EUMqMQIPO8U6vfh4f4qmgA0Rf7yxdyMuqfAltaNR619Ys1L1vt_irdRA-YmtDIG2Sc4rDN9M_t4udnbIYrV9WlF4A1YEyFCYb9nIIaevQ-V_RqRhcPEi5epfn6IBVlt47w1y"

# Other Configuration
PINECONE_API_KEY = "pcsk_3xs3j4_RqkwrJt6UHbym2YJM16TvT5yunfKtSbeJt3HnJZrcB1nwhJD9q9Gsv1t2ZoYe8k"  # 🔐 Replace with your actual Pinecone API key
GDRIVE_INDEX_NAME = "drive-metadata-index"
DROPBOX_INDEX_NAME = "cloud-metadata-index3"
LOG_FILE = "syslog_client.log"  # Log file for monitoring
ALERTS_FILE = "alerts_log.json"  # Store previously alerted changes
DROPBOX_ALERTS_FILE = "dropbox_alerts_log.json"  # Store Dropbox alerts

# Slack Config
SLACK_GDRIVE_CHANNEL = "#eventlog"
SLACK_DROPBOX_CHANNEL = "#all-sfs"
SLACK_TOKEN = "xoxb-8649015195078-8653518511733-s7bOWL8qcH2xy6hDW5Iwe0VR"

# **🔹 Initialize Services**
# Initialize Pinecone for Google Drive
pc = Pinecone(api_key=PINECONE_API_KEY)
if GDRIVE_INDEX_NAME not in pc.list_indexes().names():
    pc.create_index(
        name=GDRIVE_INDEX_NAME,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
gdrive_index = pc.Index(GDRIVE_INDEX_NAME)

# Initialize Pinecone for Dropbox
if DROPBOX_INDEX_NAME not in pc.list_indexes().names():
    pc.create_index(
        name=DROPBOX_INDEX_NAME,
        dimension=384,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )
dropbox_index = pc.Index(DROPBOX_INDEX_NAME)

# Initialize Dropbox client
dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)


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
        fetched_vectors = gdrive_index.fetch(ids=[file_id])
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
                "source": "google_drive",  # Mark the source as Google Drive
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
                "source": "google_drive",  # Mark the source as Google Drive
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

            gdrive_index.upsert(vectors=[{
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

        # Identify the source (Google Drive or Dropbox)
        source = change_details.get("source", "google_drive")
        source_display = "Google Drive" if source == "google_drive" else "Dropbox"

        # Create a more detailed message
        if change_details["type"] == "new_file":
            subject = f"New {source_display} file detected: {change_details['file_name']}"
            body = [
                f"New {source_display} file '{change_details['file_name']}' was created by {modifier_text}",
                f"Owner: {change_details['owner']}",
                "\nInitial permissions:"
            ]
            for perm in change_details.get("permissions", []):
                body.append(f"- {perm.get('displayName', 'Unknown')} ({perm.get('emailAddress')}): {perm.get('role')}")
        elif change_details["type"] == "file_deleted":
            subject = f"{source_display} file deleted: {change_details['file_name']}"
            body = [
                f"{source_display} file '{change_details['file_name']}' was deleted",
                f"Previous owner: {change_details['owner']}",
                f"File ID: {file_id}"
            ]
            if modifier_text != "Unknown":
                body.insert(1, f"Deleted by: {modifier_text}")
        else:
            subject = f"Changes detected in {source_display} file: {change_details['file_name']}"
            body = [f"The following changes were detected in {source_display} file '{change_details['file_name']}':"]

            for change in change_details.get("changes", []):
                change_modifier = change.get("modified_by", {})
                change_modifier_text = f"{change_modifier.get('name', 'Unknown')}"
                if change_modifier.get('email') and change_modifier.get('email') != "Unknown":
                    change_modifier_text += f" ({change_modifier.get('email')})"

                if change["type"] == "name_change":
                    body.append(f"- File renamed from '{change['old']}' to '{change['new']}' by {change_modifier_text}")
                elif change["type"] == "permission_added":
                    body.append(
                        f"- {change_modifier_text} added {change['role']} permission for {change['user_name']} ({change['user']})")
                elif change["type"] == "permission_removed":
                    body.append(
                        f"- {change_modifier_text} removed permission for {change['user_name']} ({change['user']})")
                elif change["type"] == "permission_changed":
                    body.append(
                        f"- {change_modifier_text} changed {change['user_name']} ({change['user']})'s role from {change['old_role']} to {change['new_role']}")

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

        # Send to Slack - use different channels based on source
        channel = SLACK_GDRIVE_CHANNEL if source == "google_drive" else SLACK_DROPBOX_CHANNEL
        slack_notify.send_slack_message(
            SLACK_TOKEN,
            channel,
            slack_message
        )

    except Exception as e:
        log_event(f"Failed to prepare email alert: {str(e)}")


def test_logging():
    """Test function for logging functionality."""
    log_event("Testing logging functionality")
    log_event({
        "test": "Sample JSON log entry",
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    print("Logging test completed")


def main():
    """Main function to monitor both Google Drive and Dropbox."""
    try:
        # First monitor Google Drive
        monitor_google_drive()

        # Then monitor Dropbox
        monitor_dropbox()

    except Exception as e:
        log_event(f"Error in main monitoring function: {e}")
    finally:
        log_event("All monitoring completed.")


def monitor_google_drive():
    """Shows basic usage of the Drive v3 API."""
    try:
        creds = None
        if os.path.exists("token2.json"):
            creds = Credentials.from_authorized_user_file("token2.json", SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file("credentials2.json", SCOPES)
                creds = flow.run_local_server(port=52166)
            with open("token2.json", "w") as token:
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
                query_response = gdrive_index.query(
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
                            "source": "google_drive",  # Mark the source as Google Drive
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
                            gdrive_index.delete(ids=[file_id])
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
        log_event(f"Error in Google Drive monitoring: {e}")
    finally:
        log_event("Google Drive monitoring complete.")


# === Dropbox Functions ===

def load_dropbox_alerts():
    """Load previously sent Dropbox alerts to avoid duplicate notifications."""
    if os.path.exists(DROPBOX_ALERTS_FILE):
        with open(DROPBOX_ALERTS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_dropbox_alerts(alerts):
    """Save the updated Dropbox alerts log."""
    with open(DROPBOX_ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def get_existing_dropbox_metadata(file_id):
    """Fetch stored Dropbox metadata from Pinecone."""
    try:
        result = dropbox_index.fetch(ids=[file_id])
        if file_id in result.vectors:
            return result.vectors[file_id].metadata
        return {}
    except Exception as e:
        log_event(f"Error fetching Dropbox metadata from Pinecone: {e}")
        return {}


def get_dropbox_files():
    """Fetch all files from Dropbox with their metadata."""
    try:
        result = dbx.files_list_folder("", recursive=True)
        files = []

        # Process initial batch
        for entry in result.entries:
            if isinstance(entry, dropbox.files.FileMetadata):
                files.append({
                    "id": entry.id,
                    "name": entry.name,
                    "path": entry.path_display,
                    "size": entry.size,
                    "client_modified": str(entry.client_modified),
                    "server_modified": str(entry.server_modified)
                })

        # Handle pagination
        while result.has_more:
            result = dbx.files_list_folder_continue(result.cursor)
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    files.append({
                        "id": entry.id,
                        "name": entry.name,
                        "path": entry.path_display,
                        "size": entry.size,
                        "client_modified": str(entry.client_modified),
                        "server_modified": str(entry.server_modified)
                    })

        log_event(f"Successfully fetched {len(files)} files from Dropbox")
        return files

    except dropbox.exceptions.ApiError as e:
        log_event(f"Dropbox API error: {e}")
        return []
    except Exception as e:
        log_event(f"Error fetching Dropbox files: {e}")
        return []


def detect_dropbox_change(file_id, new_metadata):
    """Detect and alert on Dropbox metadata changes."""
    try:
        old_metadata = get_existing_dropbox_metadata(file_id)
        alerts_log = load_dropbox_alerts()

        if old_metadata != new_metadata:
            change_details = {
                "file_id": file_id,
                "file_name": new_metadata.get("name", "Unknown"),
                "path": new_metadata.get("path", ""),
                "timestamp": str(datetime.datetime.now()),
                "source": "dropbox",  # Mark the source as Dropbox
                "changes": {
                    key: {"old": old_metadata.get(key), "new": new_metadata.get(key)}
                    for key in new_metadata if old_metadata.get(key) != new_metadata.get(key)
                }
            }

            if file_id not in alerts_log or alerts_log[file_id] != change_details["changes"]:
                send_dropbox_alert(file_id, change_details)

                # Update Pinecone with new metadata
                try:
                    vector = model.encode(json.dumps(new_metadata)).tolist()
                    dropbox_index.upsert(vectors=[{
                        "id": file_id,
                        "values": vector,
                        "metadata": new_metadata
                    }])
                except Exception as e:
                    log_event(f"Error updating Pinecone with Dropbox metadata: {e}")

                alerts_log[file_id] = change_details["changes"]
                save_dropbox_alerts(alerts_log)
                log_event(f"Dropbox change detected and alerts sent for {file_id}")
                return change_details

        return None
    except Exception as e:
        log_event(f"Error in detect_dropbox_change: {e}")
        return None


def send_dropbox_alert(file_id, change_details):
    """Send rich formatted alerts for Dropbox changes."""
    try:
        file_name = change_details.get("file_name", "Unknown")
        changes = change_details.get("changes", {})
        path = change_details.get("path", "")

        # Format email content
        subject = f"Dropbox Change: {file_name}"
        body = [
            f"Changes detected in Dropbox file '{file_name}':",
            f"Path: {path}",
            f"File ID: {file_id}",
            "\nChanges:"
        ]

        for key, change in changes.items():
            body.append(f"- {key}: Changed from '{change.get('old')}' to '{change.get('new')}'")

        body.append(f"\nTimestamp: {change_details.get('timestamp')}")

        # Log the email content
        email_content = f"Would send email:\nSubject: {subject}\nBody:\n" + "\n".join(body)
        log_event(email_content)

        # Format Slack message
        slack_blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Dropbox Change: {file_name}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*File ID:*\n`{file_id}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Path:*\n{path}"
                    }
                ]
            }
        ]

        if changes:
            changes_text = "*Changes:*\n"
            for key, change in changes.items():
                changes_text += f"- *{key}:*\n  Old: `{change.get('old', 'None')}`\n  New: `{change.get('new', 'None')}`\n"

            slack_blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": changes_text}
            })

        slack_blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View in Dropbox",
                        "emoji": True
                    },
                    "url": f"https://www.dropbox.com/home{path}"
                }
            ]
        })

        # Send to Slack using the simple function
        slack_message = f"*{subject}*\n" + "\n".join(body)
        slack_notify.send_slack_message(
            SLACK_TOKEN,
            SLACK_DROPBOX_CHANNEL,
            slack_message
        )
        log_event(f"Dropbox Slack alert sent for {file_id}")

    except Exception as e:
        log_event(f"Failed to send Dropbox alert: {e}")


def monitor_dropbox():
    """Main function to monitor Dropbox files."""
    try:
        log_event("Real-time Dropbox Metadata Monitoring Started...")

        # Get current Dropbox files
        dropbox_files = get_dropbox_files()

        # Get previously stored file IDs from Pinecone
        try:
            # Query Pinecone to get all stored Dropbox file IDs
            query_response = dropbox_index.query(
                vector=[0.1] * 384,  # Dummy vector
                top_k=1000,
                include_metadata=True
            )

            # Build a map of stored files
            stored_files = {}
            for match in query_response.matches:
                if match.id and match.metadata:
                    stored_files[match.id] = match.metadata

            # Build a map of current files
            current_files = {file['id']: file for file in dropbox_files}

            # Check for deleted files (files that were in storage but not in current files)
            for file_id, metadata in stored_files.items():
                if file_id not in current_files:
                    # File was deleted
                    change_details = {
                        "file_id": file_id,
                        "file_name": metadata.get("name", "Unknown"),
                        "path": metadata.get("path", ""),
                        "timestamp": str(datetime.datetime.now()),
                        "source": "dropbox",  # Mark the source as Dropbox
                        "changes": {"status": {"old": "present", "new": "deleted"}}
                    }

                    send_dropbox_alert(file_id, change_details)

                    # Remove the deleted file from Pinecone
                    try:
                        dropbox_index.delete(ids=[file_id])
                        log_event(f"Removed deleted Dropbox file {file_id} from Pinecone")
                    except Exception as e:
                        log_event(f"Error removing deleted Dropbox file from Pinecone: {e}")

            # Process current files for changes
            for file in dropbox_files:
                detect_dropbox_change(file["id"], file)

        except Exception as e:
            log_event(f"Error in Dropbox monitoring: {e}")

        log_event("Dropbox monitoring completed.")

    except Exception as e:
        log_event(f"Critical error in Dropbox monitoring: {e}")


# Add a test call after the main function
if __name__ == "__main__":
    # Call the main function if no arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--test-log":
        test_logging()
    else:
        main()
