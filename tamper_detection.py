import hashlib
import json
import os
import shutil
from datetime import datetime

LOG_FILE = "secure_logs.json"
BACKUP_FILE = "secure_logs_backup.json"
TAMPER_LOG = "tamper_detection_report.txt"

# ---------------------------
# HASH FUNCTION
# ---------------------------
def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ---------------------------
# LOAD LOGS
# ---------------------------
def load_logs(filename=LOG_FILE):
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
        return json.load(f)

# ---------------------------
# SAVE LOGS
# ---------------------------
def save_logs(logs, filename=LOG_FILE):
    with open(filename, "w") as f:
        json.dump(logs, f, indent=4)

# ---------------------------
# CREATE BACKUP
# ---------------------------
def create_backup():
    """Create a backup of the current log file"""
    if os.path.exists(LOG_FILE):
        shutil.copy2(LOG_FILE, BACKUP_FILE)
        print(f"✅ Backup created at {BACKUP_FILE}")
        return True
    else:
        print("⚠️ No log file to backup")
        return False

# ---------------------------
# RESTORE FROM BACKUP
# ---------------------------
def restore_from_backup():
    """Restore logs from backup file"""
    if os.path.exists(BACKUP_FILE):
        shutil.copy2(BACKUP_FILE, LOG_FILE)
        print(f"✅ Logs restored from backup")
        return True
    else:
        print("⚠️ No backup file found")
        return False

# ---------------------------
# ADD LOG ENTRY
# ---------------------------
def add_log(event_type, description):
    logs = load_logs()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    previous_hash = logs[-1]["current_hash"] if logs else "0"

    data_to_hash = timestamp + event_type + description + previous_hash
    current_hash = generate_hash(data_to_hash)

    log_entry = {
        "index": len(logs) + 1,
        "timestamp": timestamp,
        "event_type": event_type,
        "description": description,
        "previous_hash": previous_hash,
        "current_hash": current_hash
    }

    logs.append(log_entry)
    save_logs(logs)

    print("\n✅ Log added successfully (tamper-proof)")

# ---------------------------
# COMPARE LOGS
# ---------------------------
def compare_logs(logs1, logs2):
    """Compare two log files and return differences"""
    differences = []

    # Compare lengths
    if len(logs1) != len(logs2):
        differences.append(f"Different number of entries: {len(logs1)} vs {len(logs2)}")

    # Compare each entry
    min_length = min(len(logs1), len(logs2))
    for i in range(min_length):
        log1 = logs1[i]
        log2 = logs2[i]

        entry_diff = {}

        # Compare each field
        for key in log1.keys():
            if key in log2 and log1[key] != log2[key]:
                entry_diff[key] = {
                    "current": log1[key],
                    "backup": log2[key]
                }

        if entry_diff:
            differences.append({
                "index": i + 1,
                "differences": entry_diff
            })

    return differences

# ---------------------------
# VERIFY LOGS WITH DETAILS
# ---------------------------
def verify_logs_detailed():
    """Enhanced verification with detailed tampering information"""
    logs = load_logs()
    backup_logs = load_logs(BACKUP_FILE) if os.path.exists(BACKUP_FILE) else None

    if not logs:
        print("⚠️ No logs found.")
        return

    tampering_detected = False
    tamper_report = []

    print("\n" + "="*60)
    print("🔍 SECURITY VERIFICATION REPORT")
    print("="*60)

    # Check 1: Hash integrity for current logs
    print("\n📋 CHECKING HASH INTEGRITY...")
    for i in range(len(logs)):
        curr = logs[i]

        recalculated_hash = generate_hash(
            curr["timestamp"] +
            curr["event_type"] +
            curr["description"] +
            curr["previous_hash"]
        )

        if curr["current_hash"] != recalculated_hash:
            tampering_detected = True
            issue = {
                "index": curr["index"],
                "type": "Hash Mismatch",
                "details": f"Hash at index {curr['index']} does not match calculated hash",
                "current_hash": curr["current_hash"],
                "calculated_hash": recalculated_hash
            }
            tamper_report.append(issue)
            print(f"   ❌ TAMPERING at Index {curr['index']}: Hash mismatch")

    # Check 2: Chain integrity
    print("\n📋 CHECKING CHAIN INTEGRITY...")
    for i in range(1, len(logs)):
        prev = logs[i - 1]
        curr = logs[i]

        if curr["previous_hash"] != prev["current_hash"]:
            tampering_detected = True
            issue = {
                "index": curr["index"],
                "type": "Chain Broken",
                "details": f"Previous hash at index {curr['index']} doesn't match previous entry's hash",
                "expected": prev["current_hash"],
                "found": curr["previous_hash"]
            }
            tamper_report.append(issue)
            print(f"   ❌ TAMPERING at Index {curr['index']}: Chain broken")

    # Compare with backup if available
    if backup_logs:
        print("\n📋 COMPARING WITH BACKUP...")
        differences = compare_logs(logs, backup_logs)

        if differences:
            tampering_detected = True
            for diff in differences:
                issue = {
                    "index": diff["index"],
                    "type": "Backup Mismatch",
                    "details": f"Entry {diff['index']} differs from backup",
                    "differences": diff["differences"]
                }
                tamper_report.append(issue)
                print(f"   ❌ TAMPERING at Index {diff['index']}: Different from backup")

                # Show detailed differences
                for field, values in diff["differences"].items():
                    print(f"      - {field}: '{values['current']}' vs '{values['backup']}'")

    # Summary
    print("\n" + "="*60)
    if not tampering_detected:
        print("✅ ALL LOGS ARE INTACT AND SECURE!")
    else:
        print(f"⚠️ TAMPERING DETECTED! Found {len(tamper_report)} issue(s):")
        for i, issue in enumerate(tamper_report, 1):
            print(f"\n   {i}. Index {issue['index']} - {issue['type']}")
            print(f"      {issue['details']}")

        # Save detailed report
        save_tamper_report(tamper_report)

    print("="*60)
    return tampering_detected, tamper_report

# ---------------------------
# SAVE TAMPER REPORT
# ---------------------------
def save_tamper_report(tamper_report):
    """Save detailed tampering report to file"""
    with open(TAMPER_LOG, "w") as f:
        f.write(f"TAMPER DETECTION REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*60 + "\n\n")

        for i, issue in enumerate(tamper_report, 1):
            f.write(f"Issue {i}:\n")
            f.write(f"  Index: {issue['index']}\n")
            f.write(f"  Type: {issue['type']}\n")
            f.write(f"  Details: {issue['details']}\n")

            if 'differences' in issue:
                f.write(f"  Field Differences:\n")
                for field, values in issue['differences'].items():
                    f.write(f"    - {field}:\n")
                    f.write(f"        Current: {values['current']}\n")
                    f.write(f"        Backup:  {values['backup']}\n")

            f.write("\n")

    print(f"📄 Detailed tamper report saved to: {TAMPER_LOG}")

# ---------------------------
# VIEW LOGS
# ---------------------------
def view_logs():
    logs = load_logs()

    if not logs:
        print("⚠️ No logs available.")
        return

    print("\n📜 Secure Logs:\n")
    for log in logs:
        print(f"Index       : {log['index']}")
        print(f"Timestamp   : {log['timestamp']}")
        print(f"Event Type  : {log['event_type']}")
        print(f"Description : {log['description']}")
        print(f"Prev Hash   : {log['previous_hash'][:20]}...")
        print(f"Hash        : {log['current_hash'][:20]}...")
        print("-" * 50)

# ---------------------------
# VIEW BACKUP LOGS
# ---------------------------
def view_backup_logs():
    backup_logs = load_logs(BACKUP_FILE)

    if not backup_logs:
        print("⚠️ No backup logs available.")
        return

    print("\n📜 Backup Logs:\n")
    for log in backup_logs:
        print(f"Index       : {log['index']}")
        print(f"Timestamp   : {log['timestamp']}")
        print(f"Event Type  : {log['event_type']}")
        print(f"Description : {log['description']}")
        print(f"Prev Hash   : {log['previous_hash'][:20]}...")
        print(f"Hash        : {log['current_hash'][:20]}...")
        print("-" * 50)

# ---------------------------
# MAIN MENU
# ---------------------------
def main():
    while True:
        print("\n==== TAMPER-EVIDENT LOG SYSTEM ====")
        print("1. Add Log Entry")
        print("2. View Current Logs")
        print("3. Verify Logs Integrity (Detailed)")
        print("4. Create Backup")
        print("5. View Backup Logs")
        print("6. Compare with Backup")
        print("7. Restore from Backup")
        print("8. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            event = input("Enter event type (e.g., LOGIN, FILE_ACCESS): ")
            desc = input("Enter description: ")
            add_log(event, desc)

        elif choice == "2":
            view_logs()

        elif choice == "3":
            verify_logs_detailed()

        elif choice == "4":
            create_backup()

        elif choice == "5":
            view_backup_logs()

        elif choice == "6":
            current_logs = load_logs()
            backup_logs = load_logs(BACKUP_FILE)

            if not backup_logs:
                print("⚠️ No backup found. Please create a backup first.")
            else:
                differences = compare_logs(current_logs, backup_logs)
                if differences:
                    print("\n🔍 Differences found between current and backup logs:\n")
                    for diff in differences:
                        print(f"Entry {diff['index']} differences:")
                        for field, values in diff["differences"].items():
                            print(f"  - {field}:")
                            print(f"      Current: {values['current']}")
                            print(f"      Backup : {values['backup']}")
                        print()
                else:
                    print("\n✅ No differences found. Logs match backup!")

        elif choice == "7":
            confirm = input("⚠️ This will overwrite current logs. Are you sure? (y/n): ")
            if confirm.lower() == 'y':
                restore_from_backup()
            else:
                print("Restore cancelled.")

        elif choice == "8":
            print("Exiting...")
            break

        else:
            print("❌ Invalid choice. Try again.")

# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    main()
import hashlib
import json
import os
import shutil
from datetime import datetime

LOG_FILE = "secure_logs.json"
BACKUP_FILE = "secure_logs_backup.json"
TAMPER_LOG = "tamper_detection_report.txt"

# ---------------------------
# HASH FUNCTION
# ---------------------------
def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# ---------------------------
# LOAD LOGS
# ---------------------------
def load_logs(filename=LOG_FILE):
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
        return json.load(f)

# ---------------------------
# SAVE LOGS
# ---------------------------
def save_logs(logs, filename=LOG_FILE):
    with open(filename, "w") as f:
        json.dump(logs, f, indent=4)

# ---------------------------
# CREATE BACKUP
# ---------------------------
def create_backup():
    """Create a backup of the current log file"""
    if os.path.exists(LOG_FILE):
        shutil.copy2(LOG_FILE, BACKUP_FILE)
        print(f"✅ Backup created at {BACKUP_FILE}")
        return True
    else:
        print("⚠️ No log file to backup")
        return False

# ---------------------------
# RESTORE FROM BACKUP
# ---------------------------
def restore_from_backup():
    """Restore logs from backup file"""
    if os.path.exists(BACKUP_FILE):
        shutil.copy2(BACKUP_FILE, LOG_FILE)
        print(f"✅ Logs restored from backup")
        return True
    else:
        print("⚠️ No backup file found")
        return False

# ---------------------------
# ADD LOG ENTRY
# ---------------------------
def add_log(event_type, description):
    logs = load_logs()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    previous_hash = logs[-1]["current_hash"] if logs else "0"

    data_to_hash = timestamp + event_type + description + previous_hash
    current_hash = generate_hash(data_to_hash)

    log_entry = {
        "index": len(logs) + 1,
        "timestamp": timestamp,
        "event_type": event_type,
        "description": description,
        "previous_hash": previous_hash,
        "current_hash": current_hash
    }

    logs.append(log_entry)
    save_logs(logs)

    print("\n✅ Log added successfully (tamper-proof)")

# ---------------------------
# COMPARE LOGS
# ---------------------------
def compare_logs(logs1, logs2):
    """Compare two log files and return differences"""
    differences = []

    # Check if both are empty
    if not logs1 and not logs2:
        return differences

    # Compare lengths
    if len(logs1) != len(logs2):
        differences.append({
            "index": 0,
            "type": "length_mismatch",
            "differences": {
                "total_entries": {
                    "current": len(logs1),
                    "backup": len(logs2)
                }
            }
        })

    # Compare each entry
    min_length = min(len(logs1), len(logs2))
    for i in range(min_length):
        log1 = logs1[i]
        log2 = logs2[i]

        entry_diff = {}

        # Compare each field
        for key in log1.keys():
            if key in log2 and log1[key] != log2[key]:
                entry_diff[key] = {
                    "current": log1[key],
                    "backup": log2[key]
                }

        if entry_diff:
            differences.append({
                "index": i + 1,
                "type": "field_mismatch",
                "differences": entry_diff
            })

    return differences

# ---------------------------
# VERIFY LOGS WITH DETAILS
# ---------------------------
def verify_logs_detailed():
    """Enhanced verification with detailed tampering information"""
    logs = load_logs()
    backup_logs = load_logs(BACKUP_FILE) if os.path.exists(BACKUP_FILE) else None

    if not logs:
        print("⚠️ No logs found.")
        return

    tampering_detected = False
    tamper_report = []

    print("\n" + "="*60)
    print("🔍 SECURITY VERIFICATION REPORT")
    print("="*60)

    # Check 1: Hash integrity for current logs
    print("\n📋 CHECKING HASH INTEGRITY...")
    for i in range(len(logs)):
        curr = logs[i]

        recalculated_hash = generate_hash(
            curr["timestamp"] +
            curr["event_type"] +
            curr["description"] +
            curr["previous_hash"]
        )

        if curr["current_hash"] != recalculated_hash:
            tampering_detected = True
            issue = {
                "index": curr["index"],
                "type": "Hash Mismatch",
                "details": f"Hash at index {curr['index']} does not match calculated hash",
                "current_hash": curr["current_hash"],
                "calculated_hash": recalculated_hash
            }
            tamper_report.append(issue)
            print(f"   ❌ TAMPERING at Index {curr['index']}: Hash mismatch")

    # Check 2: Chain integrity
    print("\n📋 CHECKING CHAIN INTEGRITY...")
    for i in range(1, len(logs)):
        prev = logs[i - 1]
        curr = logs[i]

        if curr["previous_hash"] != prev["current_hash"]:
            tampering_detected = True
            issue = {
                "index": curr["index"],
                "type": "Chain Broken",
                "details": f"Previous hash at index {curr['index']} doesn't match previous entry's hash",
                "expected": prev["current_hash"],
                "found": curr["previous_hash"]
            }
            tamper_report.append(issue)
            print(f"   ❌ TAMPERING at Index {curr['index']}: Chain broken")

    # Compare with backup if available
    if backup_logs:
        print("\n📋 COMPARING WITH BACKUP...")
        differences = compare_logs(logs, backup_logs)

        if differences:
            tampering_detected = True
            for diff in differences:
                # Handle length mismatch
                if diff.get("type") == "length_mismatch":
                    issue = {
                        "index": 0,
                        "type": "Length Mismatch",
                        "details": f"Log length differs from backup",
                        "differences": diff["differences"]
                    }
                    tamper_report.append(issue)
                    print(f"   ❌ TAMPERING: Number of entries mismatch")
                    print(f"      Current: {diff['differences']['total_entries']['current']} entries")
                    print(f"      Backup: {diff['differences']['total_entries']['backup']} entries")

                # Handle field mismatches
                elif diff.get("type") == "field_mismatch":
                    issue = {
                        "index": diff["index"],
                        "type": "Backup Mismatch",
                        "details": f"Entry {diff['index']} differs from backup",
                        "differences": diff["differences"]
                    }
                    tamper_report.append(issue)
                    print(f"   ❌ TAMPERING at Index {diff['index']}: Different from backup")

                    # Show detailed differences
                    for field, values in diff["differences"].items():
                        print(f"      - {field}:")
                        print(f"          Current: {values['current']}")
                        print(f"          Backup:  {values['backup']}")

    # Summary
    print("\n" + "="*60)
    if not tampering_detected:
        print("✅ ALL LOGS ARE INTACT AND SECURE!")
    else:
        print(f"⚠️ TAMPERING DETECTED! Found {len(tamper_report)} issue(s):")
        for i, issue in enumerate(tamper_report, 1):
            print(f"\n   {i}. ", end="")
            if issue.get("index", 0) > 0:
                print(f"Index {issue['index']} - ", end="")
            print(f"{issue['type']}")
            print(f"      {issue['details']}")

        # Save detailed report
        save_tamper_report(tamper_report)

    print("="*60)
    return tampering_detected, tamper_report

# ---------------------------
# SAVE TAMPER REPORT
# ---------------------------
def save_tamper_report(tamper_report):
    """Save detailed tampering report to file"""
    with open(TAMPER_LOG, "w") as f:
        f.write(f"TAMPER DETECTION REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*60 + "\n\n")

        for i, issue in enumerate(tamper_report, 1):
            f.write(f"Issue {i}:\n")
            if issue.get("index", 0) > 0:
                f.write(f"  Index: {issue['index']}\n")
            f.write(f"  Type: {issue['type']}\n")
            f.write(f"  Details: {issue['details']}\n")

            if 'differences' in issue:
                f.write(f"  Field Differences:\n")
                for field, values in issue['differences'].items():
                    f.write(f"    - {field}:\n")
                    f.write(f"        Current: {values['current']}\n")
                    f.write(f"        Backup:  {values['backup']}\n")

            f.write("\n")

    print(f"📄 Detailed tamper report saved to: {TAMPER_LOG}")

# ---------------------------
# VIEW LOGS
# ---------------------------
def view_logs():
    logs = load_logs()

    if not logs:
        print("⚠️ No logs available.")
        return

    print("\n📜 Secure Logs:\n")
    for log in logs:
        print(f"Index       : {log['index']}")
        print(f"Timestamp   : {log['timestamp']}")
        print(f"Event Type  : {log['event_type']}")
        print(f"Description : {log['description']}")
        print(f"Prev Hash   : {log['previous_hash'][:20]}...")
        print(f"Hash        : {log['current_hash'][:20]}...")
        print("-" * 50)

# ---------------------------
# VIEW BACKUP LOGS
# ---------------------------
def view_backup_logs():
    backup_logs = load_logs(BACKUP_FILE)

    if not backup_logs:
        print("⚠️ No backup logs available.")
        return

    print("\n📜 Backup Logs:\n")
    for log in backup_logs:
        print(f"Index       : {log['index']}")
        print(f"Timestamp   : {log['timestamp']}")
        print(f"Event Type  : {log['event_type']}")
        print(f"Description : {log['description']}")
        print(f"Prev Hash   : {log['previous_hash'][:20]}...")
        print(f"Hash        : {log['current_hash'][:20]}...")
        print("-" * 50)

# ---------------------------
# MAIN MENU
# ---------------------------
def main():
    while True:
        print("\n==== TAMPER-EVIDENT LOG SYSTEM ====")
        print("1. Add Log Entry")
        print("2. View Current Logs")
        print("3. Verify Logs Integrity (Detailed)")
        print("4. Create Backup")
        print("5. View Backup Logs")
        print("6. Compare with Backup")
        print("7. Restore from Backup")
        print("8. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            event = input("Enter event type (e.g., LOGIN, FILE_ACCESS): ")
            desc = input("Enter description: ")
            add_log(event, desc)

        elif choice == "2":
            view_logs()

        elif choice == "3":
            verify_logs_detailed()

        elif choice == "4":
            create_backup()

        elif choice == "5":
            view_backup_logs()

        elif choice == "6":
            current_logs = load_logs()
            backup_logs = load_logs(BACKUP_FILE)

            if not backup_logs:
                print("⚠️ No backup found. Please create a backup first.")
            else:
                differences = compare_logs(current_logs, backup_logs)
                if differences:
                    print("\n🔍 Differences found between current and backup logs:\n")
                    for diff in differences:
                        if diff.get("type") == "length_mismatch":
                            print(f"⚠️ Length Mismatch:")
                            print(f"   Current: {diff['differences']['total_entries']['current']} entries")
                            print(f"   Backup: {diff['differences']['total_entries']['backup']} entries\n")

                        elif diff.get("type") == "field_mismatch":
                            print(f"Entry {diff['index']} differences:")
                            for field, values in diff["differences"].items():
                                print(f"  - {field}:")
                                print(f"      Current: {values['current']}")
                                print(f"      Backup : {values['backup']}")
                            print()
                else:
                    print("\n✅ No differences found. Logs match backup!")

        elif choice == "7":
            confirm = input("⚠️ This will overwrite current logs. Are you sure? (y/n): ")
            if confirm.lower() == 'y':
                restore_from_backup()
            else:
                print("Restore cancelled.")

        elif choice == "8":
            print("Exiting...")
            break

        else:
            print("❌ Invalid choice. Try again.")

# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    main()
