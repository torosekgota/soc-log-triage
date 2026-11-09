"""
Lightweight File Integrity Monitor (FIM).
Calculates SHA-256 hashes for a directory, saves a baseline, and compares against it.
"""
import os
import hashlib
import json

def calculate_hash(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read in chunks to save RAM on low-spec machines
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def create_baseline(directory, output_file="baseline.json"):
    """Scans a directory and saves file hashes to a baseline JSON file."""
    baseline = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            baseline[filepath] = calculate_hash(filepath)
    
    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=4)
    
    return baseline

def audit_directory(directory, baseline_file="baseline.json"):
    """Compares current directory state against the baseline."""
    if not os.path.exists(baseline_file):
        return {"error": "Baseline file not found. Run 'baseline' first."}
        
    with open(baseline_file, "r") as f:
        baseline = json.load(f)
        
    current_state = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            current_state[filepath] = calculate_hash(filepath)

    results = {
        "modified": [],
        "created": [],
        "deleted": []
    }

    # Check for modified and created files
    for filepath, curr_hash in current_state.items():
        if filepath not in baseline:
            results["created"].append(filepath)
        elif baseline[filepath] != curr_hash:
            results["modified"].append(filepath)

    # Check for deleted files
    for filepath in baseline:
        if filepath not in current_state:
            results["deleted"].append(filepath)

    return results