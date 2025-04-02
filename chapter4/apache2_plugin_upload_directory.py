import re
import json
from datetime import datetime

def parse_log_file(file_path):
    log_pattern = re.compile(
        r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) \d+ ".*?" ".*?"$'
    )
    entries = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            match = log_pattern.match(line)
            if not match:
                continue  # Skip malformed lines
            
            # Extract relevant components
            timestamp_str = match.group(2)
            path = match.group(4)
            status = match.group(6)
            
            # Apply path filter
            if "/uploads/sp-client-document-manager/3/project-plan.php" not in path:
                continue
            
            # Clean path (remove HTTP version if present)
            clean_path = path.replace("HTTP/1.1", "").strip()
            
            # Parse and format timestamp
            try:
                log_date = datetime.strptime(
                    timestamp_str, 
                    '%d/%b/%Y:%H:%M:%S %z'
                )
                formatted_time = log_date.strftime('%Y/%m/%d %H:%M:%S')
            except ValueError:
                continue  # Skip lines with invalid timestamps
            
            entries.append({
                "time": formatted_time,
                "status": status,
                "path_only": clean_path
            })
    
    # Sort entries chronologically
    entries.sort(key=lambda x: datetime.strptime(x['time'], '%Y/%m/%d %H:%M:%S'))
    
    return entries

# Process the log file and save results
results = parse_log_file("ch4_web_access_events.log")

with open("result_query2.json", "w") as f:
    json.dump(results, f, indent=2)

print("JSON file 'result_query2.json' created successfully.")