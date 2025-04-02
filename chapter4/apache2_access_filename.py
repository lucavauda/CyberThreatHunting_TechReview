import re
import json
from collections import Counter

# Define the regex to parse the log line.
log_pattern = re.compile(
    r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) \d+ ".*?" ".*?"$'
)
# This pattern captures:
#   Group 1: IP
#   Group 2: timestamp
#   Group 3: HTTP method
#   Group 4: path
#   Group 5: protocol (e.g., HTTP/1.1)
#   Group 6: status

# Regex for extracting the filename from the path (similar to the Humio regex).
filename_pattern = re.compile(r'(?P<filename>\w+\.\w+)')

# A counter to group and count occurrences of each filename.
filename_counter = Counter()

# Open and process the log file.
with open("ch4_web_access_events.log", "r") as file:
    for line in file:
        line = line.strip()
        match = log_pattern.match(line)
        if match:
            ip, timestamp, method, path, protocol, status = match.groups()
            # Emulate the replace command:
            # In the Humio query, this step removes the substring "HTTP/1.1" from the field 'path'
            # and stores the result in 'path_only'. In our parsed data, 'path' comes directly from the log,
            # but we simulate the replacement if needed.
            path_only = re.sub(r"HTTP\/1\.1", "", path)
            
            # Extract the filename using the provided regex.
            filename_match = filename_pattern.search(path_only)
            if filename_match:
                filename = filename_match.group("filename")
                filename_counter[filename] += 1

# Sort the results by count in descending order.
sorted_results = sorted(filename_counter.items(), key=lambda item: item[1], reverse=True)

# Format the result as a list of dictionaries.
result = [{"filename": fname, "count": count} for fname, count in sorted_results]

# Write the result to a JSON file.
with open("result_query1.json", "w") as json_file:
    json.dump(result, json_file, indent=4)

print("JSON file 'result_query1.json' created successfully.")
