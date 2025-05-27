# ELEVATE-TASK-2
🧪 Objective
To analyze a suspected phishing email by examining its headers and embedded URLs using publicly available tools.

🛠️ Tools Used
Tool	Purpose	Link
MXToolbox	Email header analysis	https://mxtoolbox.com
VirusTotal	URL reputation and threat scan	https://www.virustotal.com

📧 Sample Email Details
Subject: Unusual Sign-In Attempt Detected
From: Microsoft Security <alerts@m1crosoft-support.com>
Suspicious URL: http://secure-login.microsoft-verification.com/login
Date Received: May 27, 2025

🔍 Analysis Steps
🔹 1. Email Header Analysis – MXToolbox
Steps Followed:
Extracted full email headers from the raw message.
Navigated to MXToolbox Email Header Analyzer.
Pasted the raw headers into the input box and submitted.

Key Findings:
Sender domain spoofed: m1crosoft-support.com closely mimics Microsoft.
SPF/DKIM Failures: No valid DKIM or SPF alignment.
Received headers indicate suspicious origin IP (192.168.10.11), not from Microsoft servers.

🔹 2. URL Analysis – VirusTotal
Steps Followed:
Copied the suspicious link: http://secure-login.microsoft-verification.com/login
Pasted it into VirusTotal
Reviewed results from over 70+ AV and security engines.

Key Findings:
URL was flagged by multiple engines as phishing.
Domain was newly registered, with low trust score.
Some engines identified it as hosting a fake Microsoft login page.

✅ Conclusion
The email shows multiple red flags confirming it is phishing:
Spoofed sender domain
Suspicious URL
No authentication records (SPF/DKIM)
Detected by VirusTotal as malicious

🛡️ Recommendations
Report the sender and domain to your mail provider.
Add the sender domain to your blocklist.
Educate users on how to inspect URLs before clicking.
Implement DMARC enforcement on your domain.
