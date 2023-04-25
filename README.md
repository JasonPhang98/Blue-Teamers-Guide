# Blue-Teamers-Guide
Curated list of useful links and resources for study or work related to blue teaming especially for newbies in the field.

## Security Frameworks
- [MITRE framework](https://attack.mitre.org)
   - [Mitre Attack Navigator](https://mitre-attack.github.io/attack-navigator/) 
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Diamond Model](https://www.socinvestigation.com/threat-intelligence-diamond-model-of-intrusion-analysis/) 

## SIEM
### Splunk
- [What is Splunk?](https://www.guru99.com/splunk-tutorial.html)
- [How to search in Splunk](https://www.splunk.com/en_us/resources/videos/basic-search-in-splunk-enterprise.html?locale=en_us) - Video tutorial for searching in Splunk
- [Official Splunk search tutorial](https://docs.splunk.com/Documentation/Splunk/9.0.4/SearchTutorial/WelcometotheSearchTutorial) - Official Splunk documentation from searching to creating dashboards.
- [Splunk Basic Queries](https://tryhackme.com/room/splunk101) - Learn about Splunk interface. Paid room. 
- [Splunk education](https://education.splunk.com/catalog) - Use case for many types of attacks such as brute force, data exfil, etc. Also has UBA content. Free to signup for most content. 
- [Splunk TryHackMe Exercises](https://tryhackme.com/hacktivities?tab=search&page=1&free=all&order=most-popular&difficulty=all&type=all&searchTxt=splunk) - Mixture of both free and paid. Range in difficulty.
- [Splunk BOTS V1-V3](https://cyberdefenders.org/search/labs/?q=splunk)
- [Splunk UBA Demo](https://www.youtube.com/watch?v=z8NWStWFg2Y)
- [Splunk Threat Hunting Blog](https://www.splunk.com/en_us/blog/security/hunting-with-splunk-the-basics.html)

### ELK Kibana
- [What is ELK Kibana?](https://www.guru99.com/elk-stack-tutorial.html)
- [Kibana investigation exercises](https://cyberdefenders.org/search/labs/?q=elastic_1) - Free
- [Kibana threat hunting](https://cyberdefenders.org/search/labs/?q=elk) - Free
- [Try Hack Me Kibana](https://tryhackme.com/room/itsybitsy) - Paid room
- [Threat Hunting with ELK Compilation](https://www.youtube.com/playlist?list=PLeLcvrwLe184BoWZhv6Cf2kbi-bKBeDBI) - List of YouTube videos by Packt for threat hunting in ELK 

### QRadar
- [QRadar Lab and Exercise](https://cyberdefenders.org/blueteam-ctf-challenges/39#nav-questions)

### Microsoft Sentinel

## Network traffic analysis 
### Tools
- [Wireshark](https://www.wireshark.org) - Network protocol analyzer. You should know some basic queries on searching in Wireshark
- [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - Command Line interface tool for Wireshark
- [Brim](https://www.brimdata.io) - GUI based network analyzer. Can integrate together with Zeek. 
- [Network Miner](https://www.netresec.com/?page=NetworkMiner) - Able to extract info quickly from pcap such as detailed host info, files, attachments, emails and passwords
- [JA3](https://github.com/salesforce/ja3) - SSL fingerprinting for network traffic. Produces a hash for a particular network for instance Trickbot execution. Since the hash will be unique to Trickbot's execution, this makes it easier to hunt for Trickbot execution across the environment.

### Learning resources
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) - Source for pcap related to malware samples. Also provides artifacts from malware execution and EML samples in some cases. 
- [Wireshark documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html) - Official wireshark documentation guide
- [TryHackMe](https://tryhackme.com/paths) - TryHackMe's SOC Analyst path have great rooms for Wireshark, Brim and Network Miner. 
- [Network Miner tutorial](https://hackersonlineclub.com/networkminer-for-network-forensic-analysis/) 
- [Network Miner tutorial 2](https://thesecmaster.com/how-to-analyse-a-pcap-file-using-network-miner-a-network-forensic-analysis-tool-nfat/) 
- [Tshark basics](https://blog.yarsalabs.com/tshark-basics-part1/) 
- [Tshark tutorial](https://www.youtube.com/watch?v=w9mSPvacba0) 
- [Brim tutorial](https://kifarunix.com/analyze-network-traffic-using-brim-security/)
- [Threat hunting with Brim](https://medium.com/brim-securitys-knowledge-funnel/five-elegant-brim-queries-to-threat-hunt-in-zeek-logs-and-packet-captures-30eec4c09933) 
- [Network traffic hunting](https://sanog.org/resources/sanog36/SANOG36-Tutorial_ThreatHunting_Hassan.pdf)
- [Understanding JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/)

## OSINT
- [AppAnyRun](https://app.any.run) - Interactive sandbox to hunt for malware
- [Intezer](https://analyze.intezer.com) - Online sandbox to quickly triage malware. Similar to App AnyRun
- [Virus Total](https://www.virustotal.com/gui/home/upload) - Easily upload the hash of the file or IP address to know whether it is malicious or not
- [AbuseIPDB](https://www.abuseipdb.com) - Check whether an IP is blacklisted
- [GreyNoise](https://viz.greynoise.io) - Hunt for CVEs, IP addresses, hashes, etc
- [Urlscan](https://urlscan.io) - Easily scan for malicious or suspicious URL and have a realtime view of the site
- [Wayback Machine](https://archive.org/web/) - Search for archived pages of a website. 
- [Malware Bazaar](https://bazaar.abuse.ch) - Database with various types of malware.
- [Alienvault](https://otx.alienvault.com/browse/global/pulses?include_inactive=0&sort=-modified&page=1&limit=10) - Search for IOCs from malware families
- [Sputnik Browser Extension](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd?hl=en) - You can download this chrome browser extension for free and it will allow you to easily perform OSINT lookup without needing to search for the site externally. 

## OWASP Top 10
- [OWASP](https://owasp.org/www-project-top-ten/) - Document listing top 10 web app risks that are updated every few years. De facto standard for web app security.
- [OWASP TryHackMe](https://tryhackme.com/room/owasptop102021) - OWASP Top 10 in theory and practical exercises. Free.
- [OWASP Juice Shop](https://tryhackme.com/room/owaspjuiceshop) - Juice shop website to test OWASP skills. Free
- [OWASP GOAT](https://tryhackme.com/room/webgoat) - Another similar site as the juice shop. Free
- [Damn Vulnerable Web App](https://github.com/digininja/DVWA) - Similar as the others. 

## Google Dorks
- [Cheatsheet](https://cdn-cybersecurity.att.com/blog-content/GoogleHackingCheatSheet.pdf)
- [Exploit DB](https://www.exploit-db.com/google-hacking-database) - As a blue teamer, you could also use this site to check on vulnerabilites on your organization.

## Virus Total
- You can upload hashes, IP addresses, URLs or domains to it. 
- Avoid uploading directly the executable or file to Virus Total. Attackers tend to monitor online sandboxes for the detection of their malicious executables or scripts. Once it is detected, they would change their TTPs rendering the past detected artefacts useless. 
- If you do not have an offline sandbox like Cuckoo, you can grab the hash of the artefact and upload it to Virus Total. 
```
Get-FileHash test.exe
```
- Relations tab will tell you about the list of IP, domain and artefacts associated with the search. 
- Checking the communities tab will sometimes tell you about the campaing/APT/malware/CVE associated with it.
- If you are signed into Virus Total, you can view the graph summary whereby you can use the IOC from there for further threat hunting. 

## Living off the lands
Legitimate tools/sites/binaries that are abused by attackers as they can easily evade traditional detection. You could threat hunt these techniques/IOCs in your environment.
- [LOLBAS](https://lolbas-project.github.io) - Window binaries
- [GTFO](https://gtfobins.github.io/#) - UNIX binaries
- [LOLDRIVERS](https://www.loldrivers.io) - Window drivers
- [LOTS](https://lots-project.com) - Websites used for data exfil, C2, hosting of attacker tools, phishing, etc.

## Log analysis
### Tools
- [jq](https://stedolan.github.io/jq/) - CLI for parsing json
- [Gigasheet](https://www.gigasheet.com) - Useful for vieweing large csv files
- [Sysmon View](https://github.com/nshalabi/SysmonTools) - To track and visualize Sysmon logs
- [EZ Tools](https://www.sans.org/tools/ez-tools/) - Great suite for all kinds of stuff 

### Learning resources
- [jq basics](https://www.baeldung.com/linux/jq-command-json)
- [Log Analysis - TryHackMe Tempest](https://tryhackme.com/room/tempestincident) - Full case investigation using Brim, Sysmon View, Window Event Viewer
- [Apache Malicious Log Generator](https://github.com/McLabraid/Apache-Malicious-Log-Generator) - Good to practice Linux skills for analyzing web attacks in logs
- [TryHackMe Juicy Details](https://tryhackme.com/room/juicydetails) - Log analysis for a compromised juice shop. Free room
- [TryHackMe Windows Forensics 1](https://tryhackme.com/room/windowsforensics1) - Usage of Kape and EZ Tools. Free room
- [TryHackMe Windows Forensics 2](https://tryhackme.com/room/windowsforensics2) - Continuation of Window Forensics 1. Paid room
- [TryHackMe Kape](https://tryhackme.com/room/kape) - Usage of Kape and EZ Tools. Free room

## Malware Analysis

## Sigma
Sigma is equivalent to Yara and Snort for malware and traffic analysis detection respectively. This is their official [Github](https://github.com/SigmaHQ/sigma) page.

### Learning resources
- [SOC Prime](https://socprime.com/blog/sigma-rules-the-beginners-guide/) - Guide to sigma basics
- [Basics of Writing Sigma Rules](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/) 
- [Sigma](https://tryhackme.com/room/sigma) - Paid room to learn basics on Sigma 
- [Sighunt](https://tryhackme.com/room/sighunt) - Free room to practice creating Sigma rules

### Tools
-  [detection.fyi](https://detection.fyi) - Lists down sigma rules for many types of attacks. Useful tool to threat hunt according to MITRE framework. 
- [uncoder.io](https://uncoder.io) - Allows you to copy the sigma rules from detection.fyi or any other sites and easily generate the necessary syntax according to your SIEM of preference. 

## Powershell deobfuscation 
Powershell deobfuscation is a necessary technique that should be acquired by SOC analysts. Of course, you might not need to go into very deep levels of reversing heavy obfuscated scripts. But you should be able to deobfuscate with base 64 decode if you come across a script that ends with ==.

### Tools
- [PSDecode](https://github.com/R3MRUM/PSDecode) - Will break down powershell deobfuscation in stages and extracts the IOC
- [Power Decode](https://github.com/Malandrone/PowerDecode) - Perform deobfuscation alongside identifying dynamic malware analysis activities
- [Cyberchef](https://gchq.github.io/CyberChef/) - One stop centre for virtually everything. Some basic recipes for deobfuscating Powershell are:
```
From Base 64
Gunzip
Decode Text (UTF-16LE (1200))
Remove Null Bytes
Generic Beautify
XOR 
```
- [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - Detect Powershell scripts that used Invoke-Obfuscation framework
- The easiest way would be to detonate the script in a sandbox. Before detonating, ideally you should have Sysmon logging installed on the sandbox. You should also enable scriptblock logging. Monitor for Event Code 4103 & 4104 for the unraveling of the powershell. 

### Learning resources 
- [Deobfuscating Emotet Macro With Powershell Command](https://notes.netbytesec.com/2021/02/deobfuscating-emotet-macro-and.html)
- [Deobfuscation using Cyberchef](https://medium.com/mii-cybersec/malicious-powershell-deobfuscation-using-cyberchef-dfb9faff29f)
- [Quick Way to Deobfuscate Powershell](https://securityliterate.com/malware-analysis-in-5-minutes-deobfuscating-powershell-scripts/)
- [Powershell Deobfuscation Using ScriptBlock Logging](https://www.securityinbits.com/malware-analysis/deobfuscate-powershell-using-powershell-logging/)

## Cyberchef
- [Cyberchef Github page](https://gchq.github.io/CyberChef/)
- [Cyberchef from zero to hero slides](https://www.osdfcon.org/presentations/2019/Jonathan-Glass_Cybersecurity-Zero-to-Hero-With-CyberChef.pdf)
- [List of cyberchef recipes](https://github.com/4n6strider/cyber-chef-recipes) - To use the recipes, simply click on load recipes in Cyberchef and paste the recipes from there into the load recipes section. 
- [Another list of cyberchef recipes](https://github.com/mattnotmax/cyberchef-recipes)

 ![image](https://user-images.githubusercontent.com/24632042/234255052-e9fcc516-8ffb-40a2-84de-a1ca89f3a211.png)
 
 ![image](https://user-images.githubusercontent.com/24632042/234255849-c6894c24-d2af-430b-b2b6-5d52e4cbf5ad.png)

 ![image](https://user-images.githubusercontent.com/24632042/234256502-f71b88e7-352b-4fd7-81c2-93b2d18b7ac0.png)

## Blogs to read for blue teamers
- [DFIR Report](https://thedfirreport.com) - Complete reports on various malwares. Consist of full timeline of attacks, IOCs, MITRE stages of attacks, Sigma, etc.
- [SOC Investigation](https://www.socinvestigation.com) - Good all-rounder blog for SOC analysts.
- [SANS Internet Storm Center](https://isc.sans.edu) - Diaries especially from Didier Stevens are good to learn about new malware analysis tools and techniques.
- [Didier Stevens Blog](https://blog.didierstevens.com) - Didier Stevens official blog related to malware analysis tools.

## VM/Labs/Dataset to play with for blue teamers
- [Splunk Attack Range](https://github.com/splunk/attack_range) - Developed by Splunk Threat Research Team. Allows simulation of Atomics Red Team and Caldera to generate real data. You can then hunt those TTPs in Splunk.
- [Detection Lab](https://github.com/clong/DetectionLab) - Creates a simulated environment where you can play around with attacks and detection. 
- [Detection Lab ELK](https://github.com/cyberdefenders/DetectionLabELK) - Similar detection lab to Splunk but this is ELK based. 
- [HELK](https://github.com/Cyb3rWard0g/HELK) - Threat hunting platform for ELK.
- [Mordor](https://github.com/UraSecTeam/mordor) - Provides simulated adverserial TTPs in json format
- [SecRepo](https://www.secrepo.com) - Excellent repo for beginner SOC analyst who wish to understand how a log format looks like. Contains various type of log samples such as FTP, DNS, DHCP, Zeek, etc. 
   - How to learn with logs from Sec Repo
   
   First, download any sample log of your choice from Sec Repo. In this case, I am downloading the squid access logs. 
   ![image](https://user-images.githubusercontent.com/24632042/234297961-d20ad2ca-4ee9-47f2-ba2a-541ca64d43cb.png)
   
   You can download Splunk Enterprise locally into your machine from [here](https://www.splunk.com/en_us/download.html).
   
   After setting up Splunk locally, head to your main dashboard and click on Add Data.
   ![image](https://user-images.githubusercontent.com/24632042/234298760-7fb6c623-16af-4b57-8f85-e6ce5adaaa18.png)

   Click on upload as in the screenshot below. 
   ![image](https://user-images.githubusercontent.com/24632042/234299048-2b5fefec-c8f3-4893-9d3b-1e33ff5b5295.png)

   You could either upload directly as the zip file but it will take a longer time to process the data. Hence, it is better to unzip it. Once you are done,   click on next till you reach the save sourcetype part. Here, you can save as any name of your choice. Once you are done, click on submit. Before you click start searching, click on extract fields. 
   
   ![image](https://user-images.githubusercontent.com/24632042/234301271-01c6899f-3d29-41cb-9ee7-fdc87747af72.png)
   
   Click on any sample log to extract the fields.
   ![image](https://user-images.githubusercontent.com/24632042/234302451-151c0e71-2306-4bb9-bcf1-7524645c53c6.png)
   
   Click on regular expression. 
   ![image](https://user-images.githubusercontent.com/24632042/234303511-e705a68d-8cd4-49a7-93f8-7a21a83016bb.png)

   Over here, we can highlight whichever field we want and classify it as a specific field. This would make searching in Splunk easier. Since these are weblogs, I would want to have fields for soure IP, http response code, destination IP, and url accessed.
   
   ![image](https://user-images.githubusercontent.com/24632042/234304410-a6c8c329-97c0-4aa3-8a61-b5b5f2822dc4.png)
   
   Once we are done, we can view the fields in our search. Here, we can group the source IP and URLs found in the web logs according to their response codes. This is a basic way on how to use the dataset from sec repo. You would have to explore more with regex to have a more refined result.
   ![image](https://user-images.githubusercontent.com/24632042/234306103-6ddbdcbf-524c-4c3a-b996-86832931b1d9.png)   

## List of blue teaming platforms to self study 
- [Blue Team Labs Online](https://blueteamlabs.online) - Gamified blue team platform to train blue teaming skills in security operations, incident response, threat hunting, threat intelligence, reverses engineering and OSINT. Have both free and paid plans. 
- [TryHackMe](https://tryhackme.com) - Blue team/SOC Analyst path is good for beginners. Have both free and paid plans. 
- [Cyberdefenders](https://cyberdefenders.org) - Gamified blue team platform. Requires you to download the labs/tools. Free.
- [LetsDefend](https://letsdefend.io) - Simulated SOC environment where players assume the role of SOC analysts. Have both free and paid plans. 
- [Rangeforce](https://go.rangeforce.com/community-edition-registration) - Have a free community version to explore
- [Immersive Labs](https://www.immersivelabs.com/platform/blue-team-training-cyberpro/) - Another good platform but not sure if they are accepting new registrations
- Splunk Bots - The best CTF to improve Splunking skills. Free
  - [Splunk Bots V1](https://github.com/splunk/botsv1)
  - [Splunk Bots V2](https://github.com/splunk/botsv2)
  - [Splunk Bots V3](https://github.com/splunk/botsv3)
- [Splunk Bots Website](https://bots.splunk.com) - Dedicated BOTS site by Splunk with Bots v1 and v2 in it
   - Okta CTF - Hunt in Splunk with Okta dashboard
   - Corelight CTF - Hunt for Trickbot using Zeek and Suricata alerts together with Corelight CTI
   - Hunt for JA3  - Hunt for JA3 using Zeek
- [Splunk Kringle Kon 2021](https://hhc21.bossworkshops.io/en-US/account/insecurelogin?username=user&password=kringlecon)
