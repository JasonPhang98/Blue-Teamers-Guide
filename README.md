# Blue-Teamers-Guide
Curated list of useful links and resources for study or work related to blue teaming especially for newbies in the field.


## Security Frameworks
- [MITRE framework](https://attack.mitre.org)
   - [Mitre Attack Navigator](https://mitre-attack.github.io/attack-navigator/) 
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Diamond Model](https://www.socinvestigation.com/threat-intelligence-diamond-model-of-intrusion-analysis/) 

## Log Analysis
### Tools
- 

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

## Living off the lands
Legitimate tools/sites/binaries that are abused by attackers as they can easily evade traditional detection. You could threat hunt these techniques/IOCs in your environment.
- [LOLBAS](https://lolbas-project.github.io) - Window binaries
- [GTFO](https://gtfobins.github.io/#) - UNIX binaries
- [LOLDRIVERS](https://www.loldrivers.io) - Window drivers
- [LOTS](https://lots-project.com) - Websites used for data exfil, C2, hosting of attacker tools, phishing, etc.

## Log analysis

### Tools
- [jq](https://stedolan.github.io/jq/) - CLI for parsing json. 


### Learning resources
- [jq basics](https://www.baeldung.com/linux/jq-command-json)


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

## List of blue teaming platforms to self study 
- [Blue Team Labs Online](https://blueteamlabs.online) - Gamified blue team platform to train blue teaming skills in security operations, incident response, threat hunting, threat intelligence, reverses engineering and OSINT. Have both free and paid plans. 
- [TryHackMe](https://tryhackme.com) - Blue team/SOC Analyst path is good for beginners. Have both free and paid plans. 
- [Cyberdefenders](https://cyberdefenders.org) - Gamified blue team platform. Requires you to download the labs/tools. Free.
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
