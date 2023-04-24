# Blue-Teamers-Guide
Curated list of useful links and resources for study or work related to blue teaming


## OWASP Top 10


## Log analysis

## Sigma
Sigma is equivalent to Yara and Snort for malware and traffic analysis detection respectively. 
- Learning resources
1. 

- Tools
1. [detection.fyi](https://detection.fyi) - Lists down sigma rules for many types of attacks. Useful tool to threat hunt according to MITRE framework. 
2. [uncoder.io](https://uncoder.io) - Allows you to copy the sigma rules from detection.fyi or any other sites and easily generate the necessary syntax according to your SIEM of preference. 


## Powershell deobfuscation 
Powershell deobfuscation is a necessary technique that should be acquired by SOC analysts. Of course, you might not need to go into very deep levels of reversing heavy obfuscated scripts. But you should be able to deobfuscate with base 64 decode if you come across a script that ends with ==.

- Learning resources 

- Tools
1. [PSDecode](https://github.com/R3MRUM/PSDecode) - Will break down powershell deobfuscation in stages and extracts the IOC
2. [Power Decode](https://github.com/Malandrone/PowerDecode) - Perform deobfuscation alongside identifying dynamic malware analysis activities
3. [Cyberchef](https://gchq.github.io/CyberChef/) - One stop centre for virtually everything. Some basic recipes for deobfuscating Powershell are:
```
From Base 64
Gunzip
Decode Text (UTF-16LE (1200))
Remove Null Bytes
Generic Beautify
XOR 
```
4. [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) - Detect Powershell scripts that used Invoke-Obfuscation framework
5. The easiest way would be to detonate the script in a sandbox. Before detonating, ideally you should have Sysmon logging installed on the sandbox. You should also enable scriptblock logging. Monitor for Event Code 4103 & 4104 for the unraveling of the powershell. 

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
