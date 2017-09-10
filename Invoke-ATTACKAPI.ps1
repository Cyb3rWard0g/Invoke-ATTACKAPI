function Invoke-ATTACKAPI
{
<#
.SYNOPSIS
A PS script to interact with the MITRE ATT&CK Framework via its own API

.DESCRIPTION
Use this script to interact with the MITRE ATT&CK Framework via its API and gather information about techniques, 
tactics, groups, software and references provided by the MITRE ATT&CK Team @MITREattack 

Almost all data in ATT&CK can be accessed using the Semantic MediaWiki Ask API. URLs targeting 
the API are constructed in the following pattern 
/api.php?action=ask&format=<format specifier>&query=<insert query statement> 
where <format specifier> is a specific output format (usually json or jsonfm) and <insert query statement> 
refers to a query that specifies the data that will be retrieved. Queries are structured as if they are 
targeting the Semantic MediaWiki #ask parser function.

Queries are constructed by combining one or more page selectors with a set of display parameters. 
A simple selector for all techniques is [[Category:Technique]] and a simple display parameter is
?Has display name which maps to the name of the ATT&CK Technique. To construct the query, the selector
is combined with the display parameter by placing a | symbol in between. So the combined query 
is [[Category:Technique]]|?Has display name. This query will retrieve all ATT&CK techniques along 
with their display name. To run this we just have to URL encode the combined query and place it in the URL. 
The final query is:

https://attack.mitre.org/api.php?action=ask&format=jsonfm&query=%5B%5BCategory%3ATechnique%5D%5D%7C%3FHas%20display%20name

.PARAMETER Sync
Connects to the MITRE ATT&CK framework and dumps all its data to an object.
The output of this is needed before running any other parameters.

.PARAMETER Matrix
Switch that you can use to display an up to date ATT&CK Matrix for Enterprise

.PARAMETER Category
Page selector switch. 

.PARAMETER Technique
Page Selector to show all Techniques at once with their respective properties.

.PARAMETER Group
Page Selector to show all Groups at once with their respective properties.

.PARAMETER Software
Page Selector to show all Software at once with their respective properties.

.PARAMETER Tactic
Page Selector to show all Tactics at once with their respective properties.

.PARAMETER Reference
Page Selector to show all References at once with their respective properties.

.PARAMETER Attribution
Switch used to display a table with techniques and Tools attributed to a specific Group/APT

.PARAMETER All
Switch used to get all the valuable information from the MITRE ATTACK DB at once.

.PARAMETER FullText
Depending on what page selector you choose, the values of this parameter vary. 
This is usually an ID, and it is available with every single page selector.

.PARAMETER ID
Depending on what page selector you choose, the values of this parameter vary.
This is property 'Has ID', and it is available with Technique, Group and Software page selectors

.PARAMETER Name
Depending on what page selector you choose, the values of this parameter vary.
This is usually property 'Has display name' or 'Has title', and it is available with
every single page selector.

.PARAMETER TechniqueTactic
This is property 'Has tactic', and it is available only with Technique page selector.

.PARAMETER Platform
This is property 'Has platform', and it is available only with Technique page selector.

.PARAMETER Alias
This is property 'Has alias', and it is available only with Group page selector.

.PARAMETER TechniqueID
This is property 'Has technique'.fulltext , and it is available in Group and Software pages selector.

.PARAMETER TechniqueName
This is property 'Has technique'.displaytitle , and it is available in Group and Software pages selector.

.PARAMETER Tool
This is property 'Uses software, it is available only with Group page selector.

.PARAMETER Type
This is property 'Has software type' , and it is available only with Software page selector.

.PARAMETER Key
This is property 'Citation key' , and it is available only with Reference page selector.

.PARAMETER Author
This is property 'Has authors'.fulltext , and it is available only with Reference page selector.

.PARAMETER Date
Available only with Reference page selector.

.PARAMETER Year
Available only with Reference page selector.

.EXAMPLE
This query matches all techniques

Invoke-ATTACKAPI -Category -Technique

ID                  : {T1001}
Bypass              : {}
Contributor         : {}
Requires System     : {}
Data Source         : {Packet capture, Process use of network, Process monitoring, Network protocol analysis}
Description         : {Command and control (C2) communications are hidden (but not necessarily encrypted) in an
                      attempt to make the content more difficult to discover or decipher and to make the
                      communication less conspicuous and hide commands from being seen. This encompasses many
                      methods, such as adding junk data to protocol traffic, using steganography, commingling
                      legitimate traffic with C2 communications traffic, or using a non-standard data encoding
                      system, such as a modified Base64 encoding for the message body of an HTTP request.}
Mitigation          : {Network intrusion detection and prevention systems that use network signatures to
                      identify traffic for specific adversary malware can be used to mitigate activity at the
                      network level. Signatures are often for unique indicators within protocols and may be
                      based on the specific obfuscation technique used by a particular adversary or tool, and
                      will likely be different across various malware families and versions. Adversaries will
                      likely change tool C2 signatures over time or construct protocols in such a way as to
                      avoid detection by common defensive tools.University of Birmingham C2}
Tactic              : Command and Control
Analytic Details    : {Analyze network data for uncommon data flows (e.g., a client sending significantly more
                      data than it receives from a server). Processes utilizing the network that do not normally
                      have network communication or have never been seen before are suspicious. Analyze packet
                      contents to detect communications that do not follow the expected protocol behavior for
                      the port that is being used.University of Birmingham C2}
Technique Name      : {Data Obfuscation}
FullText            : Technique/T1001
Link Text           : {[[Technique/T1001|Data Obfuscation]]}
Reference           : {University of Birmingham C2, FireEye APT28, Axiom, FireEye APT30...}
Platform            : {Windows Server 2003, Windows Server 2008, Windows Server 2012, Windows XP...}
Name                : {Data Obfuscation}
CAPEC ID            : {}
Requires Permission : {}
URL                 : https://attack.mitre.org/wiki/Technique/T1001

.............
..................

ID                  : {T1068}
Bypass              : {Anti-virus, System access controls}
Contributor         : {John Lambert, Microsoft Threat Intelligence Center}
Requires System     : {Unpatched software or otherwise vulnerable target. Depending on the target and goal, the
                      system and exploitable service may need to be remotely accessible from the internal
                      network. In the case of privilege escalation, the adversary likely already has user
                      permissions on the target system.}
Data Source         : {Windows Error Reporting, File monitoring, Process monitoring}
Description         : {Exploitation of a software vulnerability occurs when an adversary takes advantage of a
                      programming error in a program, service, or within the operating system software or kernel
                      itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow
                      adversaries to run a command or binary on a remote system for lateral movement, escalate a
                      current process to a higher privilege level, or bypass security mechanisms. Exploits may
                      also allow an adversary access to privileged accounts and credentials. One example of this
                      is MS14-068, which can be used to forge Kerberos tickets using domain user
                      permissions.Technet MS14-068ADSecurity Detecting Forged Tickets}
Mitigation          : {Update software regularly by employing patch management for internal enterprise endpoints
                      and servers. Develop a robust cyber threat intelligence capability to determine what types
                      and levels of threat may use software exploits and 0-days against a particular
                      organization. Make it difficult for adversaries to advance their operation through
                      exploitation of undiscovered or unpatched vulnerabilities by using sandboxing,
                      virtualization, and exploit prevention tools such as the Microsoft Enhanced Mitigation
                      Experience Toolkit.SRD EMET}
Tactic              : {Credential Access, Defense Evasion, Lateral Movement, Privilege Escalation}
Analytic Details    : {Software exploits may not always succeed or may cause the exploited process to become
                      unstable or crash. Software and operating system crash reports may contain useful
                      contextual information about attempted exploits that correlate with other malicious
                      activity. Exploited processes may exhibit behavior that is unusual for the specific
                      process, such as spawning additional processes or reading and writing to files.}
Technique Name      : {Exploitation of Vulnerability}
FullText            : Technique/T1068
Link Text           : {[[Technique/T1068|Exploitation of Vulnerability]]}
Reference           : {ADSecurity Detecting Forged Tickets, Bitdefender APT28 Dec 2015, ESET Sednit July 2015,
                      ESET Sednit Part 1...}
Platform            : {Windows Server 2003, Windows Server 2008, Windows Server 2012, Windows XP...}
Name                : {Exploitation of Vulnerability}
CAPEC ID            : {69}
Requires Permission : {User, Administrator, SYSTEM}
URL                 : https://attack.mitre.org/wiki/Technique/T1068

.EXAMPLE
This query matches the page Technique with ID T1014

Invoke-ATTACKAPI -Category -Technique -ID T1014

ID                  : {T1014}
Bypass              : {Anti-virus, File monitoring, Host intrusion prevention systems, Process whitelisting...}
Contributor         : {}
Requires System     : {}
Data Source         : {BIOS, MBR, System calls}
Description         : {Rootkits are programs that hide the existence of malware by intercepting and modifying
                      operating system API calls that supply system information. Rootkits or rootkit enabling
                      functionality may reside at the user or kernel level in the operating system or lower, to
                      include a [[Technique/T1062|Hypervisor]], Master Boot Record, or the
                      [[Technique/T1019|System Firmware]].Wikipedia Rootkit

                      Adversaries may use rootkits to hide the presence of programs, files, network connections,
                      services, drivers, and other system components.}
Mitigation          : {Identify potentially malicious software that may contain rootkit functionality, and audit
                      and/or block it by using whitelistingBeechey 2010 tools, like AppLocker,Windows Commands
                      JPCERTNSA MS AppLocker or Software Restriction PoliciesCorio 2008 where
                      appropriate.TechNet Applocker vs SRP}
Tactic              : Defense Evasion
Analytic Details    : {Some rootkit protections may be built into anti-virus or operating system software. There
                      are dedicated rootkit detection tools that look for specific types of rootkit behavior.
                      Monitor for the existence of unrecognized DLLs, devices, services, and changes to the
                      MBR.Wikipedia Rootkit}
Technique Name      : {Rootkit}
FullText            : Technique/T1014
Link Text           : {[[Technique/T1014|Rootkit]]}
Reference           : {Wikipedia Rootkit, Beechey 2010, Windows Commands JPCERT, NSA MS AppLocker...}
Platform            : {Windows Server 2003, Windows Server 2008, Windows Server 2012, Windows XP...}
Name                : {Rootkit}
CAPEC ID            : {}
Requires Permission : {Administrator, SYSTEM}
URL                 : https://attack.mitre.org/wiki/Technique/T1014

.EXAMPLE
This query matches against all the group that use a specific software (in this case Cobalt Strike)
SYNTAX: "Software: <tool name>"

Invoke-ATTACKAPI -Category -Group -Tool "Software: Cobalt Strike"

Tool          : {Software: Cobalt Strike, Software: KOMPROGO, Software: WINDSHIELD, Software: SOUNDBITE...}
Alias         : {APT32, OceanLotus Group}
ID            : {G0050}
URL           : https://attack.mitre.org/wiki/Group/G0050
TechniqueName : {Scheduled Task, Regsvr32, PowerShell, Custom Command and Control Protocol...}
FullText      : Group/G0050
Reference     : {FireEye APT32 May 2017, GitHub Malleable C2, GitHub Invoke-Obfuscation}
Name          : {APT32}
Description   : {[[Group/G0050|APT32]] is a threat group that has been active since at least 2014. The group has
                targeted multiple private sector industries as well as with foreign governments, dissidents, and
                journalists. The group's operations are aligned with Vietnamese state interests.FireEye APT32
                May 2017}
TechniqueID   : {Technique/T1053, Technique/T1117, Technique/T1086, Technique/T1094...}
Link Text     : {[[Group/G0050|APT32]]}

.EXAMPLE
[BETA] Exporting custom results to a CSV

Invoke-ATTACKAPI -Category -Technique | where-object -Property ID -GE "T1134" | 
select @{Name="Name"; Expression={$_.Name -join ","}}, @{Name="Tactic"; Expression={$_.Tactic -join ","}}, @{Name ="ID"; Expression={$_.ID -join ","}}, 
@{Name="Description"; Expression={$_.Description -join ","}}, @{Name="Analytic details"; Expression={$_.'Analytic Details' -join ","}}, 
@{Name="Data Source";Expression={$_.'Data Source' -join ","}}  | export-csv F:\wardog\scripts\demo6.csv -NoTypeInformation

.EXAMPLE
Show up to date ATT&CK Matrix for Enterprise

Invoke-ATTACKAPI -Matrix | select Persistence, 'Privilege Escalation', 'Defense Evasion','Credential Access', Discovery, 'Lateral Movement', Execution, Collection, Exfiltration, 'Command and Control' | ft

Persistence                                           Privilege Escalation                  Defense Evasion                         Credential Access                      Discovery                              Lateral Movement                    Execution
-----------                                           --------------------                  ---------------                         -----------------                      ---------                              ----------------                    ---------
.bash_profile and .bashrc                             Access Token Manipulation             Access Token Manipulation               Account Manipulation                   Account Discovery                      AppleScript                         AppleScript
Accessibility Features                                Accessibility Features                Binary Padding                          Bash History                           Application Window Discovery           Application Deployment Software     Application Shimming
AppInit DLLs                                          AppInit DLLs                          Bypass User Account Control             Brute Force                            File and Directory Discovery           Exploitation of Vulnerability       Command-Line Interface
Application Shimming                                  Application Shimming                  Clear Command History                   Create Account                         Network Service Scanning               Logon Scripts                       Execution through API
Authentication Package                                Bypass User Account Control           Code Signing                            Credential Dumping                     Network Share Discovery                Pass the Hash                       Execution through Mod...
Bootkit                                               DLL Injection                         Component Firmware                      Credentials in Files                   Peripheral Device Discovery            Pass the Ticket                     Graphical User Interface
Change Default File Association                       DLL Search Order Hijacking            Component Object Model Hijacking        Exploitation of Vulnerability          Permission Groups Discovery            Remote Desktop Protocol             InstallUtil
Component Firmware                                    Dylib Hijacking                       Deobfuscate/Decode Files or Information Input Capture                          Process Discovery                      Remote File Copy                    Launchctl
Component Object Model Hijacking                      Exploitation of Vulnerability         Disabling Security Tools                Input Prompt                           Query Registry                         Remote Services                     PowerShell
Cron Job                                              File System Permissions Weakness      DLL Injection                           Keychain                               Remote System Discovery                Replication Through Removable Media Process Hollowing
DLL Search Order Hijacking                            Launch Daemon                         DLL Search Order Hijacking              Network Sniffing                       Security Software Discovery            Shared Webroot                      Regsvcs/Regasm
Dylib Hijacking                                       Local Port Monitor                    DLL Side-Loading                        Private Keys                           System Information Discovery           Taint Shared Content                Regsvr32
External Remote Services                              New Service                           Exploitation of Vulnerability           Securityd Memory                       System Network Configuration Discovery Third-party Software                Rundll32
File System Permissions Weakness                      Path Interception                     File Deletion                           Two-Factor Authentication Interception System Network Connections Discovery   Windows Admin Shares                Scheduled Task
Hidden Files and Directories                          Plist Modification                    File System Logical Offsets                                                    System Owner/User Discovery            Windows Remote Management           Scripting
Hypervisor                                            Scheduled Task                        Gatekeeper Bypass                                                              System Service Discovery                                                   Service Execution
Launch Agent                                          Service Registry Permissions Weakness Hidden Files and Directories                                                   System Time Discovery                                                      Source
Launch Daemon                                         Setuid and Setgid                     Hidden Users                                                                                                                                              Space after Filename
Launchctl                                             Startup Items                         Hidden Window                                                                                                                                             Third-party Software
LC_LOAD_DYLIB Addition                                Sudo                                  HISTCONTROL                                                                                                                                               Trap
Local Port Monitor                                    Valid Accounts                        Indicator Blocking                                                                                                                                        Trusted Developer Uti...
Login Item                                            Web Shell                             Indicator Removal from Tools                                                                                                                              Windows Management In...
Logon Scripts                                                                               Indicator Removal on Host                                                                                                                                 Windows Remote Manage...
Modify Existing Service                                                                     Install Root Certificate
Netsh Helper DLL                                                                            InstallUtil
New Service                                                                                 Launchctl
Office Application Startup                                                                  LC_MAIN Hijacking
Path Interception                                                                           Masquerading
Plist Modification                                                                          Modify Registry
Rc.common                                                                                   Network Share Connection Removal
Redundant Access                                                                            NTFS Extended Attributes
Registry Run Keys / Start Folder                                                            Obfuscated Files or Information
Re-opened Applications                                                                      Plist Modification
Scheduled Task                                                                              Process Hollowing
Security Support Provider                                                                   Redundant Access
Service Registry Permissions Weakness                                                       Regsvcs/Regasm
Shortcut Modification                                                                       Regsvr32
Startup Items                                                                               Rootkit
System Firmware                                                                             Rundll32
Trap                                                                                        Scripting
Valid Accounts                                                                              Software Packing
Web Shell                                                                                   Space after Filename
Windows Management Instrumentation Event Subscription                                       Timestomp
Winlogon Helper DLL                                                                         Trusted Developer Utilities
                                                                                            Valid Accounts

.EXAMPLE
Showing an up to date table with all the valuable information from the MITRE ATTACK DB at once

Invoke-ATTACKAPI -All | ft

Tactic      TechniqueName           TechniqueID     Group             Group Alias                                         Group ID Tool
------      -------------           -----------     -----             -----------                                         -------- ----
Collection  Screen Capture          Technique/T1113 APT28             {APT28, Sednit, Sofacy, Pawn Storm...}              G0007
Collection  Screen Capture          Technique/T1113 APT28             {APT28, Sednit, Sofacy, Pawn Storm...}              G0007    Software: XAgentOSX
Collection  Data from Local System  Technique/T1005 APT1              {APT1, Comment Crew, Comment Group, Comment Panda}  G0006
Collection  Screen Capture          Technique/T1113 Cleaver           {Cleaver, TG-2889, Threat Group 2889}               G0003    Software: TinyZBot
Collection  Screen Capture          Technique/T1113 APT32             {APT32, OceanLotus Group}                           G0050    Software: Cobalt Strike
Collection  Screen Capture          Technique/T1113 APT29             {APT29, The Dukes, Cozy Bear}                       G0016    Software: CosmicDuke, TinyBaron,...
Collection  Data Staged             Technique/T1074 APT30             APT30                                               G0013    Software: SPACESHIP
Collection  Data from Local System  Technique/T1005 Ke3chang          Ke3chang                                            G0004
Collection  Data from Local System  Technique/T1005 Lazarus Group     {Lazarus Group, HIDDEN COBRA, Guardians of Peace}   G0032
Collection  Data from Local System  Technique/T1005 APT29             {APT29, The Dukes, Cozy Bear}                       G0016    Software: CosmicDuke, TinyBaron,...
Collection  Data from Local System  Technique/T1005 APT29             {APT29, The Dukes, Cozy Bear}                       G0016    Software: PinchDuke
Collection  Data from Local System  Technique/T1005 APT30             APT30                                               G0013    Software: FLASHFLOOD
Collection  Screen Capture          Technique/T1113 RTM               RTM                                                 G0048    Software: RTM
Collection  Screen Capture          Technique/T1113 MONSOON           {MONSOON, Operation Hangover}                       G0042    Software: BADNEWS
Collection  Screen Capture          Technique/T1113 menuPass          {menuPass, Stone Panda, APT10, Red Apollo...}       G0045    Software: RedLeaves, BUGJUICE
Collection  Email Collection        Technique/T1114 APT29             {APT29, The Dukes, Cozy Bear}                       G0016    Software: SeaDuke, SeaDaddy, Sea...
Collection  Email Collection        Technique/T1114 APT1              {APT1, Comment Crew, Comment Group, Comment Panda}  G0006
Collection  Screen Capture          Technique/T1113 Sandworm Team     {Sandworm Team, Quedagh}                            G0034    Software: BlackEnergy, Black Energy
Collection  Screen Capture          Technique/T1113 FIN7              FIN7                                                G0046    Software: HALFBAKED
Collection  Screen Capture          Technique/T1113 Dust Storm        Dust Storm                                          G0031    Software: ZLib
Collection  Screen Capture          Technique/T1113 Dragonfly         {Dragonfly, Energetic Bear}                         G0035    Software: Trojan.Karagany
Collection  Screen Capture          Technique/T1113 menuPass          {menuPass, Stone Panda, APT10, Red Apollo...}       G0045    Software: EvilGrab
Collection  Screen Capture          Technique/T1113 Group5            Group5                                              G0043
Collection  Screen Capture          Technique/T1113 Gamaredon Group   Gamaredon Group                                     G0047    Software: Pteranodon
Collection  Data Staged             Technique/T1074 APT30             APT30                                               G0013    Software: FLASHFLOOD

.EXAMPLE
Show up to date ATT&CK Matrix for Enterprise and export it to a CSV (Technique Names are retrieved as Strings)

Invoke-ATTACKAPI -Matrix | select Persistence, 'Privilege Escalation', 'Defense Evasion','Credential Access', Discovery, 'Lateral Movement', Execution, Collection, Exfiltration, 'Command and Control' | Export-Csv C:\wardog\scripts\matrix.csv -NoTypeInformation

.EXAMPLE
Show an up to date table of Groups/APTs with the techniques and tools attributed to them

Invoke-ATTACKAPI -Attribution | ft

Group     Group Alias                                        Group ID Tactic                                  TechniqueName                           TechniqueID     Tool
-----     -----------                                        -------- ------                                  -------------                           -----------     ----
admin@338 admin@338                                          G0018    Discovery                               System Time Discovery                   Technique/T1124 Software: Net, net.exe
admin@338 admin@338                                          G0018    Defense Evasion                         Network Share Connection Removal        Technique/T1126 Software: Net, net.exe
admin@338 admin@338                                          G0018    Command and Control                     Commonly Used Port                      Technique/T1043 Software: LOWBALL
admin@338 admin@338                                          G0018    {Command and Control, Lateral Movement} Remote File Copy                        Technique/T1105 Software: LOWBALL
admin@338 admin@338                                          G0018    Discovery                               System Network Connections Discovery    Technique/T1049 Software: netstat, netstat.exe
admin@338 admin@338                                          G0018    Discovery                               System Information Discovery            Technique/T1082 Software: BUBBLEWRAP, Backdoor.APT...
admin@338 admin@338                                          G0018    Discovery                               Account Discovery                       Technique/T1087
admin@338 admin@338                                          G0018    Execution                               Command-Line Interface                  Technique/T1059
admin@338 admin@338                                          G0018    Discovery                               System Service Discovery                Technique/T1007
admin@338 admin@338                                          G0018    Defense Evasion                         Masquerading                            Technique/T1036
admin@338 admin@338                                          G0018    Discovery                               Remote System Discovery                 Technique/T1018 Software: Net, net.exe
admin@338 admin@338                                          G0018    Discovery                               System Network Connections Discovery    Technique/T1049 Software: Net, net.exe
admin@338 admin@338                                          G0018    Lateral Movement                        Windows Admin Shares                    Technique/T1077 Software: Net, net.exe
admin@338 admin@338                                          G0018    {Defense Evasion, Privilege Escalation} DLL Injection                           Technique/T1055 Software: PoisonIvy, Poison Ivy
admin@338 admin@338                                          G0018    Discovery                               System Service Discovery                Technique/T1007 Software: Net, net.exe
admin@338 admin@338                                          G0018    Discovery                               Account Discovery                       Technique/T1087 Software: Net, net.exe
admin@338 admin@338                                          G0018    Command and Control                     Standard Non-Application Layer Protocol Technique/T1095 Software: BUBBLEWRAP, Backdoor.APT...
admin@338 admin@338                                          G0018    Discovery                               System Information Discovery            Technique/T1082 Software: Systeminfo, systeminfo.exe
admin@338 admin@338                                          G0018    Credential Access                       Create Account                          Technique/T1136 Software: Net, net.exe
admin@338 admin@338                                          G0018    Discovery                               Permission Groups Discovery             Technique/T1069
admin@338 admin@338                                          G0018    Discovery                               Network Share Discovery                 Technique/T1135 Software: Net, net.exe
admin@338 admin@338                                          G0018    Command and Control                     Web Service                             Technique/T1102 Software: LOWBALL
admin@338 admin@338                                          G0018    Execution                               Service Execution                       Technique/T1035 Software: Net, net.exe
admin@338 admin@338                                          G0018    Discovery                               File and Directory Discovery            Technique/T1083
admin@338 admin@338                                          G0018    Discovery                               Permission Groups Discovery             Technique/T1069 Software: Net, net.exe
admin@338 admin@338                                          G0018    Discovery                               System Network Connections Discovery    Technique/T1049
admin@338 admin@338                                          G0018    Discovery                               System Information Discovery            Technique/T1082
admin@338 admin@338                                          G0018    Command and Control                     Standard Application Layer Protocol     Technique/T1071 Software: LOWBALL
admin@338 admin@338                                          G0018    Command and Control                     Standard Cryptographic Protocol         Technique/T1032 Software: PoisonIvy, Poison Ivy
admin@338 admin@338                                          G0018    {Collection, Credential Access}         Input Capture                           Technique/T1056 Software: PoisonIvy, Poison Ivy
admin@338 admin@338                                          G0018    Command and Control                     Standard Application Layer Protocol     Technique/T1071 Software: BUBBLEWRAP, Backdoor.APT...
admin@338 admin@338                                          G0018    Discovery                               System Network Configuration Discovery  Technique/T1016 Software: ipconfig, ipconfig.exe
admin@338 admin@338                                          G0018    Discovery                               System Network Configuration Discovery  Technique/T1016
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Collection                              Data from Local System                  Technique/T1005
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Execution                               Service Execution                       Technique/T1035 Software: xCmd
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Lateral Movement                        Pass the Hash                           Technique/T1075 Software: Pass-The-Hash Toolkit
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Execution                               Service Execution                       Technique/T1035 Software: Net, net.exe
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Discovery                               Remote System Discovery                 Technique/T1018 Software: Net, net.exe
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Collection                              Email Collection                        Technique/T1114
APT1      {APT1, Comment Crew, Comment Group, Comment Panda} G0006    Lateral Movement                        Pass the Hash                           Technique/T1075

.EXAMPLE
Show an up to date table of the techniques and tools attributed to APT with Group ID G0046 (FIN7)

Invoke-ATTACKAPI -Attribution | Where-Object -Property 'Group ID' -EQ 'G0046' | ft

Group Group Alias Group ID Tactic                                         TechniqueName                       TechniqueID     Tool                                Description
----- ----------- -------- ------                                         -------------                       -----------     ----                                -----------
FIN7  FIN7        G0046    Discovery                                      Process Discovery                   Technique/T1057 Software: HALFBAKED                 {[[Software/S0151|HALFBAKED]] can obtain information about running processes on the victim.FireEye FIN7 A...
FIN7  FIN7        G0046    Persistence                                    Registry Run Keys / Start Folder    Technique/T1060                                     {[[Group/G0046|FIN7]] malware has created a Registry Run key pointing to its malicious LNK file to establ...
FIN7  FIN7        G0046    Discovery                                      Query Registry                      Technique/T1012 Software: POWERSOURCE, DNSMessenger {[[Software/S0145|POWERSOURCE]] queries Registry keys in preparation for setting Run keys to achieve pers...
FIN7  FIN7        G0046    Persistence                                    Registry Run Keys / Start Folder    Technique/T1060 Software: POWERSOURCE, DNSMessenger {[[Software/S0145|POWERSOURCE]] achieves persistence by setting a Registry Run key, with the path dependi...
FIN7  FIN7        G0046    {Command and Control, Lateral Movement}        Remote File Copy                    Technique/T1105 Software: POWERSOURCE, DNSMessenger {[[Software/S0145|POWERSOURCE]] has been observed being used to download [[Software/S0146|TEXTMATE]] and ...
FIN7  FIN7        G0046    {Execution, Persistence, Privilege Escalation} Application Shimming                Technique/T1138                                     {[[Group/G0046|FIN7]] has used application shim databases for persistence.FireEye FIN7 Shim Databases}
FIN7  FIN7        G0046    {Execution, Persistence, Privilege Escalation} Scheduled Task                      Technique/T1053                                     {[[Group/G0046|FIN7]] malware has created scheduled tasks to establish persistence.FireEye FIN7 April 201...
FIN7  FIN7        G0046    Command and Control                            Standard Application Layer Protocol Technique/T1071 Software: Carbanak, Anunak          {The [[Software/S0030|Carbanak]] malware communicates to its command server using HTTP with an encrypted ...
FIN7  FIN7        G0046    Collection                                     Screen Capture                      Technique/T1113 Software: HALFBAKED                 {[[Software/S0151|HALFBAKED]] can obtain screenshots from the victim.FireEye FIN7 April 2017}
FIN7  FIN7        G0046    Command and Control                            Standard Application Layer Protocol Technique/T1071 Software: POWERSOURCE, DNSMessenger {[[Software/S0145|POWERSOURCE]] uses DNS TXT records for C2.FireEye FIN7 March 2017Cisco DNSMessenger Mar...
FIN7  FIN7        G0046    Execution                                      Windows Management Instrumentation  Technique/T1047 Software: HALFBAKED                 {[[Software/S0151|HALFBAKED]] can use WMI queries to gather system information.FireEye FIN7 April 2017}
FIN7  FIN7        G0046    Command and Control                            Standard Application Layer Protocol Technique/T1071 Software: TEXTMATE, DNSMessenger    {[[Software/S0146|TEXTMATE]] uses DNS TXT records for C2.FireEye FIN7 March 2017}
FIN7  FIN7        G0046    Discovery                                      System Information Discovery        Technique/T1082 Software: HALFBAKED                 {[[Software/S0151|HALFBAKED]] can obtain information about the OS, processor, and BIOS.FireEye FIN7 April...
FIN7  FIN7        G0046    {Collection, Credential Access}                Input Capture                       Technique/T1056 Software: Carbanak, Anunak          {[[Software/S0030|Carbanak]] contains keylogger functionality.Kaspersky Carbanak}
FIN7  FIN7        G0046    Command and Control                            Standard Cryptographic Protocol     Technique/T1032 Software: Carbanak, Anunak          {[[Software/S0030|Carbanak]] encrypts the message body of HTTP traffic with RC2 and Base64 encoding.Kaspe...
FIN7  FIN7        G0046    Execution                                      PowerShell                          Technique/T1086 Software: HALFBAKED                 {[[Software/S0151|HALFBAKED]] can execute PowerShell scripts.FireEye FIN7 April 2017}
FIN7  FIN7        G0046    {Command and Control, Lateral Movement}        Remote File Copy                    Technique/T1105                                     {[[Group/G0046|FIN7]] uses a PowerShell script to launch shellcode that retrieves an additional payload.F...
FIN7  FIN7        G0046    Execution                                      PowerShell                          Technique/T1086 Software: POWERSOURCE, DNSMessenger {[[Software/S0145|POWERSOURCE]] is a PowerShell backdoor.FireEye FIN7 March 2017Cisco DNSMessenger March ...
FIN7  FIN7        G0046    Execution                                      PowerShell                          Technique/T1086                                     {[[Group/G0046|FIN7]] uses a PowerShell script to launch shellcode that retrieves an additional payload.F...
FIN7  FIN7        G0046    Defense Evasion                                Masquerading                        Technique/T1036                                     {[[Group/G0046|FIN7]] has created a scheduled task named “AdobeFlashSync” to establish persistence.Morphi...
FIN7  FIN7        G0046    Defense Evasion                                Obfuscated Files or Information     Technique/T1027 Software: POWERSOURCE, DNSMessenger {If the victim is using PowerShell 3.0 or later, [[Software/S0145|POWERSOURCE]] writes its decoded payloa...
FIN7  FIN7        G0046    Defense Evasion                                File Deletion                       Technique/T1107 Software: HALFBAKED                 {[[Software/S0151|HALFBAKED]] can delete a specified file.FireEye FIN7 April 2017}
FIN7  FIN7        G0046    Execution                                      Command-Line Interface              Technique/T1059 Software: TEXTMATE, DNSMessenger    {[[Software/S0146|TEXTMATE]] executes cmd.exe to provide  a reverse shell to attackers.FireEye FIN7 March...


.LINK
https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI
.LINK
https://attack.mitre.org/wiki/Using_the_API
.LINK
https://github.com/SadProcessor/SomeStuff/blob/master/Get-ATTaCK.ps1
.LINK
https://www.semantic-mediawiki.org/wiki/Semantic_MediaWiki

.NOTES
This script was inspired by @SadProcessor's Get-ATTack.ps1 script

#>

    [CmdletBinding(HelpURI='https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI',DefaultParameterSetName='NoParam')]
    param(

        [Parameter(Position=0,Mandatory=$true,ParameterSetname='Technique')]
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='Group')]
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='Software')]
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='Tactic')]
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='Reference')][switch]$Category,

        [Parameter(Position=1,Mandatory=$true,ParameterSetname='Technique')][switch]$Technique,
        [Parameter(Position=1,Mandatory=$true,ParameterSetname='Group')][switch]$Group,
        [Parameter(Position=1,Mandatory=$true,ParameterSetname='Software')][switch]$Software,
        [Parameter(Position=1,Mandatory=$true,ParameterSetname='Tactic')][switch]$Tactic,
        [Parameter(Position=1,Mandatory=$true,ParameterSetname='Reference')][switch]$Reference,

        [Parameter(Position=0,Mandatory=$true,ParameterSetname='SyncATTCK')]
        [switch]$Sync,
        
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='ATTACKMatrix')]
        [switch]$Matrix,
        
        [Parameter(Position=0,Mandatory=$true,ParameterSetname='ATTCKAttribution')]
        [switch]$Attribution,

        [Parameter(Position=0,Mandatory=$true,ParameterSetname='ATTCKAll')]
        [switch]$All   
    )

    DynamicParam
    {        
        $TechniqueSet = $ATTCKLookUp.Technique
        $GroupSet = $ATTCKLookUp.Group
        $SoftwareSet = $ATTCKLookUp.Software
        $TacticSet = $ATTCKLookUp.Tactic  
        $ReferenceSet = $ATTCKLookUp.Reference

        If($PSCmdlet.ParameterSetName -eq 'Technique')
        {
            # Create Attribute
            $Attrib1 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib1.Mandatory = $False
            $Attrib1.Position = 2
            # Create AttributeCollection object for the attribute
            $Collection1 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection1.Add($Attrib1)
            # Add Validate Set 
            $ValidateSet1=new-object System.Management.Automation.ValidateSetAttribute($TechniqueSet.FullText)
            $Collection1.Add($ValidateSet1)
            # Create Runtime Parameter
            $DynParam1 = New-Object System.Management.Automation.RuntimeDefinedParameter('FullText', [String], $Collection1)

            # Create Attribute
            $Attrib2 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib2.Mandatory = $False
            $Attrib2.Position = 3
            # Create AttributeCollection object for the attribute
            $Collection2 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection2.Add($Attrib2)
            # Add Validate Set 
            $ValidateSet2=new-object System.Management.Automation.ValidateSetAttribute($TechniqueSet.ID)
            $Collection2.Add($ValidateSet2)
            # Create Runtime Parameter
            $DynParam2 = New-Object System.Management.Automation.RuntimeDefinedParameter('ID', [String], $Collection2)
            
            # Create Attribute
            $Attrib3 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib3.Mandatory = $False
            $Attrib3.Position = 4
            # Create AttributeCollection object for the attribute
            $Collection3 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection3.Add($Attrib3)
            # Add Validate Set 
            $ValidateSet3=new-object System.Management.Automation.ValidateSetAttribute($TechniqueSet.Name)
            $Collection3.Add($ValidateSet3)
            # Create Runtime Parameter
            $DynParam3 = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [String], $Collection3)

            # Create Attribute
            $Attrib4 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib4.Mandatory = $False
            $Attrib4.Position = 5
            # Create AttributeCollection object for the attribute
            $Collection4 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection4.Add($Attrib4)
            # Add Validate Set 
            $ValidateSet4=new-object System.Management.Automation.ValidateSetAttribute($TechniqueSet.Tactic)
            $Collection4.Add($ValidateSet4)
            # Create Runtime Parameter
            $DynParam4 = New-Object System.Management.Automation.RuntimeDefinedParameter('TechniqueTactic', [String], $Collection4)

            # Create Attribute
            $Attrib5 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib5.Mandatory = $False
            $Attrib5.Position = 6
            # Create AttributeCollection object for the attribute
            $Collection5 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection5.Add($Attrib5)
            # Add Validate Set 
            $ValidateSet5=new-object System.Management.Automation.ValidateSetAttribute($TechniqueSet.Platform)
            $Collection5.Add($ValidateSet5)
            # Create Runtime Parameter
            $DynParam5 = New-Object System.Management.Automation.RuntimeDefinedParameter('Platform', [String], $Collection5)
            
                       
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

            $Dictionary.Add('FullText', $dynParam1)
            $Dictionary.Add('ID', $dynParam2)
            $Dictionary.Add('Name', $dynParam3)
            $Dictionary.Add('TechniqueTactic', $dynParam4)
            $Dictionary.Add('Platform', $dynParam5)
            
            return $Dictionary    
        }
        
        If($PSCmdlet.ParameterSetName -eq 'Group')
        {
            # Create Attribute
            $Attrib1 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib1.Mandatory = $False
            $Attrib1.Position = 2
            # Create AttributeCollection object for the attribute
            $Collection1 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection1.Add($Attrib1)
            # Add Validate Set 
            $ValidateSet1=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.FullText)
            $Collection1.Add($ValidateSet1)
            # Create Runtime Parameter
            $DynParam1 = New-Object System.Management.Automation.RuntimeDefinedParameter('FullText', [String], $Collection1)

            # Create Attribute
            $Attrib2 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib2.Mandatory = $False
            $Attrib2.Position = 3
            # Create AttributeCollection object for the attribute
            $Collection2 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection2.Add($Attrib2)
            # Add Validate Set 
            $ValidateSet2=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.ID)
            $Collection2.Add($ValidateSet2)
            # Create Runtime Parameter
            $DynParam2 = New-Object System.Management.Automation.RuntimeDefinedParameter('ID', [String], $Collection2)
            
            # Create Attribute
            $Attrib3 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib3.Mandatory = $False
            $Attrib3.Position = 4
            # Create AttributeCollection object for the attribute
            $Collection3 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection3.Add($Attrib3)
            # Add Validate Set 
            $ValidateSet3=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.Name)
            $Collection3.Add($ValidateSet3)
            # Create Runtime Parameter
            $DynParam3 = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [String], $Collection3)

            # Create Attribute
            $Attrib4 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib4.Mandatory = $False
            $Attrib4.Position = 5
            # Create AttributeCollection object for the attribute
            $Collection4 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection4.Add($Attrib4)
            # Add Validate Set 
            $ValidateSet4=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.Alias)
            $Collection4.Add($ValidateSet4)
            # Create Runtime Parameter
            $DynParam4 = New-Object System.Management.Automation.RuntimeDefinedParameter('Alias', [String], $Collection4)

            # Create Attribute
            $Attrib5 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib5.Mandatory = $False
            $Attrib5.Position = 6
            # Create AttributeCollection object for the attribute
            $Collection5 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection5.Add($Attrib5)
            # Add Validate Set 
            $ValidateSet5=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.TechniqueID)
            $Collection5.Add($ValidateSet5)
            # Create Runtime Parameter
            $DynParam5 = New-Object System.Management.Automation.RuntimeDefinedParameter('TechniqueID', [String], $Collection5)
                       
            # Create Attribute
            $Attrib6 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib6.Mandatory = $False
            $Attrib6.Position = 7
            # Create AttributeCollection object for the attribute
            $Collection6 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection6.Add($Attrib6)
            # Add Validate Set 
            $ValidateSet6=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.TechniqueName)
            $Collection6.Add($ValidateSet6)
            # Create Runtime Parameter
            $DynParam6 = New-Object System.Management.Automation.RuntimeDefinedParameter('TechniqueName', [String], $Collection6)
            
            # Create Attribute
            $Attrib7 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib7.Mandatory = $False
            $Attrib7.Position = 8
            # Create AttributeCollection object for the attribute
            $Collection7 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection7.Add($Attrib7)
            # Add Validate Set 
            $ValidateSet7=new-object System.Management.Automation.ValidateSetAttribute($GroupSet.Tool)
            $Collection7.Add($ValidateSet7)
            # Create Runtime Parameter
            $DynParam7 = New-Object System.Management.Automation.RuntimeDefinedParameter('Tool', [String], $Collection7)
            
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

            $Dictionary.Add('FullText', $dynParam1)
            $Dictionary.Add('ID', $dynParam2)
            $Dictionary.Add('Name', $dynParam3)
            $Dictionary.Add('Alias', $dynParam4)
            $Dictionary.Add('TechniqueID', $dynParam5)
            $Dictionary.Add('TechniqueName', $dynParam6)
            $Dictionary.Add('Tool', $dynParam7)

            return $Dictionary
        }     
             
        If($PSCmdlet.ParameterSetName -eq 'Software')
        {
            # Create Attribute
            $Attrib1 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib1.Mandatory = $False
            $Attrib1.Position = 2
            # Create AttributeCollection object for the attribute
            $Collection1 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection1.Add($Attrib1)
            # Add Validate Set 
            $ValidateSet1=new-object System.Management.Automation.ValidateSetAttribute($SoftwareSet.FullText)
            $Collection1.Add($ValidateSet1)
            # Create Runtime Parameter
            $DynParam1 = New-Object System.Management.Automation.RuntimeDefinedParameter('FullText', [String], $Collection1)

            # Create Attribute
            $Attrib2 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib2.Mandatory = $False
            $Attrib2.Position = 3
            # Create AttributeCollection object for the attribute
            $Collection2 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection2.Add($Attrib2)
            # Add Validate Set 
            $ValidateSet2=new-object System.Management.Automation.ValidateSetAttribute($SoftwareSet.ID)
            $Collection2.Add($ValidateSet2)
            # Create Runtime Parameter
            $DynParam2 = New-Object System.Management.Automation.RuntimeDefinedParameter('ID', [String], $Collection2)
            
            # Create Attribute
            $Attrib3 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib3.Mandatory = $False
            $Attrib3.Position = 4
            # Create AttributeCollection object for the attribute
            $Collection3 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection3.Add($Attrib3)
            # Add Validate Set 
            $ValidateSet3=new-object System.Management.Automation.ValidateSetAttribute($SoftwareSet.Name)
            $Collection3.Add($ValidateSet3)
            # Create Runtime Parameter
            $DynParam3 = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [String], $Collection3)

            # Create Attribute
            $Attrib4 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib4.Mandatory = $False
            $Attrib4.Position = 5
            # Create AttributeCollection object for the attribute
            $Collection4 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection4.Add($Attrib4)
            # Add Validate Set 
            $ValidateSet4=new-object System.Management.Automation.ValidateSetAttribute($SoftwareSet.TechniqueID)
            $Collection4.Add($ValidateSet4)
            # Create Runtime Parameter
            $DynParam4 = New-Object System.Management.Automation.RuntimeDefinedParameter('TechniqueID', [String], $Collection4)

            # Create Attribute
            $Attrib5 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib5.Mandatory = $False
            $Attrib5.Position = 6
            # Create AttributeCollection object for the attribute
            $Collection5 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection5.Add($Attrib5)
            # Add Validate Set 
            $ValidateSet5=new-object System.Management.Automation.ValidateSetAttribute($SoftwareSet.TechniqueName)
            $Collection5.Add($ValidateSet5)
            # Create Runtime Parameter
            $DynParam5 = New-Object System.Management.Automation.RuntimeDefinedParameter('TechniqueName', [String], $Collection5)

            # Create Attribute
            $Attrib6 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib6.Mandatory = $False
            $Attrib6.Position = 7
            # Create AttributeCollection object for the attribute
            $Collection6 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection6.Add($Attrib6)
            # Add Validate Set 
            $ValidateSet6=new-object System.Management.Automation.ValidateSetAttribute($SoftwareSet.Type)
            $Collection6.Add($ValidateSet6)
            # Create Runtime Parameter
            $DynParam6 = New-Object System.Management.Automation.RuntimeDefinedParameter('Type', [String], $Collection6)
                       
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

            $Dictionary.Add('FullText', $dynParam1)
            $Dictionary.Add('ID', $dynParam2)
            $Dictionary.Add('Name', $dynParam3)
            $Dictionary.Add('TechniqueID', $dynParam4)
            $Dictionary.Add('TechniqueName', $dynParam5)
            $Dictionary.Add('Type', $dynParam6)

            return $Dictionary
        }

        If($PSCmdlet.ParameterSetName -eq 'Tactic')
        {
            # Create Attribute
            $Attrib1 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib1.Mandatory = $False
            $Attrib1.Position = 2
            # Create AttributeCollection object for the attribute
            $Collection1 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection1.Add($Attrib1)
            # Add Validate Set 
            $ValidateSet1=new-object System.Management.Automation.ValidateSetAttribute($TacticSet.FullText)
            $Collection1.Add($ValidateSet1)
            # Create Runtime Parameter
            $DynParam1 = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [String], $Collection1)
                                  
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            
            $Dictionary.Add('Name', $dynParam1)

            return $Dictionary
        }

        If($PSCmdlet.ParameterSetName -eq 'Reference')
        {
            # Create Attribute
            $Attrib1 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib1.Mandatory = $Fase
            $Attrib1.Position = 2
            # Create AttributeCollection object for the attribute
            $Collection1 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection1.Add($Attrib1)
            # Add Validate Set 
            $ValidateSet1=new-object System.Management.Automation.ValidateSetAttribute($ReferenceSet.FullText)
            $Collection1.Add($ValidateSet1)
            # Create Runtime Parameter
            $DynParam1 = New-Object System.Management.Automation.RuntimeDefinedParameter('FullText', [String], $Collection1)

            # Create Attribute
            $Attrib2 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib2.Mandatory = $False
            $Attrib2.Position = 3
            # Create AttributeCollection object for the attribute
            $Collection2 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection2.Add($Attrib2)
            # Add Validate Set 
            $ValidateSet2=new-object System.Management.Automation.ValidateSetAttribute($ReferenceSet.Key)
            $Collection2.Add($ValidateSet2)
            # Create Runtime Parameter
            $DynParam2 = New-Object System.Management.Automation.RuntimeDefinedParameter('Key', [String], $Collection2)
            
            # Create Attribute
            $Attrib3 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib3.Mandatory = $False
            $Attrib3.Position = 4
            # Create AttributeCollection object for the attribute
            $Collection3 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection3.Add($Attrib3)
            # Add Validate Set 
            $ValidateSet3=new-object System.Management.Automation.ValidateSetAttribute($ReferenceSet.Name)
            $Collection3.Add($ValidateSet3)
            # Create Runtime Parameter
            $DynParam3 = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [String], $Collection3)

            # Create Attribute
            $Attrib4 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib4.Mandatory = $False
            $Attrib4.Position = 5
            # Create AttributeCollection object for the attribute
            $Collection4 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection4.Add($Attrib4)
            # Add Validate Set 
            $ValidateSet4=new-object System.Management.Automation.ValidateSetAttribute($ReferenceSet.Author)
            $Collection4.Add($ValidateSet4)
            # Create Runtime Parameter
            $DynParam4 = New-Object System.Management.Automation.RuntimeDefinedParameter('Author', [String], $Collection4)

            # Create Attribute
            $Attrib5 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib5.Mandatory = $False
            $Attrib5.Position = 6
            # Create AttributeCollection object for the attribute
            $Collection5 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection5.Add($Attrib5)
            # Add Validate Set 
            $ValidateSet5=new-object System.Management.Automation.ValidateSetAttribute($ReferenceSet.Date)
            $Collection5.Add($ValidateSet5)
            # Create Runtime Parameter
            $DynParam5 = New-Object System.Management.Automation.RuntimeDefinedParameter('Date', [String], $Collection5)
            
            # Create Attribute
            $Attrib6 = New-Object System.Management.Automation.ParameterAttribute
            $Attrib6.Mandatory = $False
            $Attrib6.Position = 7
            # Create AttributeCollection object for the attribute
            $Collection6 = new-object System.Collections.ObjectModel.Collection[System.Attribute]
            # Add our custom attribute
            $Collection6.Add($Attrib6)
            # Add Validate Set 
            $ValidateSet6=new-object System.Management.Automation.ValidateSetAttribute($ReferenceSet.Year)
            $Collection6.Add($ValidateSet6)
            # Create Runtime Parameter
            $DynParam6 = New-Object System.Management.Automation.RuntimeDefinedParameter('Year', [String], $Collection6)
                    
            $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

            $Dictionary.Add('FullText', $dynParam1)
            $Dictionary.Add('Key', $dynParam2)
            $Dictionary.Add('Name', $dynParam3)
            $Dictionary.Add('Author', $dynParam4)
            $Dictionary.Add('Date', $dynParam5)
            $Dictionary.Add('Year', $dynParam6)

            return $Dictionary
        }
    }

    Begin 
    {
        if($PSCmdlet.ParameterSetName -eq 'NoParam'){
            get-help Invoke-ATTACKAPI -Online
            get-help Invoke-ATTACKAPI
            Break
        }
        if($PSCmdlet.ParameterSetName -eq 'Technique'){
           if ($DynParam1.IsSet)
           {
                $Property = "Fulltext"
                $match = "$($DynParam1.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -eq $match

           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "ID"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -eq $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -eq $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "Tactic"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -eq $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "Platform"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -eq $match
           }
           else
           {
                $Query = $ATTCKLookUp.Technique 
           }
        }
        if($PSCmdlet.ParameterSetName -eq 'Group'){
           if ($DynParam1.IsSet)
           {
                $Property = "Fulltext"
                $match = "$($DynParam1.value)"
                $Query = $ATTCKLookUp.Group| ? -Property $Property -eq $match
           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "ID"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -eq $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -eq $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "Alias"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -eq $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "TechniqueID"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -eq $match
           }
           elseif ($DynParam6.IsSet)
           {
                $Property = "TechniqueName"
                $match = "$($DynParam6.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -eq $match
           }
           elseif ($DynParam7.IsSet)
           {
                $Property = "Tool"
                $match = "$($DynParam7.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -eq $match
           }
           else
           {
                $Query = $ATTCKLookUp.Group
           }
        }
        if($PSCmdlet.ParameterSetName -eq 'Software'){
           if ($DynParam1.IsSet)
           {
                $Property = "Fulltext"
                $match = "$($DynParam1.value)"
                $Query = $ATTCKLookUp.Software| ? -Property $Property -eq $match
           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "ID"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -eq $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -eq $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "TechniqueID"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -eq $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "TechniqueName"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -eq $match
           }
           elseif ($DynParam6.IsSet)
           {
                $Property = "Type"
                $match = "$($DynParam6.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -eq $match
           }
           else
           {
                $Query = $ATTCKLookUp.Software
           }
        }
        if($PSCmdlet.ParameterSetName -eq 'Tactic'){
           if ($DynParam1.IsSet)
           {
                $Property = "Fulltext"
                $match = "$($DynParam1.value)"
                $Query = $ATTCKLookUp.Tactic| ? -Property $Property -eq $match
           }
           else
           {
                $Query = $ATTCKLookUp.Tactic
           }

        }
        if($PSCmdlet.ParameterSetName -eq 'Reference'){
           if ($DynParam1.IsSet)
           {
                $Property = "Fulltext"
                $match = "$($DynParam1.value)"
                $Query = $ATTCKLookUp.Reference| ? -Property $Property -eq $match
           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "Key"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -eq $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -eq $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "Author"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -eq $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "Date"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -eq $match
           }
           elseif ($DynParam6.IsSet)
           {
                $Property = "Year"
                $match = "$($DynParam6.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -eq $match
           }
           else
           {
                $Query = $ATTCKLookUp.Reference
           }
        }
        if($PSCmdlet.ParameterSetName -eq 'ATTACKMatrix'){
           $Techniques = $ATTCKLookUp.Technique 
        }
        if($PSCmdlet.ParameterSetName -eq 'ATTCKAttribution'){
           $hastechnique = $ATTCKLookUp.'Techniques subobjects'
           $groups = $ATTCKLookUp.Group
           $TechniquesList = $ATTCKLookUp.Technique                   
        }
        if($PSCmdlet.ParameterSetName -eq 'ATTCKAll'){
           $TechniquesList = $ATTCKLookUp.Technique
        }
    }
    Process
    {       
        If($PSCmdlet.ParameterSetName -eq 'SyncATTCK')
        {
            write-host "[++] Pulling MITRE ATT&CK Data" -ForegroundColor Yellow
            $Props = @{
                'Tactic' = $Null
                'Technique'= $Null
                'Group'= $Null
                'Software'= $Null
                'Reference'= $Null
                'Techniques subobjects'= $Null
            }

            $Script:ATTCKLookUp = New-Object PSCustomObject -Property $Props

            $categories = @('Tactic','Technique','Group','Software','Reference', 'Techniques subobjects')
    
            foreach ($cat in $categories)
            {
                write-host "`n[+++] Collecting $cat `n" -ForegroundColor Green
                if ($cat -eq 'Tactic'){$LookUpQuery = "[[Category:$cat]]|?Has description|?Citation reference|limit=9999"}
                elseif ($cat -eq 'Technique'){$LookUpQuery = "[[Category:$cat]]|?Has CAPEC ID|?Has ID|?Has analytic details|?Has contributor|?Has data source|?Has display name|?Has link text|?Has mitigation|?Has platform|?Has tactic|?Has technical description|?Has technique name|?Requires permissions|?Requires system|?Bypasses defense|?Citation reference|limit=9999"}
                elseif ($cat -eq 'Group'){$LookUpQuery = "[[Category:$cat]]|?Has ID|?Has alias|?Has description|?Has display name|?Has link text|?Has technique|?Uses software|?Citation reference|?Has URL|limit=9999"}
                elseif ($cat -eq 'Software'){$LookUpQuery = "[[Category:$cat]]|?Has ID|?Has alias|?Has description|?Has display name|?Has link text|?Has software type|?Has technique|?Citation reference|limit=9999"}
                elseif ($cat -eq 'Reference'){$LookUpQuery = "[[Citation text::+]]|?Citation key|?Citation text|?Has title|?Has authors|?Retrieved on|?Has URL|limit=9999"}
                elseif ($cat -eq 'Techniques subobjects'){$LookUpQuery = "[[Has technique object::+]]|?Has technique description|?Has technique object|limit=9999"}

                $LookUpURL = 'https://attack.mitre.org/api.php?action=ask&format=json&query='
                $LookUpEncQuery = [System.Net.WebUtility]::UrlEncode($LookUpQuery)
                $LookUpRequestURL = $LookUpURL + $LookUpEncQuery
                $reply = irm $LookUpRequestURL -Verbose        
                $results = (($reply.query.results | gm) | ?{$_.MemberType -eq 'NoteProperty'}).name | %{$reply.query.results.$_}
                
                $Collection =@()
                
                foreach ($object in $results)
                {                    
                    if($Cat -eq 'Technique'){
                        $Props = @{
                            'FullText' = $object.fulltext
                            'URL' = $object.fullurl
						    'CAPEC ID' = $object.printouts.'Has CAPEC ID'
                            'ID' = $object.printouts.'Has ID'
						    'Analytic Details' = $object.printouts.'Has analytic details'
						    'Contributor' = $object.printouts.'Has contributor'
						    'Data Source' = $object.printouts.'Has data source'
                            'Name' = $object.printouts.'Has display name'
						    'Link Text' = $object.printouts.'Has link text'
						    'Mitigation' = $object.printouts.'Has mitigation'
						    'Platform' = $object.printouts.'Has platform'
                            'Tactic' = $object.printouts.'Has tactic'.fulltext
                            'Description' = $object.printouts.'Has technical description'
						    'TechniqueName' = $object.printouts.'Has technique name'
						    'Requires Permission' = $object.printouts.'Requires permissions'
						    'Requires System' = $object.printouts.'Requires system'
                            'Bypass' = $object.printouts.'Bypasses defense'
                            'Reference' = $object.printouts.'Citation reference'
                            }
                            $TotalObjects = New-Object PSCustomObject -Property $Props
                            $Collection += $TotalObjects
                    }
                    if($Cat -eq 'Group'){
                        $Props = @{
                            'FullText' = $object.fulltext
                            'Display Title' = $object.displaytitle
                            'ID' = $object.printouts.'Has ID'
							'Alias' = $object.printouts.'Has alias'
							'Description' = $object.printouts.'Has Description'
                            'Name' = $object.printouts.'Has display name'
							'Link Text' = $object.printouts.'Has link text'
							'TechniqueName' = $object.printouts.'Has technique'.displaytitle
							'Tool' = $object.printouts.'Uses software'.displaytitle
                            'TechniqueID' = $object.printouts.'Has technique'.fulltext                         
							'URL' = $object.fullurl
                            'Reference' = $object.printouts.'Citation reference'
                        }   
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        $Collection += $TotalObjects
                    }
                    if($Cat -eq 'Software'){
                        $Props = @{
                            'FullText' = $object.fulltext
                            'ID' = $object.printouts.'Has ID'
							'Alias' = $object.printouts.'Has alias'
                            'Description' = $object.printouts.'Has Description'
							'Name' = $object.printouts.'Has display name'
							'Link Text' = $object.printouts.'Has link text'
							'Software Type' = $object.printouts.'Has software type'
                            'TechniqueName' = $object.printouts.'Has technique'.displaytitle
                            'Type' = $object.printouts.'Has software type'
							'TechniqueID' = $object.printouts.'Has technique'.fulltext
							'URL' = $object.fullurl
							'Reference' = $object.printouts.'Citation reference'
                        }
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        $Collection += $TotalObjects
                    }
                    if($Cat -eq 'Tactic'){
                        $Props = @{
                            'Reference' = $object.printouts.'Citation reference'
                            'URL' = $object.fullurl
                            'Description' = $object.printouts.'Has Description'
                            'FullText' = $object.fulltext
                        }
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        $Collection += $TotalObjects
                    }
                    if($Cat -eq 'Reference'){
                        $Props = @{
                            'Fulltext' = $object.fulltext
                            'Key' = $object.printouts.'Citation key'
                            'Text' = $object.printouts.'Citation text'
                            'Name' = $object.printouts.'Has title'
                            'Author' = $object.printouts.'Has authors'.fulltext
                            'Date' = $object.printouts.'Citation text'.replace('(v=ws.10)','').split('(')[1].split(')')[0]
                            'Year' = $object.printouts.'Citation text'.replace('(v=ws.10)','').split('(')[1].split(')')[0].split(',')[0]
                            'Retrieved' = $object.printouts.'Retrieved on'.fulltext
                            'URL' = $object.printouts.'Has URL'.fulltext
                        }
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        IF($TotalObjects.date -notmatch '\d\d\d\d'){$TotalObjects.date = 'n.d.'}
                        IF($TotalObjects.Year -notmatch '\d\d\d\d'){$TotalObjects.Year = 'n.d.'}
                        $Collection += $TotalObjects
                    }
                    if($cat -eq 'Techniques subobjects'){
                        $Props = @{
                            'Display Title' = $object.displaytitle
							'TechniqueName' = $object.printouts.'Has technique object'.displaytitle
                            'TechniqueID' = $object.printouts.'Has technique object'.Fulltext
                            'URL' = $object.printouts.'Has technique object'.Fullurl
                            'Description' =  $object.printouts.'Has technique description'
                        }
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        $Collection += $TotalObjects                   
                    }                              
                    $Script:ATTCKLookUp.$cat = $Collection    
                }
            }  
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ATTACKMatrix')
        {
            $MatrixProps = @{
                 'Persistence' = $Null
                 'PrivilegeEscalation' = $Null
                 'DefenseEvasion' = $Null
                 'CredentialAccess' = $Null
                 'Discovery' = $Null
                 'LateralMovement' = $Null
                 'Execution' = $Null
                 'Collection' = $Null
                 'Exfiltration' = $Null
                 'CommandControl' = $Null
            }
            $ATTACKMatrix = New-Object PSCustomObject -Property $MatrixProps
          
            $ATTACKMatrix.Persistence = $Techniques | ? -Property Tactic -eq "Persistence" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.PrivilegeEscalation = $Techniques | ? -Property Tactic -eq "Privilege Escalation" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.DefenseEvasion = $Techniques | ? -Property Tactic -eq "Defense Evasion" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.CredentialAccess = $Techniques | ? -Property Tactic -eq "Credential Access" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.Discovery = $Techniques | ? -Property Tactic -eq "Discovery"| select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.LateralMovement = $Techniques | ? -Property Tactic -eq "Lateral Movement" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.Execution = $Techniques | ? -Property Tactic -eq "Execution"| select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.Collection = $Techniques | ? -Property Tactic -eq "Collection" | select -ExpandProperty Name | Sort-Object          
            $ATTACKMatrix.Exfiltration = $Techniques | ? -Property Tactic -eq "Exfiltration" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.CommandControl = $Techniques | ? -Property Tactic -eq "Command and Control" | select -ExpandProperty Name | Sort-Object
            
            #Source: https://community.spiceworks.com/topic/795591-output-multiple-arrays-as-columns-in-csv
            #Source: https://stackoverflow.com/questions/23411202/powershell-combine-single-arrays-into-columns
            $max = (
                $ATTACKMatrix.Persistence,
                $ATTACKMatrix.PrivilegeEscalation,
                $ATTACKMatrix.DefenseEvasion,
                $ATTACKMatrix.CredentialAccess,
                $ATTACKMatrix.Discovery,
                $ATTACKMatrix.LateralMovement,
                $ATTACKMatrix.Execution,
                $ATTACKMatrix.Collection,
                $ATTACKMatrix.Exfiltration,
                $ATTACKMatrix.CommandControl | Measure-Object -Maximum -Property Count).Maximum

           $ATTACKMatrixTable = @()

           For ($i = 0; $i -lt $max; $i++)
           {
                $MatrixTableProps = New-Object Psobject -Property @{
                    'Persistence'= $(If ($ATTACKMatrix.Persistence[$i]) {$ATTACKMatrix.Persistence[$i]})
                    'Privilege Escalation'= $(If ($ATTACKMatrix.PrivilegeEscalation[$i]) {$ATTACKMatrix.PrivilegeEscalation[$i]})
                    'Defense Evasion'= $(If ($ATTACKMatrix.DefenseEvasion[$i]) {$ATTACKMatrix.DefenseEvasion[$i]})
                    'Credential Access'= $(If ($ATTACKMatrix.CredentialAccess[$i]) {$ATTACKMatrix.CredentialAccess[$i]})
                    'Discovery'= $(If ($ATTACKMatrix.Discovery[$i]) {$ATTACKMatrix.Discovery[$i]})
                    'Lateral Movement'= $(If ($ATTACKMatrix.LateralMovement[$i]) {$ATTACKMatrix.LateralMovement[$i]})
                    'Execution'= $(If ($ATTACKMatrix.Execution[$i]) {$ATTACKMatrix.Execution[$i]})
                    'Collection'= $(If ($ATTACKMatrix.Collection[$i]) {$ATTACKMatrix.Collection[$i]})
                    'Exfiltration'= $(If ($ATTACKMatrix.Exfiltration[$i]) {$ATTACKMatrix.Exfiltration[$i]})
                    'Command and Control'= $(If ($ATTACKMatrix.CommandControl[$i]) {$ATTACKMatrix.CommandControl[$i]})
                }
                $ATTACKMatrixTable += $MatrixTableProps
           }
           return $ATTACKMatrixTable
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ATTCKAttribution')
        {
            $AttriBucket = @()
            foreach ($g in $groups)
            {
                foreach ($grouptool in $g.tool)
                {
                    $AttriBucket += $hastechnique | where-object -Property 'Display Title' -EQ $grouptool | select @{Name='Group';Expression={$g.Name}}, @{Name='Group Alias'; Expression={$g.Alias}}, @{Name='Group ID'; Expression={$g.ID}}, TechniqueName, TechniqueID, @{Name='Tool'; Expression={$grouptool}}, description
                } 
                $AttriBucket += $hastechnique | where-object -Property 'Display Title' -EQ $g.'Display Title' | select @{Name='Group'; Expression={$g.Name}}, @{Name='Group Alias'; Expression={$g.Alias}}, @{Name='Group ID'; Expression={$g.ID}}, TechniqueName, TechniqueID, description
            }
                        
            $AttriFinal =@()
            foreach ($t in $TechniquesList)
            {
                $AttriFinal += $AttriBucket | Where-Object -Property TechniqueID -EQ $t.FullText | select Group, 'Group Alias', 'Group ID', @{Name='Tactic'; Expression={$t.Tactic}}, TechniqueName, TechniqueID, Tool, Description, @{Name='Data Source'; Expression={$t.'Data Source'}} 
            }           
            $AttriFinal | sort -Property Group
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ATTCKAll')
        {
            $AllAttck = @()
            $HasObject = Invoke-ATTACKAPI -Attribution       
            foreach ($t in $TechniquesList)
            {
                $AllAttck += $HasObject | Where-Object -Property TechniqueID -EQ $t.FullText | select Tactic, TechniqueName, TechniqueID, Group, 'Group Alias', 'Group ID', Tool, Description, 'Data Source', @{Name='Bypass'; Expression={$t.Bypass}}, @{Name='Analytic Details'; Expression={$t.'Analytic Details'}}, @{Name='Mitigation'; Expression={$t.Mitigation}},@{Name='Platform'; Expression={$t.Platform}},@{Name='Requires Permission'; Expression={$t.'Requires Permission'}}, @{Name='Requires System'; Expression={$t.'Requires System'}}, @{Name='Contributor'; Expression={$t.Contributor}}, @{Name='URL'; Expression={$t.URL}}   
            }
            $AllAttck += $TechniquesList | select Tactic, TechniqueName, @{Name='TechniqueID'; Expression={$_.FullText}}, Description, 'Data Source', Bypass, 'Analytic Details',Mitigation, Platform,'Requires Permission', 'Requires System','CAPEC ID', Contributor, URL 
            $AllAttck | sort -Property Tactic
        }
        else
        {
           return $Query
        }
    }
    End{}
}

write-host '

  /$$$$$$  /$$$$$$$$ /$$$$$$$$ /$$$      /$$$$$$  /$$   /$$        /$$$$$$  /$$$$$$$  /$$$$$$
 /$$__  $$|__  $$__/|__  $$__//$$ $$    /$$__  $$| $$  /$$/       /$$__  $$| $$__  $$|_  $$_/
| $$  \ $$   | $$      | $$  |  $$$    | $$  \__/| $$ /$$/       | $$  \ $$| $$  \ $$  | $$  
| $$$$$$$$   | $$      | $$   /$$ $$/$$| $$      | $$$$$/        | $$$$$$$$| $$$$$$$/  | $$  
| $$__  $$   | $$      | $$  | $$  $$_/| $$      | $$  $$        | $$__  $$| $$____/   | $$  
| $$  | $$   | $$      | $$  | $$\  $$ | $$    $$| $$\  $$       | $$  | $$| $$        | $$  
| $$  | $$   | $$      | $$  |  $$$$/$$|  $$$$$$/| $$ \  $$      | $$  | $$| $$       /$$$$$$
|__/  |__/   |__/      |__/   \____/\_/ \______/ |__/  \__/      |__/  |__/|__/      |______/ V.0.9[BETA]

            Adversarial Tactics, Techniques & Common Knowledge API' -ForegroundColor Magenta
write-host '
[*] Author: Roberto Rodriguez @Cyb3rWard0g

' -ForegroundColor Cyan
Invoke-ATTACKAPI -Sync
