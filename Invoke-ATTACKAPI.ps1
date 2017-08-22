function Invoke-ATTACKAPI
{

<#
.Synopsis
A PS script to interact with the MITRE ATT&CK Framework via its own API

.Description
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


URL             : https://attack.mitre.org/wiki/Technique/T1001
ID              : {T1001}
Tactic          : Command and Control
AnalyticDetails : {Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a
                  server). Processes utilizing the network that do not normally have network communication or have never been seen befor
                  are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for
                  the port that is being used.University of Birmingham C2}
RequiresSystem  : {}
FullText        : Technique/T1001
Bypass          : {}
Name            : {Data Obfuscation}
Description     : {Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content
                  more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being see
                  This encompasses many methods, such as adding junk data to protocol traffic, using steganography, commingling legitima
                  traffic with C2 communications traffic, or using a non-standard data encoding system, such as a modified Base64 encodi
                  for the message body of an HTTP request.}
Mitigation      : {Network intrusion detection and prevention systems that use network signatures to identify traffic for specific
                  adversary malware can be used to mitigate activity at the network level. Signatures are often for unique indicators
                  within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and wi
                  likely be different across various malware families and versions. Adversaries will likely change tool C2 signatures ov
                  time or construct protocols in such a way as to avoid detection by common defensive tools.University of Birmingham C2}
Platform        : {Windows Server 2003, Windows Server 2008, Windows Server 2012, Windows XP...}
Reference       : {University of Birmingham C2, FireEye APT28, Axiom, FireEye APT30...}

URL             : https://attack.mitre.org/wiki/Technique/T1002
ID              : {T1002}
Tactic          : Exfiltration
AnalyticDetails : {Compression software and compressed files can be detected in many ways. Common utilities that may be present on the
                  system or brought in by an adversary may be detectable through process monitoring and monitoring for command-line
                  arguments for known compression utilities. This may yield a significant amount of benign events, depending on how
                  systems in the environment are typically used.

.EXAMPLE
This query matches the page Technique with ID T1014

Invoke-ATTACKAPI -Category -Technique -ID T1014

URL             : https://attack.mitre.org/wiki/Technique/T1014
ID              : {T1014}
Tactic          : Defense Evasion
AnalyticDetails : {Some rootkit protections may be built into anti-virus or operating system software. There are dedicated rootkit
                  detection tools that look for specific types of rootkit behavior. Monitor for the existence of unrecognized DLLs,
                  devices, services, and changes to the MBR.Wikipedia Rootkit}
RequiresSystem  : {}
FullText        : Technique/T1014
Bypass          : {Anti-virus, File monitoring, Host intrusion prevention systems, Process whitelisting...}
Name            : {Rootkit}
Description     : {Rootkits are programs that hide the existence of malware by intercepting and modifying operating system API calls t
                  supply system information. Rootkits or rootkit enabling functionality may reside at the user or kernel level in the
                  operating system or lower, to include a [[Technique/T1062|Hypervisor]], Master Boot Record, or the
                  [[Technique/T1019|System Firmware]].Wikipedia Rootkit

                  Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and ot
                  system components.}
Mitigation      : {Identify potentially malicious software that may contain rootkit functionality, and audit and/or block it by using
                  whitelistingBeechey 2010 tools, like AppLocker,Windows Commands JPCERTNSA MS AppLocker or Software Restriction
                  PoliciesCorio 2008 where appropriate.TechNet Applocker vs SRP}
Platform        : {Windows Server 2003, Windows Server 2008, Windows Server 2012, Windows XP...}
Reference       : {Wikipedia Rootkit, Beechey 2010, Windows Commands JPCERT, NSA MS AppLocker...}


.EXAMPLE
This query matches against all the group that use a specific software (in this case Cobalt Strike)
SYNTAX: "Software: <tool name>"

Invoke-ATTACKAPI -Category -Group -Tool "Software: Cobalt Strike"

URL           : https://attack.mitre.org/wiki/Group/G0050
Alias         : {APT32, OceanLotus Group}
ID            : {G0050}
Tool          : {Software: Cobalt Strike, Software: KOMPROGO, Software: WINDSHIELD, Software: SOUNDBITE...}
TechniqueID   : {Technique/T1053, Technique/T1117, Technique/T1086, Technique/T1094...}
FullText      : Group/G0050
Name          : {APT32}
Description   : {[[Group/G0050|APT32]] is a threat group that has been active since at least 2014. The group has targeted multiple private
                sector industries as well as with foreign governments, dissidents, and journalists. The group's operations are aligned
                with Vietnamese state interests.FireEye APT32 May 2017}
TechniqueName : {Scheduled Task, Regsvr32, PowerShell, Custom Command and Control Protocol...}
Reference     : {FireEye APT32 May 2017, GitHub Malleable C2, GitHub Invoke-Obfuscation}

.EXAMPLE
[BETA] Exporting custom results to a CSV

PS C:\HIVE\github\Invoke-ATTACKAPI> Invoke-ATTACKAPI -Category -Technique | where-object -Property ID -GE "T1134" | select @{Name="Name"; Ex
pression={$_.Name -join ","}}, @{Name="Tactic"; Expression={$_.Tactic -join ","}}, @{Name ="ID"; Expression={$_.ID -join ","}}, @{Name="Desc
ription"; Expression={$_.Description -join ","}}, @{Name="Analyticdetails"; Expression={$_.AnalyticDetails -join ","}}, @{Name="DataSource";
 Expression={$_.DataSource -join ","}}  | export-csv F:\wardog\scripts\demo6.csv -NoTypeInformation

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
Show up to date ATT&CK Matrix for Enterprise and export it to a CSV (Technique Names are retrieved as Strings)

Invoke-ATTACKAPI -Matrix | select Persistence, 'Privilege Escalation', 'Defense Evasion','Credential Access', Discovery, 'Lateral Movement', Execution, Collection, Exfiltration, 'Command and Control' | Export-Csv C:\wardog\scripts\matrix.csv -NoTypeInformation


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

    [CmdletBinding(DefaultParameterSetName='NoParam')]
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
        [switch]$Matrix   
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
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -Match $match

           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "ID"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -Match $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -Match $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "Tactic"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -Match $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "Platform"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Technique | ? -Property $Property -Match $match
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
                $Query = $ATTCKLookUp.Group| ? -Property $Property -Match $match
           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "ID"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -Match $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -Match $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "Alias"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -Match $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "TechniqueID"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -Match $match
           }
           elseif ($DynParam6.IsSet)
           {
                $Property = "TechniqueName"
                $match = "$($DynParam6.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -Match $match
           }
           elseif ($DynParam7.IsSet)
           {
                $Property = "Tool"
                $match = "$($DynParam7.value)"
                $Query = $ATTCKLookUp.Group | ? -Property $Property -Match $match
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
                $Query = $ATTCKLookUp.Software| ? -Property $Property -Match $match
           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "ID"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -Match $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -Match $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "TechniqueID"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -Match $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "TechniqueName"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -Match $match
           }
           elseif ($DynParam6.IsSet)
           {
                $Property = "Type"
                $match = "$($DynParam6.value)"
                $Query = $ATTCKLookUp.Software | ? -Property $Property -Match $match
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
                $Query = $ATTCKLookUp.Tactic| ? -Property $Property -Match $match
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
                $Query = $ATTCKLookUp.Reference| ? -Property $Property -Match $match
           }
           elseif ($DynParam2.IsSet)
           {
                $Property = "Key"
                $match = "$($DynParam2.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -Match $match
           }
           elseif ($DynParam3.IsSet)
           {
                $Property = "Name"
                $match = "$($DynParam3.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -Match $match
           }
           elseif ($DynParam4.IsSet)
           {
                $Property = "Author"
                $match = "$($DynParam4.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -Match $match
           }
           elseif ($DynParam5.IsSet)
           {
                $Property = "Date"
                $match = "$($DynParam5.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -Match $match
           }
           elseif ($DynParam6.IsSet)
           {
                $Property = "Year"
                $match = "$($DynParam6.value)"
                $Query = $ATTCKLookUp.Reference | ? -Property $Property -Match $match
           }
           else
           {
                $Query = $ATTCKLookUp.Reference
           }
        }
    }
    Process
    {       
        If($PSCmdlet.ParameterSetName -eq 'SyncATTCK')
        {
            write-host "[++] Pulling MITRE ATT&CK Data" -ForegroundColor Cyan
            $Props = @{
                'Tactic' = $Null
                'Technique'= $Null
                'Group'= $Null
                'Software'= $Null
                'Reference'= $Null
            }

            $Script:ATTCKLookUp = New-Object PSCustomObject -Property $Props

            $categories = @('Tactic','Technique','Group','Software','Reference')
    
            foreach ($cat in $categories)
            {
                write-host "`n[+++] Collecting $cat `n" -ForegroundColor Green
                if ($cat -eq 'Tactic'){$LookUpQuery = "[[Category:$cat]]|?Has description|?Citation reference|limit=9999"}
                elseif ($cat -eq 'Technique'){$LookUpQuery = "[[Category:$cat]]|?Has ID|?Has display name|?Has technical description|?Requires system|?Has mitigation|?Has analytic details|?Has tactic|?Has data source|?Bypasses defense|?Has platform|?Citation reference|limit=9999"}
                elseif ($cat -eq 'Group'){$LookUpQuery = "[[Category:$cat]]|?Has ID|?Has display name|?Has alias|?Has description|?Has technique|?Uses software|?Citation reference|?Has URL|limit=9999"}
                elseif ($cat -eq 'Software'){$LookUpQuery = "[[Category:$cat]]|?Has ID|?Has display name|?Has description|?Has technique|?Has platform|?Has software type|?Has software page|?Citation reference|limit=9999"}
                elseif ($cat -eq 'Reference'){$LookUpQuery = "[[Citation text::+]]|?Citation key|?Citation text|?Has title|?Has authors|?Retrieved on|?Has URL|limit=9999"}

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
                        'ID' = $object.printouts.'Has ID'
                        'Name' = $object.printouts.'Has display name'
                        'Tactic' = $object.printouts.'Has tactic'.fulltext
                        'Description' = $object.printouts.'Has technical description'
                        'Bypass' = $object.printouts.'Bypasses defense'
                        'Mitigation' = $object.printouts.'Has mitigation'
                        'RequiresSystem' = $object.printouts.'Requires system'
                        'AnalyticDetails' = $object.printouts.'Has analytic details'
                        'Platform' = $object.printouts.'Has platform'
                        'Reference' = $object.printouts.'Citation reference'
                        'DataSource' = $object.printouts.'Has data source'
                        }
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        $Collection += $TotalObjects
                    }
                    if($Cat -eq 'Group'){
                        $Props = @{
                            'FullText' = $object.fulltext
                            'URL' = $object.fullurl
                            'ID' = $object.printouts.'Has ID'
                            'Name' = $object.printouts.'Has display name'
                            'Alias' = $object.printouts.'Has alias'
                            'Description' = $object.printouts.'Has Description'
                            'TechniqueID' = $object.printouts.'Has technique'.fulltext
                            'TechniqueName' = $object.printouts.'Has technique'.displaytitle
                            'Reference' = $object.printouts.'Citation reference'
                            'Tool' = $object.printouts.'Uses software'.displaytitle
                            }
                        $TotalObjects = New-Object PSCustomObject -Property $Props
                        $Collection += $TotalObjects
                        }
                    if($Cat -eq 'Software'){
                        $Props = @{
                            'FullText' = $object.fulltext
                            'URL' = $object.fullurl
                            'ID' = $object.printouts.'Has ID'
                            'Name' = $object.printouts.'Has display name'
                            'Description' = $object.printouts.'Has Description'
                            'TechniqueID' = $object.printouts.'Has technique'.fulltext
                            'TechniqueName' = $object.printouts.'Has technique'.displaytitle
                            'Reference' = $object.printouts.'Citation reference'
                            'Type' = $object.printouts.'Has software type'
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
          
            $ATTACKMatrix.Persistence = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Persistence" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.PrivilegeEscalation = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Privilege Escalation" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.DefenseEvasion = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Defense Evasion" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.CredentialAccess = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Credential Access" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.Discovery = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Discovery"| select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.LateralMovement = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Lateral Movement" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.Execution = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Execution"| select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.Collection = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Collection" | select -ExpandProperty Name | Sort-Object          
            $ATTACKMatrix.Exfiltration = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Exfiltration" | select -ExpandProperty Name | Sort-Object
            $ATTACKMatrix.CommandControl = Invoke-ATTACKAPI -Category -Technique | ? -Property Tactic -Match "Command and Control" | select -ExpandProperty Name | Sort-Object
            
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
|__/  |__/   |__/      |__/   \____/\_/ \______/ |__/  \__/      |__/  |__/|__/      |______/


[*] Author: Roberto Rodriguez @Cyb3rWard0g
[*] Version: 0.9 [BETA]
' -ForegroundColor Magenta
Invoke-ATTACKAPI -Sync
