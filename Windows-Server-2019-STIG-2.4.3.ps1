#Create Secedit config file for editing
secedit /export /cfg C:\secpol.cfg
$SecEditCfg = Get-Content -Path C:\secpol.cfg

#Secedit function
function STIG-ComplianceSecEdit([String]$StringToFind, [String]$Replacement, [String]$Description){
    Write-Host $Description -BackgroundColor Black -ForegroundColor Magenta
    $NewString = $StringToFind + ".*"
    Write-Host "Editing line..." -BackgroundColor Black -ForegroundColor Yellow
    $global:SecEditCfg = $global:SecEditCfg -replace($NewString,$Replacement)
    Write-Host "Done..." -BackgroundColor Black -ForegroundColor Cyan
}

#Registry function
function STIG-ComplianceReg([String]$RegPath, [String]$Key, [String]$Value, [String]$Type, [String]$Description) {

    Write-Host $Description -BackgroundColor Black -ForegroundColor Magenta
    Write-Host "Checking if property exist." -BackgroundColor Black -ForegroundColor Magenta
    try {
        Get-ItemProperty -Path $RegPath -Name $Key -ErrorAction Stop
        Write-Host "Forcing registry value..." -BackgroundColor Black -ForegroundColor Yellow
        New-ItemProperty -Path $RegPath -Name $Key -PropertyType $Type -Value $Value -Force
        Write-Host "Done..." -BackgroundColor Black -ForegroundColor Cyan
    }
    
    catch [System.Management.Automation.ItemNotFoundException] {
        Write-Host "Registry Path does not exist.." -BackgroundColor Black -ForegroundColor Yellow
        Write-Host "Creating registiry path, key, and setting the value..." -BackgroundColor Black -ForegroundColor Yellow
        New-Item -Path $RegPath -Force
        New-ItemProperty -Path $RegPath -Name $Key -PropertyType $Type -Value $Value -Force
        Write-Host "Done..." -BackgroundColor Black -ForegroundColor Cyan
    }

    catch {
        Write-Host "Registry path found, but key not found or set..." -BackgroundColor Black -ForegroundColor Yellow
        Write-Host "Creating Key and Setting value..." -BackgroundColor Black -ForegroundColor Yellow
        New-ItemProperty -Path $RegPath -Name $Key -PropertyType $Type -Value $Value -Force
        Write-Host "Done..." -BackgroundColor Black -ForegroundColor Cyan
    }
}

#AuditPol function
function STIG-ComplianceAuditPolLogging([String]$SubCategory, [String]$Success, [String]$Failure, [String]$Description) {
    Write-Host $Description -BackgroundColor Black -ForegroundColor Magenta
    Write-Host "Forcing values..." -BackgroundColor Black -ForegroundColor Yellow
    auditpol /set /Subcategory:$SubCategory /success:$Success /failure:$Failure
    auditpol /get /Subcategory:$SubCategory
    Write-Host "Done..." -BackgroundColor Black -ForegroundColor Cyan
}

#This hash table will formated as such:
#V_NUMBER : [RegPath, Key, Value, Type, Description]
#V_NUMBER is the Stig Vulnerability Number
#RegPath is the Registry Path
#Key is the Key located at the RegPath
#Value is the value of the Key
#Type is the Key type
#Description is the V_NUMBER description from the STIG

$hashStigReg = [ordered]@{

    ################################################## CAT 1 Vulnerabilities ####################################################
    "205711" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client";
            Key = "AllowBasic";
            Value = "0";
            Type = "DWORD";
            Description = "Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.";
     };
     "205713" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
            Key = "AllowBasic";
            Value = "0";
            Type = "DWORD";
            Description = "Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.";
     };
     "205724" = [ordered]@{
            RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa";
            Key = "RestrictAnonymous";
            Value = "1";
            Type = "DWORD";
            Description = "Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.";
     };
     "205802" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer";
            Key = "AlwaysInstallElevated";
            Value = "0";
            Type = "DWORD";
            Description = "Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.";
     };
     "205804" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer";
            Key = "NoAutoplayfornonVolume";
            Value = "1";
            Type = "DWORD";
            Description = "Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon as media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. This setting will disable AutoPlay for non-volume devices, such as Media Transfer Protocol (MTP) devices.";
     };
     "205805" = [ordered]@{
            RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            Key = "NoAutorun";
            Value = "1";
            Type = "DWORD";
            Description = "Allowing AutoRun commands to execute may introduce malicious code to a system. Configuring this setting prevents AutoRun commands from executing.";
     };
     "205806" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            Key = "NoDriveTypeAutoRun";
            Value = "255";
            Type = "DWORD";
            Description = "Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. By default, AutoPlay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. Enabling this policy disables AutoPlay on all drives.";
     };
     "205919" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
            Key = "LmCompatibilityLevel";
            Value = "5";
            Type = "DWORD";
            Description = "The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to standalone or nondomain-joined computers that are running later versions.";
     };
     ################################################## CAT 2 Vulnerabilities ####################################################
     "205633" = [ordered]@{
            RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System";
            Key = "InactivityTimeoutSecs";
            Value = "900";
            Type = "DWORD";
            Description = "Unattended systems are susceptible to unauthorized use and should be locked when unattended. The screen saver should be set at a maximum of 15 minutes and be password protected. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.";
     };
     "205636" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services";
            Key = "fEncryptRPCTraffic";
            Value = "1";
            Type = "DWORD";
            Description = "Allowing unsecure RPC communication exposes the system to man-in-the-middle attacks and data disclosure attacks. A man-in-the-middle attack occurs when an intruder captures packets between a client and server and modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in the packets in an attempt to cause either the client or server to reveal sensitive information.";
     };
     "205637" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services";
            Key = "MinEncryptionLevel";
            Value = "3";
            Type = "DWORD";
            Description = "Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting 'High Level' will ensure encryption of Remote Desktop Services sessions in both directions.";
     };
     "205638" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
            Key = "ProcessCreationIncludeCmdLine_Enabled";
            Value = "1";
            Type = "DWORD";
            Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.";
     };
     "205639" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
            Key = "EnableScriptBlockLogging";
            Value = "1";
            Type = "DWORD";
            Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.";
     };
     "205644" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
            Key = "SCENoApplyLegacyAuditPolicy";
            Value = "1";
            Type = "DWORD";
            Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.";
     };
     "205651" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography";
            Key = "ForceKeyProtection";
            Value = "2";
            Type = "DWORD";
            Description = "If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure. The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.";
     };
     "205686" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization";
            Key = "NoLockScreenSlideshow";
            Value = "1";
            Type = "DWORD";
            Description = "Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged-on user.";
     };
     "205687" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest";
            Key = "UseLogonCredential";
            Value = "0";
            Type = "DWORD";
            Description = "When the WDigest Authentication protocol is enabled, plain-text passwords are stored in the Local Security Authority Subsystem Service (LSASS), exposing them to theft. WDigest is disabled by default in Windows Server 2019. This setting ensures this is enforced.";
     };
     "205688" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            Key = "DisableWebPnPDownload";
            Value = "1";
            Type = "DWORD";
            Description = "Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. This setting prevents the computer from downloading print driver packages over HTTP.";
     };
     "205689" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            Key = "DisableHTTPPrinting";
            Value = "1";
            Type = "DWORD";
            Description = "Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.";
     };
     "205690" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            Key = "DontDisplayNetworkSelectionUI";
            Value = "1";
            Type = "DWORD";
            Description = "Enabling interaction with the network selection UI allows users to change connections to available networks without signing in to Windows.";
     };
     "205692" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\System";
            Key = "EnableSmartScreen";
            Value = "1";
            Type = "DWORD";
            Description = "Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be malicious. Enabling SmartScreen can block potentially malicious programs or warn users.";
     };
     "205694" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search";
            Key = "AllowIndexingEncryptedStoresOrItems";
            Value = "0";
            Type = "DWORD";
            Description = "Indexing of encrypted files may expose sensitive data. This setting prevents encrypted files from being indexed.";
     };
     "205712" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client";
            Key = "AllowDigest";
            Value = "0";
            Type = "DWORD";
            Description = "Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential.";
     };
     "205714" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI";
            Key = "EnumerateAdministrators";
            Value = "0";
            Type = "DWORD";
            Description = "Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.";
     };
     "205715" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            Key = "LocalAccountTokenFilterPolicy";
            Value = "0";
            Type = "DWORD";
            Description = "A compromised local administrator account can provide means for an attacker to move laterally between domain systems. With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.";
     };
     "205717" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            Key = "ConsentPromptBehaviorAdmin";
            Value = "5";
            Type = "DWORD";
            Description = "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the elevation requirements for logged-on administrators to complete a task that requires raised privileges.";
     };
     "205722" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services";
            Key = "fDisableCdm";
            Value = "1";
            Type = "DWORD";
            Description = "Preventing users from sharing the local drives on their client computers with Remote Session Hosts that they access helps reduce possible exposure of sensitive data.";
     };
     "205747" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
            Key = "RestrictRemoteSAM";
            Value = "O:BAG:BAD:(A;;RC;;;BA)";
            Type = "STRING";
            Description = "The Windows SAM stores users' passwords. Restricting Remote Procedure Call (RPC) connections to the SAM to Administrators helps protect those credentials.";
     };
     "205796" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application";
            Key = "MaxSize";
            Value = "40000";
            Type = "DWORD";
            Description = "Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.";
     };
     "205797" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security";
            Key = "MaxSize";
            Value = "200000";
            Type = "DWORD";
            Description = "Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.";
     };
     "205798" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System";
            Key = "MaxSize";
            Value = "40000";
            Type = "DWORD";
            Description = "Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.";
     };
     "205801" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer";
            Key = "EnableUserControl";
            Value = "0";
            Type = "DWORD";
            Description = "Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.";
     };
     "205808" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
            Key = "DisablePasswordSaving";
            Value = "1";
            Type = "DWORD";
            Description = "Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client.";
     };
     "205809" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services";
            Key = "fPromptForPassword";
            Value = "1";
            Type = "DWORD";
            Description = "This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.";
     };
     "205810" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service";
            Key = "DisableRunAs";
            Value = "1";
            Type = "DWORD";
            Description = "Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.";
     };
     "205811" = [ordered]@{
            RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System";
            Key = "FilterAdministratorToken";
            Value = "1";
            Type = "DWORD";
            Description = "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.";
     };
     "205812" = [ordered]@{
            RegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System";
            Key = "ConsentPromptBehaviorUser";
            Value = "0";
            Type = "DWORD";
            Description = "User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting controls the behavior of elevation when requested by a standard user account.";
     };
     "205814" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc";
            Key = "RestrictRemoteClients";
            Value = "1";
            Type = "DWORD";
            Description = "Unauthenticated RPC clients may allow anonymous access to sensitive information. Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.";
     };
     "205816" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client";
            Key = "AllowUnencryptedTraffic";
            Value = "0";
            Type = "DWORD";
            Description = "Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.";
     };
     "205817" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service";
            Key = "AllowUnencryptedTraffic";
            Value = "0";
            Type = "DWORD";
            Description = "Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.";
     };
     "205825" = [ordered]@{
            RegPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters";
            Key = "RequireSecuritySignature";
            Value = "1";
            Type = "DWORD";
            Description = "The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.";
     };
     "205827" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters";
            Key = "RequireSecuritySignature";
            Value = "1";
            Type = "DWORD";
            Description = "The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will only communicate with an SMB client that performs SMB packet signing.";
     };
     "205828" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters";
            Key = "EnableSecuritySignature";
            Value = "1";
            Type = "DWORD";
            Description = "The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB server will negotiate SMB packet signing as requested by the client.";
     };
     "205863" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation";
            Key = "AllowProtectedCreds";
            Value = "1";
            Type = "DWORD";
            Description = "An exportable version of credentials is provided to remote hosts when using credential delegation which exposes them to theft on the remote host. Restricted Admin mode or Remote Credential Guard allow delegation of non-exportable credentials providing additional protection of the credentials. Enabling this configures the host to support Restricted Admin mode or Remote Credential Guard.";
     };
     "205866" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}";
            Key = "NoGPOListChanges";
            Value = "0";
            Type = "DWORD";
            Description = "Registry entries for group policy settings can potentially be changed from the required configuration. This could occur as part of troubleshooting or by a malicious process on a compromised system. Enabling this setting and then selecting the Process even if the Group Policy objects have not changed option ensures the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.";
     };
     "205867" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51";
            Key = "DCSettingIndex";
            Value = "1";
            Type = "DWORD";
            Description = "A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (on battery).";
     };
     "205868" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51";
            Key = "ACSettingIndex";
            Value = "1";
            Type = "DWORD";
            Description = "A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (plugged in).";
     };
     "205869" = [ordered]@{
            RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection";
            Key = "AllowTelemetry";
            Value = "0";
            Type = "DWORD";
            Description = "Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The Security option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. Basic sends basic diagnostic and usage data and may be required to support some Microsoft services.";
     };
     "205873" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds";
            Key = "DisableEnclosureDownload";
            Value = "1";
            Type = "DWORD";
            Description = "Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise. The Security option for Telemetry configures the lowest amount of data, effectively none outside of the Malicious Software Removal Tool (MSRT), Defender, and telemetry client settings. Basic sends basic diagnostic and usage data and may be required to support some Microsoft services.";
     };
     "205906" = [ordered]@{
            RegPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            Key = "CachedLogonsCount";
            Value = "4";
            Type = "String";
            Description = "The default Windows configuration caches the last logon credentials for users who log on interactively to a system. This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable. Even though the credential cache is well protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain.";
     };
     "205912" = [ordered]@{
            RegPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
            Key = "SCRemoveOption";
            Value = "1";
            Type = "String";
            Description = "Unattended systems are susceptible to unauthorized use and must be locked. Configuring a system to lock when a smart card is removed will ensure the system is inaccessible when unattended.";
     };
     "205916" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
            Key = "UseMachineId";
            Value = "1";
            Type = "DWORD";
            Description = "Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity.";
     };
     "205917" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
            Key = "AllowNullSessionFallback";
            Value = "0";
            Type = "DWORD";
            Description = "NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.";
     };
     "205918" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u";
            Key = "AllowOnlineID";
            Value = "0";
            Type = "DWORD";
            Description = "PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.";
     };
     "205921" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
            Key = "NTLMMinClientSec";
            Value = "537395200";
            Type = "DWORD";
            Description = "Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.";
     };
     "205922" = [ordered]@{
            RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
            Key = "NTLMMinServerSec";
            Value = "537395200";
            Type = "DWORD";
            Description = "Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.";
     };

     ################################################## CAT 3 Vulnerabilities ####################################################
     "205691" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat";
            Key = "DisableInventory";
            Value = "1";
            Type = "DWORD";
            Description = "Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.";
     };
     "205819" = [ordered]@{
            RegPath = "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters";
            Key = "NoNameReleaseOnDemand";
            Value = "1";
            Type = "DWORD";
            Description = "Configuring the system to ignore name release requests, except from WINS servers, prevents a denial of service (DoS) attack. The DoS consists of sending a NetBIOS name release request to the server for each entry in the server's cache, causing a response delay in the normal operation of the server's WINS resolution capability.";
     };
     "205858" = [ordered]@{
            RegPath = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters";
            Key = "DisableIPSourceRouting";
            Value = "2";
            Type = "DWORD";
            Description = "Configuring the system to disable IPv6 source routing protects against spoofing.";
     };
     "205859" = [ordered]@{
            RegPath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters";
            Key = "DisableIPSourceRouting";
            Value = "2";
            Type = "DWORD";
            Description = "Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled, this forces ICMP to be routed via the shortest path first.";
     };
     "205860" = [ordered]@{
            RegPath = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters";
            Key = "EnableICMPRedirect";
            Value = "0";
            Type = "DWORD";
            Description = "Allowing ICMP redirect of routes can lead to traffic not being routed properly. When disabled, this forces ICMP to be routed via the shortest path first.";
     };
     "205870" = [ordered]@{
            RegPath = "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization";
            Key = "DODownloadMode";
            Value = "1";
            Type = "DWORD";
            Description = "Windows Update can obtain updates from additional sources instead of Microsoft. In addition to Microsoft, updates can be obtained from and sent to PCs on the local network as well as on the Internet. This is part of the Windows Update trusted process, however to minimize outside exposure, obtaining updates from or sending to systems on the Internet must be prevented.";
     };
};

#AuditPol hash table
#Subcategories can be found with /auditpol /list /subcategory:* /V
#GUID's are used because you can't trust scripts with spaces if you can avoid it
#Formated as V_NUMBER : SubCategory, Success, Failure, Description
#V_Number is the STIG vulnerability number
#SubCategory is the GUID provided by the auditpol command above
#Success and Failure will be set to "enable" or "disable" and corrospond to auditpol's settings
#Description is the V_NUMBER description from the STIG

$hashStigAuditPolLogging = [ordered]@{
    "205627" = [ordered]@{
        SubCategory = "{0CCE9235-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.";
    };
    "205730" = [ordered]@{
        SubCategory = "{0CCE9217-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling user accounts.";
    };
    "205769" = [ordered]@{
        SubCategory = "{0CCE923A-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Other Account Management Events records events such as the access of a password hash or the Password Policy Checking API being called.";
    };
    "205770" = [ordered]@{
        SubCategory = "{0CCE922B-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Process Creation records events related to the creation of a process and the source.";
    };
    "205772" = [ordered]@{
        SubCategory = "{0CCE922F-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Audit Policy Change records events related to changes in audit policy.";
    };    
    "205774" = [ordered]@{
        SubCategory = "{0CCE9231-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Authorization Policy Change records events related to changes in user rights, such as 'Create a token object'.";
    };
    "205775" = [ordered]@{
        SubCategory = "{0CCE9228-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Sensitive Privilege Use records events related to use of sensitive privileges, such as 'Act as part of the operating system' or 'Debug programs'.";
    };
    "205776" = [ordered]@{
        SubCategory = "{0CCE9228-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Sensitive Privilege Use records events related to use of sensitive privileges, such as 'Act as part of the operating system' or 'Debug programs'.";
    };
    "205777" = [ordered]@{
        SubCategory = "{0CCE9213-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. IPsec Driver records events related to the IPsec Driver, such as dropped packets.";
    };
    "205778" = [ordered]@{
        SubCategory = "{0CCE9213-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. IPsec Driver records events related to the IPsec Driver, such as dropped packets.";
    };
    "205782" = [ordered]@{
        SubCategory = "{0CCE9211-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Security System Extension records events related to extension code being loaded by the security subsystem.";
    };
    "205833" = [ordered]@{
        SubCategory = "{0CCE923F-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Credential Validation records events related to validation tests on credentials for a user account logon.";
    };
    "205836" = [ordered]@{
        SubCategory = "{0CCE9227-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects.";
    };
    "205837" = [ordered]@{
        SubCategory = "{0CCE9227-69AE-11D9-BED3-505054503030}";
        Success = "enable";
        Failure = "enable";
        Description = "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior. Auditing for other object access records events related to the management of task scheduler jobs and COM+ objects.";
    };
};

#Security Edits hash table
#The cfg file is generated earlier in the script
#I think it's a inf file, but oh well
#Formated as V_NUMBER : StringToFind, Replacement, Description
#V_Number is the STIG vulnerability number
#StringToFind is the string it is looking for in the cfg file
#Replacement is the replacement text
#Description is the V_NUMBER description from the STIG

$hashStigSecurityEdits = [ordered]@{
    "205629" = [ordered]@{
        StringToFind = "LockoutBadCount";
        Replacement = "LockoutBadCount = 3";
        Description = "The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack while allowing for honest errors made during normal user logon.";
    };
    "205659" = [ordered]@{
        StringToFind = "MaximumPasswordAge =";
        Replacement = "MaximumPasswordAge = 60";
        Description = "The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.";
    };
    "205660" = [ordered]@{
        StringToFind = "PasswordHistorySize";
        Replacement = "PasswordHistorySize = 24";
        Description = "The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords. Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.";
    };
    "205662" = [ordered]@{
        StringToFind = "MinimumPasswordLength";
        Replacement = "MinimumPasswordLength = 11";
        Description = "Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.";
    };
};


foreach ($hashStigKey in $hashStigReg.Keys) {
    STIG-ComplianceReg -RegPath $hashStigReg.$hashStigKey.Item("RegPath") -Key $hashStigReg.$hashStigKey.Item("Key") -Value $hashStigReg.$hashStigKey.Item("Value") -Type $hashStigReg.$hashStigKey.Item("Type") -Description $hashStigReg.$hashStigKey.Item("Description")
}

foreach ($hashStigKey in $hashStigAuditPolLogging.Keys) {
    STIG-ComplianceAuditPolLogging -SubCategory $hashStigAuditPolLogging.$hashStigKey.Item("SubCategory") -Success $hashStigAuditPolLogging.$hashStigKey.Item("Success") -Failure $hashStigAuditPolLogging.$hashStigKey.Item("Failure") -Description $hashStigAuditPolLogging.$hashStigKey.Item("Description")
}

foreach ($hashStigKey in $hashStigSecurityEdits.Keys) {
    STIG-ComplianceSecEdit -StringToFind $hashStigSecurityEdits.$hashStigKey.Item("StringToFind") -Replacement $hashStigSecurityEdits.$hashStigKey.Item("Replacement") -Description $hashStigSecurityEdits.$hashStigKey.Item("Description")
}

$SecEditCfg #Display the output
$SecEditCfg > C:\secpol_1.cfg
secedit /validate C:\secpol_1.cfg
if($? -eq $True) {
    #C:\Windows\security\local.sdb is the default secedit database
    secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol_1.cfg
}
if($? -eq $True) {
    Remove-Item C:\secpol.cfg -Force
    Remove-Item C:\secpol_1.cfg -Force
}

#One offs
#V-205685 - Uninstall Powershell 2.0
Uninstall-WindowsFeature -Name PowerShell-v2
