# Hyper-V VM Templates
__Hyper-VVMTemplates__ is a PowerShell module that natively implements Windows Virtual Machine (VM) Templates on Hyper-V. VM Templates are pre-configured VM images tailored for rapid deployment. VM Templates typically include operating systems, drivers, applications, and configurations required for specific workloads. Additionally, the module provides functionality to create virtual machines with an automated installation from a Windows Product ISO.
## License
Copyright (c) 2025 Mason Wexler.  This software is licensed under the [MIT License](https://github.com/mhwexler/Hyper-VVMTemplates/blob/main/LICENSE).
## Module Functions
- __New-HvtNoPromptInstallISO__ - Convert a Windows Product ISO to not require user interaction to install Windows.  NoPrompt ISOs are required to fully automate Windows installation using AutoUnattend.xml files.
- __New-HvtVMTemplate__ - Convert a virtual machine into a VM Template by running Sysprep on the VM. The virtual machine
    is be deleted during the conversion.
- __New-HvtVirtualMachine__ - Create a new virtual machine and perform an automated Windows installation either using a
    Windows Product ISO or a VM Template (Sysprepped Windows OS .vhdx file).
- __Add-HvtVMDisk__ - Adds one or more virtual disks to a virtual machine.  This function is intended to facilitate adding
    multiple virtual disks in implement large storage spaces volumes.
- __New-HvtISO__ - Create an ISO from a folder using the Windows ADK Oscdimg utility.
- __Remove-HvtVMUnattendISO__ - Remove AutoUnattend.iso files and the virtual DVD drives that were used to perform an automated Windows installation by the New-HvtVirtualMachine function for all VMs on a Hyper-V server.  This function is intended to be configured to run on host servers as a scheduled task.

## Template Workbench Installation Procedure
This procedure documents the steps necessary to configure a workbench server and create the initial VM Templates. The workbench may be run on a physical server or a VM configured for [Nested Virtualization](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/enable-nested-virtualization). The server must have the Hyper-V Feature and the Microsoft Windows Assessment and Deployment Kit (ADK) installed and should have at least 2 Cores and 12 GB of memory.  It is recommended that a ReFS formatted volume is used to store the VM Templates and VMs to take advantage of ReFS Block Cloning.
|Step|Description|PowerShell Code|
| :------: | ------ | ------ |
| 1 | Install the Windows Hyper-V Feature.| `Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart` |
| 2 | Install the [Windows Assessment Toolkit (ADK)](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install) _Deployment Tools_| |
| 3 | Create the VM Switch.| `New-VMSwitch -Name 'Default Switch' -AllowManagementOS $true -NetAdapterName Ethernet` |
| 4 | Format the second drive using ReFS and create the VMs. VMTemplates, NoPromptISOs, and WindowsProductISOs folders. | `Initalize-Disk -Number 1 -PartitionStyle GPT` |
| | | `$Partition = New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter F` |
| | | `Format-Volume -Partition $Partition -FileSystem ReFS `|
| | | ` New-Item -Path F:\VMs -ItemType Directory` |
| | | `New-Item -Path F:\NoPromptISOs -ItemType Directory` |
| | | `New-Item -Path F:\VMTemplates -ItemType Directory` |
| | | `New-Item -Path F:\WindowsProductISOs -ItemType Directory` |
| 5 | Create the scheduled task to run __Remove-HvtVMUnattendISO__ every 15 minutes to clean up the Autounattend.iso files which may contain clear text passwords. | `$ScheduledTaskTrigger =  New-ScheduledTaskTrigger -Daily -At 00:00` |
| | | `$ScheduledTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command {-NoProfile -Command {F:\Scripts\Remove-VMUnattendISO -LogFilePath C:\Temp\VMUnattendISO.log}"` |
| | | `$ScheduledTask = Register-ScheduledTask -TaskName "Remove-HvtVMUnattendISO" -Trigger $ScheduledTaskTrigger -Action $ScheduledTaskAction -Description "Removes Autounattend.iso files and associated virtual DVDs" -RunLevel Highest -User 'SYSTEM'` |
| | | `$ScheduledTask.Triggers[0].Repetition.Interval = "PT15M"` |
| | | `$ScheduledTask.Triggers[0].Repetition.Duration = "P1D"` |
| 6 | Download the Windows Product ISOs for Windows Server 2025 and Windows 11 Enterprise to the F:\WindowsProductISOs folder. | `Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2293312&clcid=0x409&culture=en-us&country=us' -Destination F:\WindowsProductISOs\WindowsServer2025Eval.iso\` |
| | | `Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2289031&clcid=0x409&culture=en-us&country=us' -Destination F:\WindowsProductISOs\Windows11EnterpriseEval.iso` |
| 7 | Create the NoPromp ISOs which are required to fully automate the installation from Windows Product ISOs. | `New-HvtNoPromptInstallISO -WindowsISOPath F:\WindowsProductISOs\WindowsServer2025Eval.iso -NoPromptISODirectory F:\NoPromptISOs -Verbose` |
| | | `New-HvtNoPromptInstallISO -WindowsISOPath F:\WindowsProductISOs\Windows11EnterpriseEval.iso -NoPromptISODirectory F:\NoPromptISOs -Verbose` |
| 8 | Create the VMs that will be used to create the VM Templates. | `$AdministratorPassword = Read-Host -AsSecureString` |
 | | | `New-HvtVirtualMachine -VMName Srv2025StdGUI -VMTemplatePath F:\VMTemplates -OperatingSystem WindowsServer2025Standard -ServerOSVersion GUI -AdministratorPassword $AdministratorPassword -VMPath F:\VMs -SwitchName 'Default Switch' -Verbose` |
| | | `New-HvtVirtualMachine -VMName Win11Ent -VMTemplatePath F:\VMTemplates -OperatingSystem Windows11 -DesktopOSVersion Enterprise -AdministratorPassword $AdministratorPassword -VMPath F:\VMs -SwitchName 'Default Switch' -Verbose` |
| 9 | Logon to each of the VMs and download the latest patches from Microsoft.| |
| 10 | Create VMs to from the VM Templates to verify they are working properly. | `New-HvtVirtualMachine -VMName SERVER1 -VMPath F:\VMs -VMTemplatePath F:\VMTemplates\Srv2025StdGUI.vhdx -OperatingSystem WindowsServer2025Standard -ServerOSVersion GUI -AdministratorPassword $AdministratorPassword -SwitchName 'Default Switch' -TimeZone 'US Mountain Standard Time' -Verbose`
| | | `New-HvtVirtualMachine -VMName DESKTOP1 -VMPath F:\VMs -VMTemplatePath F:\VMTemplates\Win11Ent.vhdx -OperatingSystem Windows11 -DesktopOSVersion Enterprise -AdministratorPassword $AdministratorPassword -SwitchName 'Default Switch' -TimeZone 'US Eastern Standard Time' -Verbose` | 

## VM Creation Examples
| 1. Create a VM from a Product ISO and prompt for the Administrator password before logging on the first time. |
| :------ | 
| `New-HvtVirtualMachine -VMName SERVER2 -VMPath F:\VMs -WindowsInstallISO F:\NoPromptISOs\WindowsServer2025Eval_NoPrompt.iso -OperatingSystem WindowsServer2025Standard` |

| 2. Create a VM from a Product ISO and specify the Timezone (Administrator password is optional when VMs are created from Product ISOs) |
| :------ | 
| `$AdministratorPassword = Read-Host -AsSecureString` |
| `New-HvtVirtualMachine -VMName TESTVM1 -WindowsInstallISO C:\NoPromptISOs\WindowsServer2025Eval_NoPrompt.iso -OperatingSystem WidowsServer2025Standard -AdministratorPassword $AdministratorPassword` |

| 3. Create a VM from a Template (Administrator password is required when VMs are created from Templates) |
| :------ | 
| `$AdministratorPassword = Read-Host -AsSecureString` |
| `New-HvtVirtualMachine -VMName SERVER1 -VMPath F:\VMs -VMTemplatePath F:\VMTemplates\Srv2025StdGUI.vhdx -OperatingSystem WindowsServer2025Standard -ServerOSVersion GUI -AdministratorPassword $AdministratorPassword -SwitchName 'Default Switch' -TimeZone 'US Mountain Standard Time' -Verbose` |

| 4. Create a VM from a Template for Server Joined To A Domain |
| :------ |
| `$AdministratorPassword = Read-Host -AsSecureString` |
| `$DomainJoinCredential = Get-Credential` |
| `New-HvtVirtualMachine -VMName SERVER2  -OperatingSystem WindowsServer2025Standard -VMPath C:\ClusterStorage\Volume01\VMs -WindowsInstallISO C:\ClusterStorage\Volume01\NoPromptISOs\en-us_windows_server_2025_x64_dvd_b7ec10f3_NoPrompt.iso -TimeZone 'US Mountain Standard Time' -AdministratorPassword $AdministratorPassword -SwitchName PublicVMSwitch -EnableRemoteDesktop -DomainName dom1.com -DomainOUPath 'OU=Servers,OU=_DOM1,DC=dom1,DC=com' -DomainJoinCredential $DomainJoinCredential` |

| 5. Create a VM from a Template and specify the TCP/IP configuration |
| :------ |
| `$AdministratorPassword = Read-Host -AsSecureString` |
| `New-HvtVirtualMachine -VMName SERVER1 -VMPath F:\VMs -VMTemplatePath F:\VMTemplates\Srv2025StdGUI.vhdx -OperatingSystem WindowsServer2025Standard -AdministratorPassword $AdministratorPassword -IPAddress 192.168.1.2 -SubnetPrefix 24 -DefaultGateway 192.168.1.1 -DNSServers '8.8.8.8,4.4.4.4'
` |
## Usage Notes
1. The local Administrator and Domain Join Credential passwords as passed to functions as [SecureStrings](https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-security-securestring); however, they are unencrypted within the functions and stored in clear text in the Unattend.xml files.  While the Unattend.xml files are automatically erased, to mitigate the potential to be exploited by malicious attackers they should be tightly scoped and not shared.  In addition, local Administrator passwords should be changed on a regular basis using a password manager such as Microsoft’s free [Local Administrator Password Solution (LAPS)]( https://www.microsoft.com/en-us/download/details.aspx?id=46899&gt&msockid=11ce442110d26fae2654515411ad6eb1).
2. To implement automated installation of VMs from the Windows Product ISOs, the Autounnatend.xml file which may contain clear text passwords is converted into an ISO and mounted on the VM.  To ensure that these ISOs are erased from the VMs, a scheduled task should be configured on all hosts that runs the __Remove-HvtVMUnattendISO__ function.








