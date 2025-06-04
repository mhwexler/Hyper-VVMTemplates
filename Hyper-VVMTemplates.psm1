#requires -RunAsAdministrator

# Copyright © 2025 Mason Wexler
#
# This software is licened under the The MIT License (MIT) - https://mit-license.org/
#
# All functionality is implemented in the Hyper-VVMTemplate.psm1 module which must be run on a Windows Server that has the Windows
# Hyper-V feature and the Windows Assessment Toolkit (ADK) for Windows Server 2022 installed.
#
# To configure a server to implement VM Templates,
#   - Install the Hyper-V Feature.
#   - Install the Windows ADK for Windows Server 2022.
#   - Import the Hyper-VVMTemplate module.
#   - Set up folders for the Windows product ISOs, NoPrompt ISOs, and virtual machines.  It is highly recommended that these folders
#     be on a volume formatted with ReFS in order to take advantage of Block cloning which reduces that time and disk space used
#     copying VM Templates.
#   - Download the Microsoft Windows product ISOs.
#   - Create the NoPrompt ISOs from the Windows Product ISOs.
#   - Create the Windows VMs used to create the VM Templates.  The VMs may be patched and configured with any desired settings.
#   - Create the VM Templates from the Template VMs.
#   - Set up the Remove-HvtVMUnattendISO function as a schedule task to remove unneeded DVD drives from VMs erase autounattend.iso files which may contain
#     clear text passwords.

function New-HvtNoPromptInstallISO {
<#
    .SYNOPSIS
    Convert a Windows Installation ISO to not require user interaction to install Windows.

    .DESCRIPTION
    Convert a Windows Product ISO to not require user interaction to install Windows.  NoPrompt ISOs
    are required to fully automate Windows installation using AutoUnattend.xml files. The Windows Installation
    ISO is unpacked into a folder that will remain after the function completes.

    .PARAMETER WindowsISOPath
    Specifies the path to the Windows Installation ISO.

    .PARAMETER NoPromptISODirectory
    Specifies the directory where the new Windows Installation NoPrompt ISO is created.

    .PARAMETER LogFilePath
    Specifies the path of the log file.

    .EXAMPLE
    PS>New-HvtNoPromptInstallISO -WindowsISOPath C:\Software\en-us_windows_server_2025.iso -NoPromptISODirectory C:\NoPromptISOs
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WindowsISOPath,

        [Parameter(Mandatory)]
        [string]$NoPromptISODirectory,

        [string]$LogFilePath=''
    )

    Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

    if ( !(Test-Path -Path $WindowsISOPath) ) {
        throw "Windows ISO $WindowsISOPath not found"
    }
    if ( !(Test-Path -Path $NoPromptISODirectory) ) {
        throw "Destination NoPromptISO directory $NoPromptISODirectory not found"
    }

    # Make sure OSCDIMG is installed
    $OscdimgPath = Get-HvtOscdimgPath
    if ($OscdimgPath -eq '') {
        throw 'The Windows Assessment and Deployment Kit (Windows ADK) must be installed before running this script'
    }

    # Get the new ISO name and working directory (create or recreate the working directory if necessary)
    $NewWindowsISOName = [System.IO.Path]::GetFileNameWithoutExtension($WindowsISOPath)
    $NewWindowsISOPath = "$NoPromptISODirectory\$($NewWindowsISOName)_NoPrompt.iso"
    $NewWindowsImageCSVPath = "$NoPromptISODirectory\$($NewWindowsISOName)_NoPrompt.csv"
    $NewISOSourceDirectory = "$NoPromptISODirectory\$NewWindowsISOName"
    if ( !(Test-Path -Path $NoPromptISODirectory)) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Creating NoPrompt ISO Directory $NoPromptISODirectory"
        New-Item -Path $NoPromptISODirectory -ItemType Directory | Out-Null
    }

     # Mount the windows install ISO
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Mounting Windows Installation ISO $WindowsISOPath"
    Mount-DiskImage -ImagePath  $WindowsISOPath -ErrorAction Stop | Out-Null

    # Mount the volume and save get the drive letter
    $MountDriveLetter  = Get-DiskImage -ImagePath  $WindowsISOPath | Get-Volume | Select-Object -ExpandProperty DriveLetter
    $MountPath = "$($MountDriveLetter):\"

    # Copy the ISO to a temporary folder
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Unpacking Windows Installation ISO to $NewISOSourceDirectory"
    robocopy.exe $MountPath $NewISOSourceDirectory /mir

    # Dismount the Source ISO
    Dismount-DiskImage -ImagePath $WindowsISOPath | Out-Null

    # Create a companion .csv file for the NoPrompt ISO identifying the images
    $WindowsImage = Get-WindowsImage -ImagePath "$NewISOSourceDirectory\sources\install.wim" | Select-Object -Property ImageIndex,ImageName,ImageDescription,ImageSize
    $WindowsImage | Export-Csv -Path $NewWindowsImageCSVPath -NoTypeInformation

    # Create the new ISO
    $BootData = "2#p0,e,b`"$OscdimgPath\etfsboot.com`"#pEF,e,b`"$OscdimgPath\efisys_noprompt.bin`""
    $ProcArgList = @(
        "-bootdata:$BootData",
        '-u2',
        '-udfver102',
        "`"$NewISOSourceDirectory`"",
        "`"$NewWindowsISOPath`""
    )

    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Creating Windows NoPrompt Installation ISO $NewWindowsISOPath"
    $Proc = Start-Process -FilePath "$OscdimgPath\oscdimg.exe" -ArgumentList $ProcArgList -PassThru -Wait -WindowStyle Normal
    if($Proc.ExitCode -ne 0)
    {
        Throw "Failed to generate ISO with ExitCode: $($Proc.ExitCode)"
    }

}

function New-HvtVMTemplate {
<#
    .SYNOPSIS
    Convert a virtual machine into a VM Template.

    .DESCRIPTION
    Convert a virtual machine into a VM Template by running Sysprep on the VM. The virtual machine
    is be deleted during the conversion.

    .PARAMETER VMName
    Specifies the name of the VM to be converted to a VM Template.

    .PARAMETER TemplateDirectory
    Specifies the directory to copy the VM Template to.

    .PARAMETER Credential
    Specifies the user and password of the Administrator account on the VM.

    .PARAMETER LogFilePath
    Specifies the path of the log file.

    .EXAMPLE
    PS>$Credential = Get-Credential
    PS>New-HvtVMTemplate -VMName VM1 -TemplateName WindowsServer2025StdGUI -TemplateDirectory C:\VMTemplates -Credential $Credential -Confirm $false
#>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName,

        [Parameter(Mandatory=$true)]
        [string]$TemplateName,

        [string]$TemplateDirectory = 'C:\VMTemplates',
        [PSCredential]$Credential,
        [string]$LogFilePath=''
    )

    Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

    # Make sure VM is exists and is powered off
    $VM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($null -eq $VM) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM $VMName doesn't exists"
        return
    }
    if ($VM.State -notin 'Off','Saved') {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message  "VM $VMName must be powered off"
        return
    }

    # Make sure the OS hard drive exists
    $OSHardDrive = $VM.HardDrives | Where-Object {$_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0}
    if ($null -eq $OSHardDrive) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM $VMName OS hard disk not found"
        return
    }

    # Get the credential if it wasn't entered
    if ($null -eq $Credential) {
        $Credential = Get-Credential -Message "Enter the administrator credential for VM $VMName" -UserName Administrator
        if ($null -eq $Credential) {return}
    }

    # Make sure no VMCheckpoints exist
    $VMCheckpoints = Get-VMSnapshot -VMName $VMName
    if ( !($null -eq $VMCheckpoints) ) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "Remove all checkpoints from $VMName before running this script"
        return
    }

    # Make sure it's OK to delete the VM
    if( !$PSCmdlet.ShouldProcess($VMName,'Convert VM to VM Template')){
        return
    }

    # Start the VM
    Write-Verbose -Message "Starting VM $VMName"
    Start-VM -VMName $VMName
    Start-Sleep -Seconds 6

    # Create a PowerShell Session
    for ([int]$Count=1; $Count -le 20; $Count++) {
        Start-Sleep -Milliseconds 500
        $VMSession = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction SilentlyContinue
        if ($null -ne $VMSession) {break}
    }
    if ($null -eq $VMSession) {throw "Unable to create a PowerShell Session to $VMName"}

    # Remove WidgetsPlatformRuntime which causes Sysprep to fail and then invoke sysprep on the VM
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message 'Removing AppPackages which cause Sysprep to fail'
    Invoke-Command -Session $VMSession -ScriptBlock {$ProgressPreference = 'SilentlyContinue'}
    Invoke-Command -Session $VMSession -ScriptBlock {Get-AppPackage | Where-Object Name -in Microsoft.WidgetsPlatformRuntime,Microsoft.BingSearch,Microsoft.Copilot,Microsoft.Edge.GameAssist | Remove-AppPackage}
    Invoke-Command -Session $VMSession -ScriptBlock {Write-Progress "Done" "Done" -Completed}

    # Run Sysprep on the VM
    Write-Host -Object "Starting Sysprep of VM $VMName; the Sysprep operation will take a while to complete..."
    #$Job = Invoke-Command -Session $VMSession -ScriptBlock {c:\Windows\system32\cmd.exe /C C:\Windows\System32\Sysprep\sysprep.exe /generalize /shutdown /oobe} -AsJob

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-Command -Session $VMSession -ScriptBlock {c:\Windows\system32\cmd.exe /C C:\Windows\System32\Sysprep\sysprep.exe /generalize /shutdown /oobe}

    # Wait for the Sysprep to complete
    #$EstimatedSeconds = 60*7 # 7 Minutes

   

    $ElapsedTime = $Stopwatch.Elapsed
    $StatusMessage = [string]::Format("Sysprep of $VMName Completed; Elapsed Time {0:d2}:{1:d2}:{2:d2}", $ElapsedTime.Hours, $ElapsedTime.Minutes, $ElapsedTime.Seconds)
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message $StatusMessage

    # Delete the VM
    Remove-PSSession -Session $VMSession

    # Wait for VM to shutdown
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message  "Waiting for VM $VMName to shutdown"

    do {
        Start-Sleep -Seconds 1
        $VM = Get-VM -Name $VMName
    } until ($VM.State -eq 'Off')
    $ElapsedTime = $Stopwatch.Elapsed

    # Check the status of the Sysprep by mounting the VM virtual disk and looking at the sysprep status file
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Mounting VM $VMName C: drive to access Sysprep log"
    $TemporaryDirectory = New-HvtTemporaryDirectory
    $MountDisk = Mount-VHD -Path $OSHardDrive.Path -NoDriveLetter -PassThru
    $MountVolume =  $MountDisk | Get-Partition | Where-Object Type -eq 'Basic'
    Add-PartitionAccessPath -InputObject $MountVolume -AccessPath $TemporaryDirectory
    $SysprepSucceeded = Test-Path -Path "$TemporaryDirectory\Windows\System32\Sysprep\Sysprep_succeeded.tag"
    $SysprepErrorLog = Get-Content -Path "$TemporaryDirectory\Windows\System32\Sysprep\Panther\setuperr.log"
    Dismount-VHD -Path $OSHardDrive.Path
    Remove-Item -Path $TemporaryDirectory
    if ( !$SysprepSucceeded ) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message 'Sysprep failed, VM Template not created.'
        Write-Host -Object $SysprepErrorLog
        return
    }

    $StatusMessage = [string]::Format("Shutdown of $VMName Completed; Elapsed Time {0:d2}:{1:d2}:{2:d2}", $ElapsedTime.Hours, $ElapsedTime.Minutes, $ElapsedTime.Seconds)
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message $StatusMessage

    # Create the template folder if it doesn't exist
    if ( !(Test-Path -Path $TemplateDirectory) ) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Creating VM Template folder $TemplateDirectory"
        New-Item -Path $TemplateDirectory -ItemType Directory | Out-Null
    }

    # Move the  OS Hard Drive to the Template Destination
    $TemplateFilePath = "$TemplateDirectory\$TemplateName.vhdx"
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Moving the VM virtual disk to $TemplateFilePath"
    Move-Item -Path $OSHardDrive.Path -Destination $TemplateFilePath -Force

    if ( !(Test-Path -Path $TemplateFilePath) ) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "Error moving VM $VMName OS disk to '$TemplateDirectory\$TemplateName.vhdx'"
        return
    }

    # Delete VM and the hard drives
    Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Deleting VM $VMName"
    Remove-VM -VMName $VMName -Force

    $HardDrives = $VM.HardDrives
    foreach ($HardDrives in $OtherHardDrives) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Deleting virtual disk $($OtherHardDrive.Path)"
        Remove-Item -Path $OtherHardDrive.Path -Force | Out-Null
    }

    # Remove the VM Folder with any ISOs that were left laying around
    Remove-Item -Path $VM.Path -Force -Recurse
}

Function New-HvtVirtualMachine {
<#
    .SYNOPSIS
    Create a new virtual machine and perform an automated Windows installation.

    .DESCRIPTION
    Create a new virtual machine and perform an automated Windows installation either using a
    Windows Product ISO or a VM Template (Sysprepped Windows OS .vhdx file).

    .PARAMETER VMName
    Specifies the name of the VM to be created.

    .PARAMETER VMTemplatePath
    Specifies the path of the VM Template .vhdx file to be used to create the VM.

    .PARAMETER WindowsInstallISO
    Specifies the path of the Windows installation ISO to be used to

    .PARAMETER OperatingSystem
    Specifies the name of the VM Operating System.

    .PARAMETER ServerOSVersion
    Specifies the type of the Windows Server Operating System (Core or GUI).

    .PARAMETER DesktopOSVersion
    Specifies the type of the Windows Desktop Operating System (Enterprise, EnterpriseLTSC,Education, or Pro). Other
    Windows 10/11 OS types can be selected by specifying the Windows Image Number.

    .PARAMETER WindowsImageNumber
    Specifies the image number for the image on the Windows Installation ISO (defaults based on the
    Operating System specified).

    .PARAMETER OSDiskSizeBytes
    Specifies the size for the VM hard disk the OS will be installed on (defaults to 140GB).

    .PARAMETER EnableRemoteDesktop
    Configured Remote Desktop to be enabled on the VM (only supported when installing from a Windows
    Installation ISO.

    .PARAMETER AdministratorPassword
    Sets the initial Administrator password. If this parameter is not specified, the user will prompted
    by the Windows installation process to enter a password at first logon.  Note that the password is
    entered in clear text in the unattend.xml file so the password should be changed after the installation
    process is complete.

    .PARAMETER TimeZone
    Specifies the time zone of the computer.  For a list of available time zones, use tzutil /l

    .PARAMETER VMPath
    Specifies the directory where the VM will be created. Note that the VM will be created in a dedicated
    VM directory and the virtual disk will be created in the VirtualDisks subdirectory.

    .PARAMETER SwitchName
    Specifies the virtual switch used for virtual network adapter. If this parameter is not specified,
    then the virtual network adapter will not be connected to a network.

    .PARAMETER HighlyAvailable
    Specifies the VM will be configured to be on a cluster.  Note that this parameter requires that the VM
    be stored on a Cluster Shared Volume.

    .PARAMETER MemoryStartupBytes
    Specifies the initial VM memory size. Dynamic memory is configured by default which will allow the
    memory size to increase if needed.

    .PARAMETER StaticMemory
    Specifies the VM should be configured with static memory instead of dynamic memory.

    .PARAMETER ProcessorCount
    Specifies the number of virtual processors to be allocated to the VM.

    .PARAMETER EnableTPM
    Enables TPM functionality on a virtual machine.

    .PARAMETER IPAddress
    Specifies that a static IP address should be configured on the VM.

    .PARAMETER SubnetPrefix
    Specifies the subnet prefix to be used when configuring a static IP address (defaults to 24).

    .PARAMETER DefaultGateway
    Specifies the default gateway to be used when configuring a static IP address.

    .PARAMETER DNSServers
    Specifies the DNS servers to be configured for both a static IP address or DHCP configuration.

    .PARAMETER DomainName
    Specifies that the VM should be joined to a domain. If DomainName is specified, DomainOUPath and
    DomainJoinCredential must also be specified).

    .PARAMETER DomainOUPath
    Specifies the OU path where the VM computer account will be created when it is joined to the Domain.

    .PARAMETER DomainJoinCredential
    Specifies the credential used to join the VM to the Domain. Note that the password is entered in
    clear text in the unattend.xml file so it should be configured with the least privileges necessary
    to join the computer to the Domain.

    .PARAMETER NoStart
    Specifies the VM should be not be started to initiate the automated Windows installation.

    .PARAMETER LogFilePath
    Specifies the path of the log file.

    .EXAMPLE
    PS>$AdministratorPassword = Read-Host -AsSecureString
    PS>New-HvtVirtualMachine -VMName TESTVM1 -WindowsInstallISO C:\NoPromptISOs\WindowsServer2025Eval_NoPrompt.iso -OperatingSystem WindowsServer2025Standard -AdministratorPassword $AdministratorPassword
#>
    [CmdLetBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName='VMTemplatePath')]
        [Parameter(Mandatory, ParameterSetName='WindowsInstallISO')]
        [ValidateLength(1,15)]
        [string]$VMName,

        [Parameter(Mandatory)]
        [string]$VMPath,

        [Parameter(Mandatory=$false, ParameterSetName='VMTemplatePath')]
        [string]$VMTemplatePath,

        [Parameter(Mandatory, ParameterSetName='WindowsInstallISO')]
        [string]$WindowsInstallISO,

        [Parameter(Mandatory)]
        [ValidateSet('WindowsServer2025Standard','WindowsServer2025Datacenter','WindowsServer2022Standard','WindowsServer2022Datacenter','WindowsServer2019Standard','WindowsServer2019Datacenter','Windows10','Windows11')]
        [string]$OperatingSystem,

        [ValidateSet('Core','GUI')]
        [string]$ServerOSVersion = 'GUI',

        [ValidateSet('Enterprise','EnterpriseLTSC','Education','Pro')]
        [string]$DesktopOSVersion = 'Pro',

        [Parameter(Mandatory=$false, ParameterSetName='WindowsInstallISO')]
        [string]$WindowsImageNumber='',

        [Parameter(Mandatory=$false, ParameterSetName = 'WindowsInstallISO')]
        [UInt64]$OSDiskSizeBytes=140GB,

        [Parameter(Mandatory=$false, ParameterSetName='WindowsInstallISO')]
        [switch]$EnableRemoteDesktop,

        # Optional parameters
        [SecureString]$AdministratorPassword,
        [string]$TimeZone='',
        [string]$ProductKey='',
        [string]$SwitchName='',
        [switch]$HighlyAvailable,
        [Int64]$MemoryStartupBytes=1GB,
        [switch]$StaticMemory,
        [Int64]$ProcessorCount=1,
        [switch]$EnableTPM,
        [string]$IPAddress='',
        [string]$SubnetPrefix='',
        [string]$DefaultGateway='',
        [string]$DNSServers='',
        [string]$DomainName='',
        [string]$DomainOUPath='',
        [PSCredential]$DomainJoinCredential,
        [switch]$NoStart,
        [string]$LogFilePath=''
    )

    Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

     # Perform parameter validation
    if ($PSCmdlet.ParameterSetName -eq 'VMTemplatePath') {
        if ( !(Test-Path -Path $VMTemplatePath) ) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM Template $VMTemplatePath not found"
            return
        }
        if (!$VMTemplatePath.EndsWith('.vhdx')) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM Template $VMTemplatePath is not a .vhdx file"
            return
        }
        if ($null -eq $AdministratorPassword) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message  'AdministratorPassword is required when the Sysprep option is specified'
            return
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'WindowsInstallISO') {
        if ( !(Test-Path -Path $WindowsInstallISO) ) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "Windows Install ISO $WindowsInstallISO not found"
            return
        }
        if (!$WindowsInstallISO.EndsWith('.iso')) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "Windows Install ISO $WindowsInstallISO is not a .iso file"
            return
        }
    }

    if ($DomainName -ne '' -and ($DomainOUPath -eq '' -or $null -eq $DomainJoinCredential)) {
        Write-HvtMessage -LogFilePath $FilePath -WriteWaring -Message 'If DomainName is specified DomainOUPath and DomainJoinCredential are required'
        return
    }
    if ($IPAddress -ne '' -and $SubnetPrefix -eq '') {
        Write-HvtMessage -LogFilePath $FilePath -WriteWaring -Message 'SubnetPrefix must be specified if IPAddress is'
        return
    }

    # Calculate the default Generic Volume License Key and Image Number
    if ($OperatingSystem -like 'WindowsServer*') {
        $FullOperatingSystemName = $OperatingSystem + $ServerOSVersion
    }
    else {
        $FullOperatingSystemName = $OperatingSystem + $DesktopOSVersion
    }

    switch ($FullOperatingSystemName) {
            WindowsServer2025StandardCore    {$DefaultProductKey = 'TVRH6-WHNXV-R9WG3-9XRFY-MY832'; $DefaultWindowsImageNumber = '1'}
            WindowsServer2025StandardGUI     {$DefaultProductKey = 'TVRH6-WHNXV-R9WG3-9XRFY-MY832'; $DefaultWindowsImageNumber = '2'}
            WindowsServer2025DatacenterCore  {$DefaultProductKey = 'D764K-2NDRG-47T6Q-P8T8W-YP6DF'; $DefaultWindowsImageNumber = '3'}
            WindowsServer2025DatacenterGUI   {$DefaultProductKey = 'D764K-2NDRG-47T6Q-P8T8W-YP6DF'; $DefaultWindowsImageNumber = '4'}
            WindowsServer2022StandardCore	 {$DefaultProductKey = 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H'; $DefaultWindowsImageNumber = '1'}
            WindowsServer2022StandardGUI	 {$DefaultProductKey = 'VDYBN-27WPP-V4HQT-9VMD4-VMK7H'; $DefaultWindowsImageNumber = '2'}
            WindowsServer2022DatacenterCore	 {$DefaultProductKey = 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33'; $DefaultWindowsImageNumber = '3'}
            WindowsServer2022DatacenterGUI	 {$DefaultProductKey = 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33'; $DefaultWindowsImageNumber = '4'}
            WindowsServer2019StandardCore	 {$DefaultProductKey = 'N69G4-B89J2-4G8F4-WWYCC-J464C'; $DefaultWindowsImageNumber = '1'}
            WindowsServer2019StandardGUI	 {$DefaultProductKey = 'N69G4-B89J2-4G8F4-WWYCC-J464C'; $DefaultWindowsImageNumber = '2'}
            WindowsServer2019DatacenterCore  {$DefaultProductKey = 'WMDGN-G9PQG-XVVXX-R3X43-63DFG'; $DefaultWindowsImageNumber = '3'}
            WindowsServer2019DatacenterGUI   {$DefaultProductKey = 'WMDGN-G9PQG-XVVXX-R3X43-63DFG'; $DefaultWindowsImageNumber = '4'}
            Windows10Enterprise              {$DefaultProductKey = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'; $DefaultWindowsImageNumber = '1'}
            Windows10EnterpriseLTSC          {$DefaultProductKey = 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'; $DefaultWindowsImageNumber = '1'}
            Windows10Education               {$DefaultProductKey = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'; $DefaultWindowsImageNumber = '4'}
            Windows10Pro                     {$DefaultProductKey = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'; $DefaultWindowsImageNumber = '6'}
            Windows11Enterprise              {$DefaultProductKey = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'; $DefaultWindowsImageNumber = '1'}
            Windows11EnterpriseLTSC          {$DefaultProductKey = 'M7XTQ-FN8P6-TTKYV-9D4CC-J462D'; $DefaultWindowsImageNumber = '1'}
            Windows11Education               {$DefaultProductKey = 'NW6C2-QMPVW-D7KKK-3GKT6-VCFB2'; $DefaultWindowsImageNumber = '4'}
            Windows11Pro                     {$DefaultProductKey = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'; $DefaultWindowsImageNumber = '6'}
        }

    # Default Product Key Windows Image Number if they weren't specified
    if ($ProductKey -eq '') {
        $ProductKey = $DefaultProductKey
    }
    if ($WindowsImageNumber -eq '') {
        $WindowsImageNumber = $DefaultWindowsImageNumber
    }

    # Make sure Oscdimg is installed if this is VM is created from an install ISO
    if ($PSCmdlet.ParameterSetName -eq 'WindowsInstallISO') {
        $OscdimgPath = Get-HvtOscdimgPath
        if ($OscdimgPath -eq '') {
            Write-HvtMessage -LogFilePath $FilePath -WriteWaring -Message 'The Windows Assessment and Deployment Kit (Windows ADK) must be installed before running this script'
            return
        }
    }

    # Default Windows 11 to minimum requirements (TPM, 4GB, and 2 Processors)
    if ($OperatingSystem -eq 'Windows11') {
        if ($MemoryStartupBytes -lt 4GB) {$MemoryStartupBytes = 4GB}
        if ($ProcessorCount -lt 2) {$ProcessorCount = 2}
    }

    # Make sure HighlyAvailable VMs are on a cluster volume
    if ($HighlyAvailable.IsPresent) {
        $ClusterSharedVolumes = Get-ClusterSharedVolume | Select-Object -ExpandProperty SharedVolumeInfo | Select-Object -ExpandProperty FriendlyVolumeName
        if ($VMPath -notin $ClusterSharedVolumes) {
            Write-HvtMessage -LogFilePath $FilePath -WriteWaring -Message "VMPath $VMPath must be on a Cluster Shared Volume for HighlyAvailable VMs"
            return
        }
    }

    # If VMPath is a network share, make sure it exists
    if ($VMPath.StartsWith('\\')) {
        if ( !(Test-Path -Path $VMPath) ) {
            Write-HvtMessage -LogFilePath $FilePath -WriteWaring 'Network share VMPath $VMPath is not accessible'
            return
        }
    }
    else {
        # Create the VMPath directory if it doesn't exist
        if ( !(Test-Path -Path $VMPath) ) {
            New-Item -Path $VMPath -ItemType Directory | Out-Null
        }
    }

    # Create the VirtualDisks directory if it doesn't exist
    if ( !(Test-Path -Path "$VMPath\VirtualDisks") ) {
        New-Item -Path "$VMPath\VirtualDisks" -ItemType Directory | Out-Null
    }

    # Make sure the VM doesn't already exist
    $VM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($null -ne $VM) {
        Write-HvtMessage -LogFilePath $FilePath -WriteWaring -Message "VM $VMName already exists"
        return
    }

    # Make virtual disk doesn't already exist
    $VHDPath = "$VMPath\VirtualDisks\$($VMName)_DISK_00.vhdx"
    if (Test-Path -Path $VHDPath) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM Virtual Disk $VHDPath already exists"
        return
    }

    # Allow VM to be created without connecting to a switch
    $SplatArguments = @{
        Name = $VMName
        MemoryStartupBytes = $MemoryStartupBytes
        Path = $VMPath
        Generation = 2
        NoVHD = $true
    }
    if ($SwitchName -ne '') {
        $SplatArguments.Add('SwitchName',$SwitchName)
    }

    # Create the VM
    Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message "Creating VM $VMName"
    $VM = New-VM @SplatArguments

    # Set the additional VM settings (ProcessorCount, StaticMemory)
    if ($ProcessorCount -ne 1) {
        Set-VM -Name $VMName -ProcessorCount $ProcessorCount
    }
    if ($StaticMemory.IsPresent) {
        Set-VM -Name $VMName -StaticMemory
    }
    else {
        Set-VM -Name $VMName -DynamicMemory
    }

    Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false

    # Enable the TPM if requested or Windows 11
    if ($EnableTPM.IsPresent -or $OperatingSystem -like 'Windows11*') {
        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message 'Enabling Virtual TPM'
        Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
        Enable-VMTPM -VMName $VMName
    }

    # Process WindowsInstallISO (add blank hard disk, OS install DVD, and AutoUnattend.xml DVD)
    if ($PSCmdlet.ParameterSetName -eq 'WindowsInstallISO') {

        # Create and add the C Drive
        New-VHD -Path $VHDPath -SizeBytes $OSDiskSizeBytes -Dynamic | Out-Null
        Add-VMHardDiskDrive -VMName $VMName -Path $VHDPath -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0

        # Add the DVD with the OS ISO and set the boot order to boot from the CD
        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message "Mounting the Windows Installation ISO $WindowsInstallISO"
        $DVD = Add-VMDvdDrive -VMName $VMName -ControllerNumber 0 -ControllerLocation 63 -Path $WindowsInstallISO -Passthru
        Set-VMFirmware -VMName $VMName -FirstBootDevice $DVD

        # Create the AutoUnattend iso
        $ISOPath = "$VMPath\$VMName\autounattend.iso"
        $TempFolderPath = New-HvtTemporaryDirectory
        $TempUnattendXMLPath = "$TempFolderPath\autounattend.xml"
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Creating Unattend.xml file $TempUnattendXMLPath"
        New-HvtUnattendXMLFile -WindowsInstallISO -FilePath $TempUnattendXMLPath -ComputerName $VMName -OperatingSystem $OperatingSystem -WindowsImageNumber $WindowsImageNumber -ProductKey $ProductKey -AdministratorPassword $AdministratorPassword -IPAddress $IPAddress -SubnetPrefix $SubnetPrefix -DefaultGateway $DefaultGateway -DNSServers $DNSServers -DomainName $DomainName -DomainOUPath $DomainOUPath -DomainJoinCredential $DomainJoinCredential -EnableRemoteDesktop $EnableRemoteDesktop -TimeZone $TimeZone

        # Create the ISO and mount it to the VM
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Creating Unattend ISO $ISOPath"
        $ISOCreated = New-HvtISO -SourcePath $TempFolderPath -ISOPath $ISOPath
        if (!$ISOCreated) {
            throw "Error creating ISO"
        }
        Remove-Item -Path $TempFolderPath -Recurse

        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message 'Mounting the Windows AutoUnattend.xml ISO to SCSI controller location 62'
        Add-VMDvdDrive -VMName $VMName -ControllerNumber 0 -ControllerLocation 62 -Path $ISOPath
    }

    # Process VMTemplatePath (add blank hard disk, OS install DVD, and AutoUnattend.xml DVD)
    else {

        # Copy the Template virtual disk and add it to the VM
        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message 'Copying the Sysprepped virtual disk to the VM'
        Copy-HvtFile -Path $VMTemplatePath -Destination $VHDPath

        # Mount the VM Template File that was copied as the VM hard disk
        $VMHardDiskDrive = Add-VMHardDiskDrive -VMName $VMName -ControllerNumber 0 -ControllerLocation 0 -Path $VHDPath -ControllerType SCSI -Passthru
        Set-VMFirmware -VMName $VMName -FirstBootDevice $VMHardDiskDrive

        $TemporaryDirectory = New-HvtTemporaryDirectory
        $MountDisk = Mount-VHD -Path $VHDPath -NoDriveLetter -PassThru
        $MountVolume =  $MountDisk | Get-Partition | Where-Object Type -eq 'Basic'
        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message 'Mounting $VHDPath to mount point $TemporaryDirectory'
        Add-PartitionAccessPath -InputObject $MountVolume -AccessPath $TemporaryDirectory

        # Inject the unattend.xml file to configure the template VM when it is started
        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message 'Injecting the Unattend.xml file into the VM'
        # New-HvtUnattendXMLFile -Sysprep -FilePath "$TemporaryDirectory\Windows\System32\Sysprep\unattend.xml" -ComputerName $VMName -AdministratorPassword $AdministratorPassword -ProductKey $ProductKey -IPAddress $IPAddress -SubnetPrefix $SubnetPrefix -DefaultGateway $DefaultGateway -DNSServers $DNSServers -OperatingSystem $OperatingSystem -DomainName $DomainName -DomainOUPath $DomainOUPath -DomainJoinCredential $DomainJoinCredential
        $FilePath =  "$TemporaryDirectory\Windows\System32\Sysprep\unattend.xml"
        New-HvtUnattendXMLFile -Sysprep -FilePath $FilePath -ComputerName $VMName -OperatingSystem $OperatingSystem -AdministratorPassword $AdministratorPassword -IPAddress $IPAddress -SubnetPrefix $SubnetPrefix -DefaultGateway $DefaultGateway -DNSServers $DNSServers -DomainName $DomainName -DomainOUPath $DomainOUPath -DomainJoinCredential $DomainJoinCredential -EnableRemoteDesktop $EnableRemoteDesktop -TimeZone $TimeZone
        Dismount-VHD -Path $VHDPath
        Remove-Item -Path $TemporaryDirectory
    }

    if ($HighlyAvailable.IsPresent) {
        Write-HvtMessage -LogFilePath $FilePath -WriteVerbose -Message 'Setting the VM to be Highly Available'
        Add-ClusterVirtualMachineRole -VMName $VMName
    }

    # Start the VM and wait for the installation to complete
    if ( !$NoStart.IsPresent) {
        Start-VM -VMName $VMName
        Write-HvtMessage -LogFilePath $LogFilePath -WriteHost -ForegroundColor Cyan -Message "Virtual Machine $VMName created and started"
    }
    else {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteHost -ForegroundColor Cyan -Message "Virtual Machine $VMName created and left powered off"
    }
}

function Add-HvtVMDisk {
<#
    .SYNOPSIS
    Adds virtual disks to a virtual machine.

    .DESCRIPTION
    Adds one or more virtual disks to a virtual machine.  This function is intended to facilitate adding
    multiple virtual disks in implement large storage spaces volumes.

    .PARAMETER VMName
    Specifies the name of the VM to add virtual disks to.

    .PARAMETER DiskSizeBytes
    Specifies the size of the virtual disks.

    .PARAMETER NumberDisks
    Specifies the number of virtual disks to be added.

    .PARAMETER LogFilePath
    Specifies the path of the log file.

    .EXAMPLE
    PS>Add-HvtVMDisk -VMName VM1 -DiskSizeBytes 200GB -NumberDisks 6
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VMName,

        [long]$DiskSizeBytes=100GB,
        [byte]$NumberDisks=1,
        [string]$LogFilePath=''
    )

    Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

    # Make sure VM exists
    $VM = Get-VM -Name $VMName -ErrorAction Ignore
    if ($null -eq $VM) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM $VMName does not exist"
        return
    }

    # Find free SCSI Controller Locations
    $UsedSCSILocations = Get-VMScsiController -VMName $VMName -ControllerNumber 0 | Select-Object -ExpandProperty Drives | Select-Object -ExpandProperty ControllerLocation
    $FreeSCSILocations = 2..60 | Where-Object {$_ -notin $UsedSCSILocations}
    if ($NumberDisks -gt $FreeSCSILocations.Count) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "There are not enough SCSI Controller ports available to add $($NumberDisks.Count) virtual disks"
        return
    }

    # Get the path for the virtual disks
    $VHDDirectoryPath = $VM.HardDrives | Select-Object -First 1 -ExpandProperty Path | Split-Path -Parent

    # Add the hard disks
    for ([int]$Count = 0; $Count -lt $NumberDisks; $Count++) {
        $ControllerLocation = $FreeSCSILocations[$Count]
        $VHDPath = "$VHDDirectoryPath\$($VMName)_DISK_$($ControllerLocation.ToString().PadLeft(2,'0')).vhdx"
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Adding virtual disk $VHDPath"
        New-VHD -Path $VHDPath -SizeBytes $DiskSizeBytes -Dynamic | Out-Null
        Add-VMHardDiskDrive -VMName $VMName -Path $VHDPath -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $ControllerLocation
    }
}

function New-HvtISO {
<#
    .SYNOPSIS
    Creates an ISO from a folder.

    .DESCRIPTION
    Create an ISO from a folder using the Windows ADK Oscdimg utility.

    .PARAMETER SourcePath
    Specifies the path to the directory containing the files used to create the ISO.

    .PARAMETER ISOPath
    Specifies the path where the ISO is created.

    .PARAMETER LogFilePath
    Specifies the path of the log file.

    .OUTPUTS
    Returns a boolean value indicating whether or not the ISO was successfully created.

    .EXAMPLE
    PS>New-HvtISO -SourcePath C:ISOSource -ISOPath C:\Temp\NewISO.iso
#>

    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,

        [Parameter(Mandatory=$true)]
        [string]$ISOPath,

        [string]$LogFilePath=''
    )

    Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

    # Make sure OSCDIMG is installed
    $OscdimgPath = Get-HvtOscdimgPath
    if ($OscdimgPath -eq '') {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message 'The Windows Assessment and Deployment Kit (ADK) must be installed before running this script'
        return $false
    }

    # Make sure source directory exists
    if (!(Test-Path -Path $SourcePath -PathType Container)) {
        Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Source directory $SourcePath not found"
        return $false
    }

    # Make sure we can delete the existing ISO (want a more meaningful error then just having OSCDIMG fail)
    if (Test-Path -Path $ISOPath) {
        Remove-Item -Path $ISOPath -ErrorAction SilentlyContinue -ErrorVariable RemoveItemError
        if ($RemoveItemError.Count -ge 1) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Unable to remove old ISO file : $($RemoveItemError[0].Exception.Message)"
            return false
        }
    }

    # Create the ISO file
    $ProcArgList = @(
        '-u2',
        '-udfver102',
        "`"$SourcePath`"",
        "`"$ISOPath`""
    )

    $Proc = Start-Process -FilePath "$OscdimgPath\oscdimg.exe" -ArgumentList $ProcArgList  -PassThru -Wait -WindowStyle Normal
    if($Proc.ExitCode -ne 0) {
        Throw "Failed to generate ISO with ExitCode: $($Proc.ExitCode)"
    }
    return $true
}

function Remove-HvtVMUnattendISO {
<#
    .SYNOPSIS
    Removes AutoUnattend.iso files and their associated virtual DVD drives.

    .DESCRIPTION
    Remove AutoUnattend.iso files and the virtual DVD drives that were used to perform an automated
    Windows installation by the New-HvtVirtualMachine function for all VMs on a Hyper-V server.  This
    fuction is intended to be configured to run on host servers as a scheduled task.

    .PARAMETER LogFilePath
    Specifies the path of the log file.
#>
    param (
        [string]$LogFilePath=''
    )

    Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

    # Remove the second DVD drive used for the unattend.xml file
    $VMs = Get-VM
    foreach ($VM in $VMs) {

        # Remove the unattend DVD once the ISO is ejected as part of the unattend.xml process
        $UnattendDVD = $VM.DVDDrives | Where-Object ControllerLocation -eq 62
        if ($null -ne $UnattendDVD -and $UnattendDVD.Path -ne '') {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Removing SCSI controller number 62 from VM $VM.Name"
            $UnattendDVD | Remove-VMDvdDrive
        }

        # Delete the unattend.xml ISO from the VM (it can't be deleted until it is ejected)
        $AutoUnattendIsoPath = "$($VM.Path)\autounattend.iso"
        Remove-Item -Path $AutoUnattendIsoPath -ErrorAction SilentlyContinue -ErrorVariable RemoveError
        if ($RemoveError.Count -eq 0) {
            Write-HvtMessage -LogFilePath $LogFilePath -WriteVerbose -Message "Deleting AutoUnattend ISO $AutoUnattendIsoPath"
        }
    }
}

######################################################################################
# Internal Functions
######################################################################################

function New-HvtTemporaryDirectory {
<#
    .SYNOPSIS
    Creates a new Temporary Directory.

    .DESCRIPTION
    Creates a new Temporary Directory in the in the user's AppData\Temp folder using a GUID to
    make sure it is unique.  Temporary Directories should be deleted after they are no longer
    needed.  Note that the directory will be prefixed with HVMTemplate.

    .EXAMPLE
    PS>$TemporaryDirectory = New-HvtTemporaryDirectory
#>
$TempRootFolder = [System.IO.Path]::GetTempPath()
    $TempSubfolderName = "HVMTemplate-$((New-Guid).ToString("N"))"
    $TempSubfolderPath =  $TempRootFolder + $TempSubfolderName
    New-Item -ItemType Directory -Path $TempSubfolderPath | Out-Null
    return $TempSubfolderPath
}

function Get-HvtOscdimgPath {
    <#
    .SYNOPSIS
    Gets the location of the directory containing Oscdimg.

    .DESCRIPTION
    Gets the location of the directory containing Oscdimg

     which is the Windows ADK utility to create ISOs.
    If the Windows ADK wasn't installed, then the server is checked to see if if the VMMLite (Virtual Machine
    Management Lite) was installed locally.

    .EXAMPLE
    PS>$TemporaryDirectory = New-HvtTemporaryDirectory
#>
    # If the Windows ADK was installed, get the path of the Oscdimg directory
    $ADKProperties = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots\' -ErrorAction Ignore
    if ($null -ne $ADKProperties.KitsRoot10) {
        $OscdimgPath = "$($ADKProperties.KitsRoot10)Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"
        if ( Test-Path -Path $OscdimgPath) {
            return $OscdimgPath
        }
    }

    # If the Windows ADK wasn't installed, check to see if Oscdimg was copied locally by VMMLite
    $VMMLiteProperties = Get-ItemProperty -Path 'HKLM:\SOFTWARE\VMMLite' -ErrorAction Ignore
    if ($null -ne  $VMMLiteProperties) {
        $LocalInstallDirectory = $VMMLiteProperties.LocalInstallDirectory
        $OscdimgPath = "$LocalInstallDirectory\Oscdimg"
        if (Test-Path -Path "$OscdimgPath\oscdimg.exe") {
            return $OscdimgPath
        }
    }

    # It is a critical error if Oscdimg isn't available
    throw 'The Windows ADK must be installed or the Oscdimg utility must be installed on the VMMLite Library share'
}


function Copy-HvtFile {
<#
    .SYNOPSIS
    Copy a file.

    .DESCRIPTION
    Copy a file using BITS Transfer to show the progress unless both the source and destination are on a ReFS
    formatted volume to take advantage of ReFs Block cloning

    .PARAMETER Path
    Specifies the path of the source file to be copied.

    .PARAMETER Destination
    Specifies the destination path where the source file to copied to.

    .EXAMPLE
    PS>Copy-HvtFile -Path C:\ClusterStorage\Volume01\VMTemplates\WindowsServer2025StandardGUI.vhdx -Destination C:\ClusterStorage\Volume01\VMs\VirtualDisks\VM1_DISK_00.vhdx
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    # Get the source volume
    $OSDriveLetter = "$env:windir" | Split-Path -Parent
    if ($Path -like "$($OSDriveLetter)ClusterStorage\Volume*") {
        $Pos1 = $Path.IndexOf('\',3)
        $Pos2 = $Path.IndexOf('\',$Pos1+1)
        $SourceVolumePath = $Path.Substring(0,$Pos2)
        $SourceVolume = Get-Volume -FilePath $SourceVolumePath
    }
    else {
        $DriveLetter = $Path.Substring(0,1)
        $SourceVolumePath = $DriveLetter + ":\"
        $SourceVolume = Get-Volume -DriveLetter $Path.Substring(0,1)
    }

    # Get the destination volume
    if ($Destination -like "$($OSDriveLetter)ClusterStorage\Volume*") {
        $Pos1 = $Destination.IndexOf('\',3)
        $Pos2 = $Destination.IndexOf('\',$Pos1+1)
        $DestinationVolumePath = $Path.Substring(0,$Pos2)
        #$DestinationVolume = Get-Volume -FilePath $DestinationVolumePath
    }
    else {
        $DriveLetter = $Path.Substring(0,1)
        $DestinationVolumePath = $DriveLetter + ":\"
        #$DestinationVolume = Get-Volume -DriveLetter $Path.Substring(0,1)
    }

    # Perform a regular copy to leverage ReFS Cloning of the source and the destination are on the same ReFS formatted volume
    if ($SourceVolumePath -eq $DestinationVolumePath -and $SourceVolume.FileSystemType -in 'ReFS','CSVFS_ReFS') {
            Copy-Item -Path $Path -Destination $Destination
    }
    else {
            Copy-HvtFileUsingBitsTransfer -Source $Path -Destination $Destination
    }
}

function Copy-HvtFileUsingBitsTransfer {

<#
    .SYNOPSIS
    Copy a file using BITS Transfer.

    .DESCRIPTION
    Copy a file using BITS Transfer which allows a progress bar to be displayed.  This function
    should not be used to copy files on a ReFS formatted volume because it will bypasses ReFS Cloning.

    .PARAMETER Source
    The source file to be copied.

    .PARAMETER Destination
    The destination for the file to be copied to.

    .EXAMPLE
    PS> Copy-HvtFileUsingBitsTransfer -Source C:\VMs\VirtualDisks\VM12_DISK_00.vhdx C:\VMTemplates\WindowsServer2025StandardGUITemplate
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    # Make sure the Bits service is started
    $BitServiceStatus = Get-Service -Name BITS | Select-Object -ExpandProperty Status
    if ($BitServiceStatus -eq 'Stopped') {
        Start-Service -Name BITS
    }

    # Start the bits copy
    $BitsJob = Start-BitsTransfer -Source $Source -Destination $Destination -Asynchronous

    # Update the progress
    $FileName = Split-Path $Source -Leaf
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($BitsJob.JobState -in "Transferring","Connecting") {
        $ElapsedTime = $Stopwatch.Elapsed

        $PercentComplete = [math]::Round($BitsJob.BytesTransferred / $BitsJob.BytesTotal * 100)
        $StatusMessage = [string]::Format("$PercentComplete% Complete; Elapsed Time {0:d2}:{1:d2}:{2:d2}", $ElapsedTime.Hours, $ElapsedTime.Minutes, $ElapsedTime.Seconds)
        Write-Progress -Activity "Performing BITS Transfer of $FileName..." -Status $StatusMessage -PercentComplete $PercentComplete
        Start-Sleep -Seconds 1
    }

    # Clean up the BITS Transfer
    Complete-BitsTransfer -BitsJob $BitsJob
}

function New-HvtUnattendXMLFile {

<#
    .SYNOPSIS
    Creates an Unattend.xml file.

    .DESCRIPTION
    Creates an Unattend.xml file to automate installing Windows on a VM from a product ISO or when
    using a Sysprepped image.

    .PARAMETER WindowsInstallISO
    Create an Unattend.xml file targeted for an installation from a Windows Product ISO.

    .PARAMETER Sysprep
    Create an Unattend.xml file targeted for an installation using a Sysprepped OS.

    .PARAMETER FilePath
    Specifies the path where the Unattend.xml file is created.

    .PARAMETER ComputerName
    Specifies the computer name to be configured.

    .PARAMETER OperatingSystem
    Specifies the Operating System that the Unattend.xml file will be used to configure.

    .PARAMETER WindowsImageNumber
    Specifies the Image Number used when performing the Windows installation (WindowsInstallISO only).

    .PARAMETER ProductKey
    Specifies the Product Key used when performing the Windows installation (WindowsInstallISO only).

    .PARAMETER TimeZone
    Specifies the time zone of the computer.  For a list of available time zones, use the tzutil /l

    .PARAMETER AdministratorPassword
    Specifies the initial password for the Administrator account. AdministratorPassword is required if the Sysprep
    option is specified and optional when WindowsInstallISO is specified to allow the administrator password to
    be entered at the end of the installation process.

    .PARAMETER IPAddress
    Specifies the IP Address to configure the default VM ethernet adapter.

    .PARAMETER SubnetPrefix
    Specifies the TCP/IP subnet prefix to be configured.

    .PARAMETER DefaultGateway
    Specifies the TCP/IP default gateway to be configured.

    .PARAMETER DNSServers
    Specifies the DNS servers to be configured.

    .PARAMETER DomainName
    Specifies Domain to join the computer to.

    .PARAMETER DomainOUPath
    Specifies OU where the computer account will be created (required if DomainName is specified).

    .PARAMETER DomainJoinCredential
    Specifies the user and password that will be used to join the computer to the domain (required if DomainName is specified).

    .PARAMETER EnableRemoteDesktop
    Specifies that remote desktop will be configured including opening the firewall for port 3389.

    .EXAMPLE
    PS>New-HvtUnattendXMLFile -WindowsInstallISO -FilePath C:\Temp\unattend.xml -ComputerName VM1 -OperatingSystem WindowsServer2025 -WindowsImageNumber 2 -ProductKey 'TVRH6-WHNXV-R9WG3-9XRFY-MY832'

    .EXAMPLE
    PS>$AdministratorPassword = Read-Host -AsSecureString
    PS>New-HvtUnattendXMLFile -Sysprep -FilePath C:\Temp\unattend.xml -ComputerName VM1 -OperatingSystem WindowsServer2025 -AdministratorPassword $AdministratorPassword
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='WindowsInstallISO')]
        [switch]$WindowsInstallISO,

        [Parameter(Mandatory=$true, ParameterSetName='Sysprep')]
        [switch]$Sysprep,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateSet('WindowsServer2025Standard','WindowsServer2025Datacenter','WindowsServer2022Standard','WindowsServer2022Datacenter','WindowsServer2019Standard','WindowsServer2019Datacenter','Windows10','Windows11')]
        [string]$OperatingSystem,

        [Parameter(Mandatory=$true, ParameterSetName='WindowsInstallISO')]
        [string]$WindowsImageNumber,

        [Parameter(Mandatory=$true, ParameterSetName='WindowsInstallISO')]
        [string]$ProductKey,

        [string]$TimeZone='',

        [SecureString]$AdministratorPassword,
        [string]$IPAddress = '',
        [string]$SubnetPrefix = '24',
        [string]$DefaultGateway = '',
        [string]$DNSServers = '',

        [string]$DomainName='',
        [string]$DomainOUPath='',
        [PSCredential]$DomainJoinCredential,

        [bool]$EnableRemoteDesktop=$false
    )

    if ($PSCmdlet.ParameterSetName -eq 'Sysprep' -and $null -eq $AdministratorPassword) {
        throw 'AdministratorPassword is required when the Sysprep option is specified'
    }

    if ($DomainName -ne '' -and ($DomainOUPath -eq '' -or $null -eq $DomainJoinCredential)) {
        throw 'If DomainName is specified, DomainOUPath and DomainJoinCredential must a;be specified if DomainName was'
    }

    # Process variables used in the component sections so that substitutions are made when the sections are initialized
    if ($DomainName -ne '') {

        # Convert the password in the credential to clear text
        $BSTRPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainJoinCredential.Password)
        $DomainJoinClearTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRPointer)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTRPointer) # Free the pointer
        $DomainJoinUserName = $DomainJoinCredential.UserName

        if ($null -ne $DomainJoinCredential) {
            # Convert the password in the SecureString to clear text
            $BSTRPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainJoinCredential.Password)
            $DomainJoinClearTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRPointer)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTRPointer) # Free the pointer
        }
    }

    if ($null -ne $AdministratorPassword) {
        # Convert the password in the SecureString to clear text
        $BSTRPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdministratorPassword)
        $AdministratorClearTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRPointer)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTRPointer) # Free the pointer
    }

    if ($DNSServers -ne '') {
        $DNSServerList = $DNSServers.Split(',')
        $DNSServer1 = $DNSServerList[0]
        if ($DNSServerList.Count -ge 2) {$DNSServer2 = $DNSServerList[1]}
        if ($DNSServerList.Count -ge 3) {$DNSServer3 = $DNSServerList[2]}
    }

#region windowsPE Pass
######################################################################################################################################################################################
# Create components for the 'windowsPE' pass of the Unattend.xml file
######################################################################################################################################################################################
$WindowsPEComponent_MicrosoftWindowsInternationalCoreWinPE = @"
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>0409:00000409</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
"@
$WindowsPEComponent_MicrosoftWindowsSetup = @"
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserData>
                <AcceptEula>true</AcceptEula>
                <ProductKey>
                    <WillShowUI>OnError</WillShowUI>
                    <Key>$ProductKey</Key>
                </ProductKey>
            </UserData>
            <DiskConfiguration>
                <Disk wcm:action="add">
                    <CreatePartitions>
                        <CreatePartition wcm:action="add">
                            <Order>4</Order>
                            <Type>Primary</Type>
                            <Extend>true</Extend>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>1</Order>
                            <Size>700</Size>
                            <Type>Primary</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>2</Order>
                            <Size>100</Size>
                            <Type>EFI</Type>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>3</Order>
                            <Type>MSR</Type>
                            <Size>128</Size>
                        </CreatePartition>
                    </CreatePartitions>
                    <ModifyPartitions>
                        <ModifyPartition wcm:action="add">
                            <Label>WINRE</Label>
                            <Format>NTFS</Format>
                            <Order>1</Order>
                            <PartitionID>1</PartitionID>
                            <TypeID>DE94BBA4-06D1-4D40-A16A-BFD50179D6AC</TypeID>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <PartitionID>2</PartitionID>
                            <Order>2</Order>
                            <Label>SYSTEM</Label>
                            <Format>FAT32</Format>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>3</Order>
                            <PartitionID>3</PartitionID>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Order>4</Order>
                            <PartitionID>4</PartitionID>
                            <Letter>C</Letter>
                            <Label>DISK_C</Label>
                            <Format>NTFS</Format>
                            <Extend>false</Extend>
                        </ModifyPartition>
                    </ModifyPartitions>
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                </Disk>
                <WillShowUI>OnError</WillShowUI>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/INDEX</Key>
                            <Value>$WindowsImageNumber</Value>
                        </MetaData>
                    </InstallFrom>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>4</PartitionID>
                    </InstallTo>
                    <WillShowUI>OnError</WillShowUI>
                </OSImage>
            </ImageInstall>
        </component>
"@

    # Add the components for windowsPE
    $Unattend_windowsPEComponents = @()

    if ($WindowsInstallISO.IsPresent) {
        $Unattend_windowsPEComponents += $WindowsPEComponent_MicrosoftWindowsInternationalCoreWinPE
        $Unattend_windowsPEComponents += $WindowsPEComponent_MicrosoftWindowsSetup
    }

    # Join the components together and create the 'windowsPE' pass
    if ($Unattend_windowsPEComponents.Count -gt 0) {
        $Unattend_windowsPEPass = '    <settings pass="windowsPE">'
        foreach ($Component in $Unattend_windowsPEComponents) {
            $Unattend_windowsPEPass += "`r`n$Component"
        }
        $Unattend_windowsPEPass += "`r`n    </settings>"
    }
#endregion

#region generalize Pass
######################################################################################################################################################################################
# Create components for the 'generalize' pass of the Unattend.xml file
######################################################################################################################################################################################
$GeneralizeComponent_MicrosoftWindowsPnpSysprep = @"
        <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
        </component>
"@

    $Unattend_generalizeComponents = @()
    if ($Sysprep.IsPresent) {
        $Unattend_generalizeComponents += $GeneralizeComponent_MicrosoftWindowsPnpSysprep
    }

    # Join the components together and create the 'windowsPE' pass
    if ($Unattend_generalizeComponents.Count -gt 0) {
        $Unattend_generalizePass = '    <settings pass="generalize">'
        foreach ($Component in $Unattend_generalizeComponents) {
            $Unattend_generalizePass += "`r`n$Component"
        }
        $Unattend_generalizePass += "`r`n    </settings>"
    }

#endregion

#region specialize pass
######################################################################################################################################################################################
# Create components for the 'specialize' pass of the Unattend.xml file
######################################################################################################################################################################################
$SpecializeComponent_MicrosoftWindowsShellSetup = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>c:\Windows\System32\cmd.exe /C del C:\Windows\Panther\unattend-original.xml</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>c:\Windows\System32\cmd.exe /C rmdir /S /Q C:\Windows.old</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Path>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command (New-Object -ComObject Shell.Application).Namespace(17).Items() | Where-Object Type -eq 'CD Drive' | foreach { `$_.InvokeVerb('Eject') }</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsShellSetupTimeZone = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
            <TimeZone>$TimeZone</TimeZone>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>c:\Windows\System32\cmd.exe /C del C:\Windows\Panther\unattend-original.xml</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>c:\Windows\System32\cmd.exe /C rmdir /S /Q C:\Windows.old</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Path>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command (New-Object -ComObject Shell.Application).Namespace(17).Items() | Where-Object Type -eq 'CD Drive' | foreach { `$_.InvokeVerb('Eject') }</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsShellSetupSysprep = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>c:\Windows\System32\cmd.exe /C del C:\Windows\System32\Sysprep\unattend.xml</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsShellSetupSysprepTimeZone = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$ComputerName</ComputerName>
            <TimeZone>$TimeZone</TimeZone>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>c:\Windows\System32\cmd.exe /C del C:\Windows\System32\Sysprep\unattend.xml</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsSecureStartupFilterDriver = @"
        <component name="Microsoft-Windows-SecureStartup-FilterDriver" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <PreventDeviceEncryption>true</PreventDeviceEncryption>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsUnattendedJoin = @"
        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
           <Identification>
                <Credentials>
                    <Domain>$DomainName</Domain>
                    <Password>$DomainJoinClearTextPassword</Password>
                    <Username>$DomainJoinUserName</Username>
                </Credentials>
                <JoinDomain>$DomainName</JoinDomain>
                <MachineObjectOU>$DomainOUPath</MachineObjectOU>
            </Identification>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsTCPIPWithoutGateway = @"
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
                    </Ipv4Settings>
                    <Ipv6Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
                    </Ipv6Settings>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$SubnetPrefix</IpAddress>
                    </UnicastIpAddresses>
                    <Identifier>Ethernet</Identifier>
                  </Interface>
            </Interfaces>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsTCPIPWithGateway = @"
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
                    </Ipv4Settings>
                    <Ipv6Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
                    </Ipv6Settings>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$SubnetPrefix</IpAddress>
                    </UnicastIpAddresses>
                    <Identifier>Ethernet</Identifier>
                    <Routes>
                        <Route wcm:action="add">
                            <Prefix>0.0.0.0/0</Prefix>
                            <NextHopAddress>$DefaultGateway</NextHopAddress>
                            <Identifier>0</Identifier>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsDNSClient1 = @"
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$DNSServer1</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsDNSClient2 = @"
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$DNSServer1</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="2">$DNSServer2</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsDNSClient3 = @"
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$DNSServer1</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="2">$DNSServer2</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="2">$DNSServer3</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
"@
$SpecializeComponent_MicrosoftWindowsTerminalServicesLocalSessionManager = @"
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <FirewallGroups>
                <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">
                    <Active>true</Active>
                    <Group>@FirewallAPI.dll,-28752</Group>
                    <Profile>all</Profile>
                </FirewallGroup>
            </FirewallGroups>
        </component>
"@

    # Add the components for specialize
    $Unattend_specializeComponents = @()

    if ($WindowsInstallISO.IsPresent) {
        if ($TimeZone -eq '') {
            $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsShellSetup
        }
        else {
            $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsShellSetupTimeZone
        }

        # Add  Disable BitLocker component for Windows 11 VMs
        if ($OperatingSystem -like 'Windows11*') {
            $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsSecureStartupFilterDriver
        }
    }
    else
    {
        if ($TimeZone -eq '') {
            $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsShellSetupSysprep
        }
        else {
            $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsShellSetupSysprepTimeZone
        }
    }

    # Add optional JoinDomain component
    if ($DomainName -ne '') {
        $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsUnattendedJoin
    }

    # Add optional TCPIP configuration component
    if ($IPAddress -ne '') {
        if ($DefaultGateway -eq '') {
             $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsTCPIPWithoutGateway
        }
        else {
            $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsTCPIPWithGateway
        }
    }

    if ($DNSServerList.Count -eq 1) {
        $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsDNSClient1
    }
    elseif ($DNSServerList.Count -eq 2) {
        $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsDNSClient2
    }
    elseif ($DNSServerList.Count -ge 3) {
        $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsDNSClient3
    }

    if ($EnableRemoteDesktop) {
        $Unattend_specializeComponents += $SpecializeComponent_MicrosoftWindowsTerminalServicesLocalSessionManager
    }

    # Join the components together and create the 'specialize' pass
        if ($Unattend_specializeComponents.Count -gt 0) {
        $Unattend_specializePass = '    <settings pass="specialize">'
        foreach ($Component in $Unattend_specializeComponents) {
            $Unattend_specializePass += "`r`n$Component"
        }
        $Unattend_specializePass += "`r`n    </settings>"
    }
#endregion

#region oobeSystem pass
######################################################################################################################################################################################
# Create components for the 'oobeSystem' pass of the Unattend.xml file
######################################################################################################################################################################################
$OobeSystemComponent_MicrosoftWindowsInternationalCore = @"
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>0409:00000409</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
"@
$OobeSystemComponent_MicrosoftWindowsShellSetupWindows11 = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
            </OOBE>
        </component>
"@
$OobeSystemComponent_MicrosoftWindowsShellSetupWindows11WithAdministratorPassword = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <ProtectYourPC>3</ProtectYourPC>
                <HideEULAPage>true</HideEULAPage>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Password>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
            </AutoLogon>
        </component>
"@
$OobeSystemComponent_MicrosoftWindowsShellSetupWindowsServer = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Password>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
            </AutoLogon>
        </component>
"@
$OobeSystemComponent_MicrosoftWindowsShellSetupWindows11Sysprep = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <VMModeOptimizations>
                    <SkipAdministratorProfileRemoval>true</SkipAdministratorProfileRemoval>
                    <SkipNotifyUILanguageChange>true</SkipNotifyUILanguageChange>
                    <SkipWinREInitialization>true</SkipWinREInitialization>
                </VMModeOptimizations>
            </OOBE>
        </component>
"@
$OobeSystemComponent_MicrosoftWindowsShellSetupWindows11WithAdministratorPasswordSysprep = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <ProtectYourPC>3</ProtectYourPC>
                <HideEULAPage>true</HideEULAPage>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <VMModeOptimizations>
                    <SkipAdministratorProfileRemoval>true</SkipAdministratorProfileRemoval>
                    <SkipNotifyUILanguageChange>true</SkipNotifyUILanguageChange>
                    <SkipWinREInitialization>true</SkipWinREInitialization>
                </VMModeOptimizations>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Password>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
            </AutoLogon>
        </component>
"@
$OobeSystemComponent_MicrosoftWindowsShellSetupWindowsServerSysprep = @"
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <VMModeOptimizations>
                    <SkipAdministratorProfileRemoval>true</SkipAdministratorProfileRemoval>
                    <SkipNotifyUILanguageChange>true</SkipNotifyUILanguageChange>
                    <SkipWinREInitialization>true</SkipWinREInitialization>
                </VMModeOptimizations>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <AutoLogon>
                <Username>Administrator</Username>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Password>
                    <Value>$AdministratorClearTextPassword</Value>
                    <PlainText>true</PlainText>
                </Password>
            </AutoLogon>
        </component>
"@

    # Add the components for the 'oobeSystem' pass
    $Unattend_oobeSystemComponents = @()

   if ($WindowsInstallISO.IsPresent) {
        if ($OperatingSystem -like 'Windows1*') {
            $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsInternationalCore
            if ($null -eq $AdministratorPassword) {
                $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsShellSetupWindows11
            }
            else {
                $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsShellSetupWindows11WithAdministratorPassword
            }
        }
        elseif ($null -ne $AdministratorPassword) {
            $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsShellSetupWindowsServer
        }
    }
    else {
        if ($OperatingSystem -like 'Windows1*') {
            $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsInternationalCore
            if ($null -eq $AdministratorPassword) {
                $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsShellSetupWindows11Sysprep
            }
            else {
                $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsShellSetupWindows11WithAdministratorPasswordSysprep
            }
        }
        elseif ($null -ne $AdministratorPassword) {
            $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsInternationalCore
            $Unattend_oobeSystemComponents += $OobeSystemComponent_MicrosoftWindowsShellSetupWindowsServerSysprep
        }
    }

    # Join the components together and create the 'oobeSystem' pass
    if ($Unattend_oobeSystemComponents.Count -gt 0) {
        $Unattend_oobeSystemPass = '    <settings pass="oobeSystem">'
        foreach ($Component in $Unattend_oobeSystemComponents) {
            $Unattend_oobeSystemPass += "`r`n`t`t$Component"
        }
        $Unattend_oobeSystemPass += "`r`n`t</settings>"
    }
#endregion

######################################################################################################################################################################################
# Assemble the unattend pass sections into the Unattend.xml file
######################################################################################################################################################################################

    $UnattendXML = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
"@

    # Add in the 'windowsPE' pass components
    if ($Unattend_windowsPEComponents.Count -ge 1) {
        $UnattendXML += "`r`n$Unattend_windowsPEPass"
    }

    # Add in the 'generalize' pass components
    if ($Unattend_generalizeComponents.Count -ge 1) {
        $UnattendXML += "`r`n$Unattend_generalizePass"
    }

    # Add in the 'specialize' pass components
    if ($Unattend_specializeComponents.Count -ge 1) {
        $UnattendXML += "`r`n$Unattend_specializePass"
    }

    # Add in the 'oobeSystem' pass components
    if ($Unattend_oobeSystemComponents.Count -ge 1) {
        $UnattendXML += "`r`n$Unattend_oobeSystemPass"
    }

    # Close out the Unattend.xml file
    $CloseUnattendXML = @"

    <cpi:offlineImage cpi:source="wim:c:/VMMLite/en-us_windows_server_2025_x64_dvd_b7ec10f3/sources/install.wim#Windows Server 2025 SERVERSTANDARD" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@
    $UnattendXML += $CloseUnattendXML

    # Write out the Unattend.XML file
     $UnattendXML | Out-File -Encoding ascii -FilePath $FilePath

}

function Write-HvtMessage {
<#
    .SYNOPSIS
    Write out a status message.

    .DESCRIPTION
    Write out a message (Host, Verbose, or Warning and optionally write the message to a log file.

    .PARAMETER WriteHost
    Specifies the message is displayed as host output. ForegroundColor may be specified.

    .PARAMETER WriteVerbose
    Specifies the message is displayed if the -Verbose option was specified on the primar function.

    .PARAMETER WriteWaring
    Specifies the message is displayed as a warning.

    .PARAMETER ForegroundColor
    Specifies the Foreground Color if the WriteHost switch was selected.

    .PARAMETER Message
    Specifies the message to be displayed..

    .PARAMETER LogFilePath
    Specifies the destination path where the source file to copied to.

    .PARAMETER NewLogFile
    Specifies a new log file with 0 length should be created. The parent path for the log file will
    be created if necessary.

    .EXAMPLE
    PS>Write-HvtMessage -LogFilePath $LogFilePath -NewLogFile

    .EXAMPLE
    PS>Write-HvtMessage -LogFilePath $LogFilePath -WriteWaring -Message "VM $VMName doesn't exists"
#>

    param (
        [switch]$WriteHost,
        [switch]$WriteVerbose,
        [switch]$WriteWaring,
        [string]$ForegroundColor='White',
        [string]$Message,
        [string]$LogFilePath = '',
        [switch]$NewLogFile
      )

    # Create a new log file creating the directory if it doesn't exist
    if ($NewLogFile.IsPresent -and $LogFilePath -ne '') {
        New-Item -Path $LogFilePath -ItemType File -Force | Out-Null
        return
    }

    # Display the message based on the type switch
    if ($WriteHost.IsPresent) {
        $Message | Write-Host -ForegroundColor $ForegroundColor
    }
    elseif ($WriteWaring.IsPresent) {
        Write-Warning -Message $Message
    }
    elseif ($WriteVerbose.IsPresent) {
        Write-Verbose -Message $Message
    }

    # Also write the message to the log file if requested
    if ($LogFilePath -ne '') {
        $Message | Out-File -FilePath $LogFilePath -Encoding ascii -Append
    }
}

Export-ModuleMember -Function 'New-HvtNoPromptInstallISO','New-HvtVMTemplate','New-HvtVirtualMachine','Add-HvtVMDisk','New-HvtISO','Remove-HvtVMUnattendISO'