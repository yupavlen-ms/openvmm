# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$ROOT_HYPER_V_NAMESPACE = "root\virtualization\v2"

function Get-MsvmComputerSystem
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm
    )

    $vmid = $Vm.Id
    $msvm_ComputerSystem = Get-CimInstance -namespace $ROOT_HYPER_V_NAMESPACE -query "select * from Msvm_ComputerSystem where Name = '$vmid'"

    if (-not $msvm_ComputerSystem)
    {
        throw "Unable to find a virtual machine with id $vmid."
    }

    $msvm_ComputerSystem
}

function Get-Vssd
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm
    )

    Get-MsvmComputerSystem $Vm | Get-CimAssociatedInstance -ResultClass "Msvm_VirtualSystemSettingData" -Association "Msvm_SettingsDefineState"
}

function Get-Vmms
{
    Get-CimInstance -Namespace $ROOT_HYPER_V_NAMESPACE -Class Msvm_VirtualSystemManagementService
}

function Get-VmGuestManagementService
{
    Get-CimInstance -Namespace $ROOT_HYPER_V_NAMESPACE -Class Msvm_VirtualSystemGuestManagementService
}

function ConvertTo-CimEmbeddedString
{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [Microsoft.Management.Infrastructure.CimInstance] $CimInstance
    )

    if ($null -eq $CimInstance)
    {
        return ""
    }

    $cimSerializer = [Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
    $serializedObj = $cimSerializer.Serialize($CimInstance, [Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
    return [System.Text.Encoding]::Unicode.GetString($serializedObj)
}

function Set-InitialMachineConfiguration
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm,

        [Parameter(Mandatory = $true)]
        [string] $ImcHive
    )

    $msvm_ComputerSystem = Get-MsvmComputerSystem $Vm

    $imcHiveData = Get-Content -Encoding Byte $ImcHive
    $length = [System.BitConverter]::GetBytes([int32]$imcHiveData.Length + 4)
    if ([System.BitConverter]::IsLittleEndian)
    {
        [System.Array]::Reverse($length);
    }
    $imcData = $length + $imcHiveData

    $vmms = Get-Vmms
    $vmms | Invoke-CimMethod -name "SetInitialMachineConfigurationData" -Arguments @{
        "TargetSystem" = $msvm_ComputerSystem;
        "ImcData" = [byte[]]$imcData
    }
}

function Set-VmSystemSettings {
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.Management.Infrastructure.CimInstance] $Vssd
    )

    $vmms = Get-Vmms
    $vmms | Invoke-CimMethod -Name "ModifySystemSettings" -Arguments @{
        "SystemSettings" = ($Vssd | ConvertTo-CimEmbeddedString)
    }
}

function Set-VmResourceSettings {
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]$Rasd
    )

    $vmms = Get-Vmms
    $vmms | Invoke-CimMethod -Name "ModifyResourceSettings" -Arguments @{
        "ResourceSettings" = @($Rasd | ConvertTo-CimEmbeddedString)
    }
}

function Set-OpenHCLFirmware
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm,

        [Parameter(Mandatory = $true)]
        [string] $IgvmFile,

        [switch] $IncreaseVtl2Memory
    )

    $vssd = Get-Vssd $Vm
    # Enable OpenHCL by feature
    $vssd.GuestFeatureSet = 0x00000201
    # Set the OpenHCL image file path
    $vssd.FirmwareFile = $IgvmFile

    if ($IncreaseVtl2Memory) {
        # Configure VM for auto placement mode
        $vssd.Vtl2AddressSpaceConfigurationMode = 1
        # 1GB of OpenHCL address space
        $vssd.Vtl2AddressRangeSize = 1024
        # 512 MB of OpenHCL MMIO space. So total OpenHCL ram = Vtl2AddressRangeSize- Vtl2MmioAddressRangeSize.
        $vssd.Vtl2MmioAddressRangeSize = 512
    }

    Set-VmSystemSettings $vssd
}

function Set-VmCommandLine
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $CommandLine
    )

    $vssd = Get-Vssd $Vm
    $vssd.FirmwareParameters = [System.Text.Encoding]::UTF8.GetBytes($CommandLine)
    Set-VmSystemSettings $vssd
}

function Get-VmCommandLine
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm
    )

    $vssd = Get-Vssd $Vm
    [System.Text.Encoding]::UTF8.GetString($vssd.FirmwareParameters)
}

function Set-VmScsiControllerTargetVtl
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm,

        [Parameter(Mandatory = $true)]
        [int] $ControllerNumber,

        [Parameter(Mandatory = $true)]
        [int] $TargetVtl
    )

    $vssd = Get-Vssd $Vm
    $rasds = $vssd | Get-CimAssociatedInstance -ResultClassName "Msvm_ResourceAllocationSettingData" | Where-Object { $_.ResourceSubType -eq "Microsoft:Hyper-V:Synthetic SCSI Controller" }
    $rasd = $rasds[$ControllerNumber]
    $rasd.TargetVtl = $TargetVtl
    $rasd | Set-VmResourceSettings
}

function Set-VMBusRedirect
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm,

        [Parameter(Mandatory = $true)]
        [bool] $Enable
    )

    $vssd = Get-Vssd $Vm
    $vssd | ForEach-Object {
            $_.VMBusMessageRedirection = [int]$Enable
            $_
        }
    Set-VmSystemSettings $vssd
}

<#
.SYNOPSIS
    Helper function that processes a CIMMethodResult/Msvm_ConcreteJob.

.DESCRIPTION
    Helper function that processes a CIMMethodResult/Msvm_ConcreteJob.

.PARAMETER WmiClass
    Supplies the WMI class object from where the method is being called.

.PARAMETER MethodName
    Supplies the method name that the job called.

.PARAMETER TimeoutSeconds
    Supplies the duration in seconds to wait for job completion.

.INPUTS
    Input a CIMMethodResult object through the pipeline, or any object with
    a ReturnValue property and optionally a Job property that is an Msvm_ConcreteJob.

.OUTPUTS
    Returns the input object on success; throws on error.

.EXAMPLE
    $job | Trace-CimMethodExecution -WmiClass $VMMS -MethodName ExportSystemDefinition
        Processes a job for the given class and method, shows progress until it reaches completion.
#>
filter Trace-CimMethodExecution {
    param (
        [Alias("WmiClass")]
        [Microsoft.Management.Infrastructure.CimInstance]$CimInstance = $null,
        [string] $MethodName = $null,
        [int] $TimeoutSeconds = 0
    )

    $errorCode = 0
    $returnObject = $_
    $job = $null
    $shouldProcess = $true
    $timer = $null

    if ($_.CimSystemProperties.ClassName -eq "Msvm_ConcreteJob") {
        $job = $_
    }
    elseif ((Get-Member -InputObject $_ -name "ReturnValue" -MemberType Properties)) {
        if ((Get-Member -InputObject $_.ReturnValue -name "Value" -MemberType Properties)) {
            # InvokeMethod from New-CimSession return object
            $returnValue = $_.ReturnValue.Value
        }
        else {
            # Invoke-CimMethod return object
            $returnValue = $_.ReturnValue
        }

        if (($returnValue -ne 0) -and ($returnValue -ne 4096)) {
            # An error occurred
            $errorCode = $returnValue
            $shouldProcess = $false
        }
        elseif ($returnValue -eq 4096) {
            if ((Get-Member -InputObject $_ -name "Job" -MemberType Properties) -and $_.Job) {
                # Invoke-CimMethod return object
                # CIM does not seem to actually populate the non-key fields on a reference, so we need
                # to go get the actual instance of the job object we got.
                $job = ($_.Job | Get-CimInstance)
            }
            elseif ((Get-Member -InputObject $_ -name "OutParameters" -MemberType Properties) -and $_.OutParameters["Job"]) {
                # InvokeMethod from New-CimSession return object
                $job = ($_.OutParameters["Job"].Value | Get-CimInstance)
            }
            else {
                throw "ReturnValue of 4096 with no Job object!"
            }
        }
        else {
            # No job and no error, just exit.
            return $returnObject
        }
    }
    else {
        throw "Pipeline input object is not a job or CIM method result!"
    }

    if ($shouldProcess) {
        $caption = if ($job.Caption) { $job.Caption } else { "Job in progress (no caption available)" }
        $jobStatus = if ($job.JobStatus) { $job.JobState } else { "No job status available" }
        $percentComplete = if ($job.PercentComplete) { $job.PercentComplete } else { 0 }

        if (($job.JobState -eq 4) -and $TimeoutSeconds -gt 0) {
            $timer = [Diagnostics.Stopwatch]::StartNew()
        }

        while ($job.JobState -eq 4) {
            if (($timer -ne $null) -and ($timer.Elapsed.Seconds -gt $TimeoutSeconds)) {
                throw "Job did not complete within $TimeoutSeconds seconds!"
            }
            Write-Progress -Activity $caption -Status ("{0} - {1}%" -f $jobStatus, $percentComplete) -PercentComplete $percentComplete
            Start-Sleep -seconds 1
            $job = $job | Get-CimInstance
        }

        if ($timer) { $timer.Stop() }

        if ($job.JobState -ne 7) {
            if (![string]::IsNullOrEmpty($job.ErrorDescription)) {
                Throw $job.ErrorDescription
            }
            else {
                $errorCode = $job.ErrorCode
            }
        }
        Write-Progress -Activity $caption -Status $jobStatus -PercentComplete 100 -Completed:$true
    }

    if ($errorCode -ne 0) {
        if ($CimInstance -and $MethodName) {
            $cimClass = Get-CimClass -ClassName $CimInstance.CimSystemProperties.ClassName `
                -Namespace $CimInstance.CimSystemProperties.Namespace -ComputerName $CimInstance.CimSystemProperties.ServerName

            $methodQualifierValues = ($cimClass.CimClassMethods[$MethodName].Qualifiers["ValueMap"].Value)
            $indexOfError = [System.Array]::IndexOf($methodQualifierValues, [string]$errorCode)

            if (($indexOfError -ne "-1") -and $methodQualifierValues) {
                # If the class in question has an error description defined for the error in its Values collection, use it
                if ($cimClass.CimClassMethods[$MethodName].Qualifiers["Values"] -and $indexOfError -lt $cimClass.CimClassMethods[$MethodName].Qualifiers["Values"].Value.Length) {
                    Throw "ReturnCode: ", $errorCode, " ErrorMessage: '", $cimClass.CimClassMethods[$MethodName].Qualifiers["Values"].Value[$indexOfError], "' - when calling $MethodName"
                }
                else {
                    # The class has no error description for the error code, so just return the error code
                    Throw "ReturnCode: ", $errorCode, " - when calling $MethodName"
                }
            }
            else {
                # The error code is not found in the ValueMap, so just return the error code
                Throw "ReturnCode: ", $errorCode, " ErrorMessage: 'MessageNotFound' - when calling $MethodName"
            }
        }
        else {
            Throw "ReturnCode: ", $errorCode, "When calling $MethodName - for rich error messages provide classpath and method name."
        }
    }

    return $returnObject
}

function Restart-OpenHCL
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $Vm,
        [int] $TimeoutHintSeconds = 15, # Ends up as the deadline in GuestSaveRequest (see the handling of
                                        # SaveGuestVtl2StateNotification in guest_emulation_transport). Keep O(15 seconds).
                                        #
                                        # Also used as the hint for how long to wait (in this cmdlet) for the
                                        # ReloadManagementVtl method to complete.
        [switch] $OverrideVersionChecks,
        [switch] $DisableNvmeKeepalive
    )
    
    $vmid = $Vm.Id.tostring();
    $guestManagementService = Get-VmGuestManagementService;
    $options = 0;
    if ($OverrideVersionChecks) {
        $options = $options -bor 1;
    }
    if ($DisableNvmeKeepalive) {
        $options = $options -bor 16;
    }
    $result = $guestManagementService | Invoke-CimMethod -name "ReloadManagementVtl" -Arguments @{
        "VmId"            = $vmid
        "Options"         = $options
        "TimeoutHintSecs" = $TimeoutHintSeconds
    }

    $result | Trace-CimMethodExecution -CimInstance $guestManagementService -MethodName "ReloadManagementVtl" -TimeoutSeconds $TimeoutHintSeconds
}
