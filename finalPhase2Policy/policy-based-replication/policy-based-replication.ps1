### -----------------------------------------------------------------------------------------------
### <script name=policy-based-replication>
### <summary>
### This script creates all the prerequisite resources for allowing policy based replication at
### scale. Once the resources are created, the script further deploys a new policy assignment with
### appropriate parameters.
### </summary>
###
### <param name="subscriptionId">Mandatory parameter defining the subscription Id.</param>
### <param name="sourceResourceGroupName">Mandatory parameter defining the source resource group
### name. The policy will be deployed at this resource group's scope.</param>
### <param name="sourceLocation">Mandatory parameter defining the source region.</param>
### <param name="targetLocation">Mandatory parameter defining the target region.</param>
### <param name="vaultResourceGroupName">Mandatory parameter defining the vault resource group
### name.</param>
### <param name="vaultName">Mandatory parameter defining the vault name.</param>
### <param name="msiLocation">Mandatory parameter defining the location where the managed services
### identity is deployed.</param>
### <param name="replicationPolicyName">Optional parameter defining the replication policy name.
### Default value used - 24-hours-retention-policy.</param>
### <param name="recoveryNetworkName">Optional parameter defining the recovery network name.
### Default value used - <sourceResourceGroupName>-vnet-asr.</param>
### <param name="targetResourceGroupName">Optional parameter defining the target resource group
### name. Default value used - <sourceResourceGroupName>-asr.</param>
### <param name="cacheStorageAccountName">Optional parameter defining the cache storage account
### name. Default value used - <vaultName> + cacheasr + GUID. This is trimmed down to 24 length.
### </param>
### <param name="cacheStorageAccountSkuName">Optional parameter defining the cache storage account
### SKU name. Default value used - Standard_LRS.</param>
### <param name="recoverySubnetName">Optional parameter defining a subnet name in case a new
### recovery network is created. Default value used - default.</param>
### <param name="addressPrefix">Optional parameter defining the address prefix range in case a new
### recovery network is created. This address prefix is used by the corresponding recovery subnet
### as well. Default value used - 10.0.0.0/16.</param>
### <param name="pitRetentionInHours">Optional parameter defining the recovery point retention in
### hours in case a new replication policy is created. Default value used - 24.</param>
### <param name="appConsistentFrequencyInHours">Optional parameter defining the application
### consistent snapshot frequency in hours, in case a new replication policy is created. Default
### value used - 24.</param>
### -----------------------------------------------------------------------------------------------

#Region Parameters

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true,
               HelpMessage="Subscription Id.")]
    [ValidateNotNullorEmpty()]
    [string]$subscriptionId,

    [Parameter(Mandatory = $true,
               HelpMessage="Source resource group name.")]
    [ValidateNotNullorEmpty()]
    [string]$sourceResourceGroupName,

    [Parameter(Mandatory = $true,
               HelpMessage="Source region.")]
    [ValidateNotNullorEmpty()]
    [string]$sourceLocation,

    [Parameter(Mandatory = $true,
               HelpMessage="Target region.")]
    [ValidateNotNullorEmpty()]
    [string]$targetLocation,

    [Parameter(Mandatory = $true,
               HelpMessage="Vault resource group name.")]
    [ValidateNotNullorEmpty()]
    [string]$vaultResourceGroupName,

    [Parameter(Mandatory = $true,
               HelpMessage="Vault name.")]
    [ValidateNotNullorEmpty()]
    [string]$vaultName,

    [Parameter(Mandatory = $true,
               HelpMessage="Managed services identity location (https://docs.microsoft.com/" + `
                "en-us/azure/active-directory/managed-identities-azure-resources/overview).")]
    [ValidateNotNullorEmpty()]
    [string]$msiLocation,

    [Parameter(Mandatory = $false,
               HelpMessage="Replication policy name.")]
    [ValidateNotNullorEmpty()]
    [string]$replicationPolicyName = "24-hour-retention-policy",

    [Parameter(Mandatory = $false,
               HelpMessage="Recovery virtual network name.")]
    [ValidateNotNullorEmpty()]
    [string]$recoveryNetworkName = $null,

    [Parameter(Mandatory = $false,
               HelpMessage="Target resource group name.")]
    [ValidateNotNullorEmpty()]
    [string]$targetResourceGroupName = $null,

    [Parameter(Mandatory = $false,
               HelpMessage="Cache storage account name.")]
    [ValidateNotNullorEmpty()]
    [string]$cacheStorageAccountName = $null,

    [Parameter(Mandatory = $false,
               HelpMessage="Cache storage account SKU name.")]
    [ValidateNotNull()]
    [ValidateSet(
        "Standard_LRS",
        "Standard_ZRS",
        "Standard_GRS",
        "Standard_RAGRS",
        "Premium_LRS",
        "Premium_ZRS")]
    [string]$cacheStorageAccountSkuName = "Standard_LRS",

    [Parameter(Mandatory = $false,
               HelpMessage="Recovery subnet name used, if need be, for creation of new network.")]
    [ValidateNotNullorEmpty()]
    [string]$recoverySubnetName = "default",

    [Parameter(Mandatory = $false,
               HelpMessage="Recovery network address prefix used, if need be, for creation of " + `
                "new network.")]
    [ValidateNotNullorEmpty()]
    [string]$addressPrefix = "10.0.0.0/16",

    [Parameter(Mandatory = $false,
               HelpMessage="Recovery point retention in hours for new replication policy.")]
    [ValidateNotNull()]
    [int]$pitRetentionInHours = 24,

    [Parameter(Mandatory = $false,
               HelpMessage="Application consistent snapshot frequency in hours for new " + `
                "replication policy.")]
    [ValidateNotNull()]
    [int]$appConsistentFrequencyInHours = 1)
#EndRegion

#Region Required

Set-StrictMode -Version 1.0
#EndRegion

#Region Logger

### <summary>
###  Types of logs available.
### </summary>
Enum LogType
{
    ### <summary>
    ###  Log type is error.
    ### </summary>
    ERROR = 1

    ### <summary>
    ###  Log type is warning.
    ### </summary>
    WARNING = 2

    ### <summary>
    ###  Log type is debug.
    ### </summary>
    DEBUG = 3

    ### <summary>
    ###  Log type is information.
    ### </summary>
    INFO = 4

    ### <summary>
    ###  Log type is output.
    ### </summary>
    OUTPUT = 5
}

### <summary>
###  Class to log results.
### </summary>
class Logger
{
    ### <summary>
    ###  Gets the output file name.
    ### </summary>
    [string]$fileName

    ### <summary>
    ###  Gets the output file location.
    ### </summary>
    [string]$filePath

    ### <summary>
    ###  Gets the output line width.
    ### </summary>
    [int]$lineWidth

    ### <summary>
    ###  Gets the debug segment status.
    ### </summary>
    [bool]$isDebugSegmentOpen

    ### <summary>
    ###  Gets the debug output.
    ### </summary>
    [System.Object[]]$debugOutput

    ### <summary>
    ###  Initializes an instance of class OutLogger.
    ### </summary>
    ### <param name="name">Name of the file.</param>
    ### <param name="path">Local or absolute path to the file.</param>
    Logger(
        [String]$name,
        [string]$path)
    {
        $this.fileName = $name
        $this.filePath = $path
        $this.isDebugSegmentOpen = $false
        $this.lineWidth = 80
    }

    ### <summary>
    ###  Gets the full file path.
    ### </summary>
    [String] GetFullPath()
    {
        $path = $this.fileName + '.log'

        if($this.filePath)
        {
            if (-not (Test-Path $this.filePath))
            {
                Write-Warning "Invalid file path: $($this.filePath)"
                return $path
            }

            if ($this.filePath[-1] -ne "\")
            {
                $this.filePath = $this.filePath + "\"
            }

            $path = $this.filePath + $path
        }

        return $path
    }


    ### <summary>
    ###  Gets the full file path.
    ### </summary>
    ### <param name="invocationInfo">Gets the invocation information.</param>
    ### <param name="message">Gets the message to be logged.</param>
    ### <param name="type">Gets the type of log.</param>
    ### <return>String containing the formatted message -
    ### Type: DateTime ScriptName Line [Method]: Message.</return>
    [String] GetFormattedMessage(
        [System.Management.Automation.InvocationInfo] $invocationInfo,
        [string]$message,
        [LogType] $type)
    {
        $dateTime = Get-Date -uFormat "%d/%m/%Y %r"
        $line = $type.ToString() + "`t`t: $dateTime "
        $line +=
            "$($invocationInfo.scriptName.split('\')[-1]):$($invocationInfo.scriptLineNumber) " + `
            "[$($invocationInfo.invocationName)]: "
        $line += $message

        return $line
    }

    ### <summary>
    ###  Starts the debug segment.
    ### </summary>
    [Void] StartDebugLog()
    {
        $script:DebugPreference = "Continue"
        $this.isDebugSegmentOpen = $true
    }

    ### <summary>
    ###  Stops the debug segment.
    ### </summary>
    [Void] StopDebugLog()
    {
        $script:DebugPreference = "SilentlyContinue"
        $this.isDebugSegmentOpen = $false
    }

    ### <summary>
    ###  Gets the debug output and stores it in $DebugOutput.
    ### </summary>
    ### <param name="command">Command whose debug output needs to be redirected.</param>
    ### <return>Command modified to get the debug output to the success stream to be stored in
    ### a variable.</return>
    [string] GetDebugOutput([string]$command)
    {
        if ($this.isDebugSegmentOpen)
        {
            return '$(' + $command + ') 5>&1'
        }

        return $command
    }

    ### <summary>
    ###  Redirects the debug output to the output file.
    ### </summary>
    ### <param name="invocationInfo">Gets the invocation information.</param>
    ### <param name="command">Gets the command whose debug output needs to be redirected.</param>
    ### <return>Command modified to redirect debug stream to the log file.</return>
    [string] RedirectDebugOutput(
        [System.Management.Automation.InvocationInfo] $invocationInfo,
        [string]$command)
    {
        if ($this.isDebugSegmentOpen)
        {
            $this.Log(
                $InvocationInfo,
                "Debug output for command: $command`n",
                [LogType]::DEBUG)
            return $command + " 5>> $($this.GetFullPath())"
        }

        return $command
    }

    ### <summary>
    ###  Appends a message to the output file.
    ### </summary>
    ### <param name="invocationInfo">Gets the invocation information.</param>
    ### <param name="message">Gets the message to be logged.</param>
    ### <param name="type">Gets the type of log.</param>
    [Void] Log(
        [System.Management.Automation.InvocationInfo] $invocationInfo,
        [string] $message,
        [LogType] $type)
    {
        switch ($type) {

            ([LogType]::OUTPUT) {
                Out-File -FilePath $($this.GetFullPath()) -InputObject $message -Append `
                    -NoClobber -Width $this.lineWidth
                break
            }

            Default {
                Out-File -FilePath $($this.GetFullPath()) -InputObject $this.GetFormattedMessage(
                    $invocationInfo,
                    $message,
                    $type) -Append -NoClobber -Width $this.lineWidth
            }
        }
    }

    ### <summary>
    ###  Appends an object to the output file.
    ### </summary>
    ### <param name="invocationInfo">Gets the invocation information.</param>
    ### <param name="object">Gets the object to be logged.</param>
    ### <param name="type">Gets the type of log.</param>
    [Void] LogObject(
        [System.Management.Automation.InvocationInfo] $invocationInfo,
        $object,
        [LogType] $type)
    {
        Out-File -FilePath $($this.GetFullPath()) -InputObject $this.GetFormattedMessage(
            $invocationInfo,
            "`n",
            $type) -Append -NoClobber -Width $this.lineWidth
        Out-File -FilePath $($this.GetFullPath()) -InputObject $object -Append -NoClobber
    }
}
#EndRegion

#Region Constants

class ConstantStrings
{
    static [string] $asrSuffix = "-asr"
    static [string] $cacheStorageAccountString = "cacheasr"
    static [string] $deploymentSuffix = "deployments"
    static [int] $policyAssignmentNameMaxLength = 64
    static [string] $policyAssignmentPrefix = "AzureSiteRecovery-Replication-Policy-Assignment-"
    static [string] $policyDefinitionName = "AzureSiteRecovery-Replication-Policy"
    static [string] $policyDefinitionUrl = "https://raw.githubusercontent.com/punit1396/" + `
        "TestTemplates/master/finalPhase2Policy/policy-1.0/policy.json"
    static [string] $policyParametersUrl = "https://raw.githubusercontent.com/punit1396/" + `
        "TestTemplates/master/finalPhase2Policy/policy-1.0/parameters.json"
    static [string] $portalPolicyCompliancePageLink = "https://portal.azure.com/#blade/" + `
        "Microsoft_Azure_Policy/PolicyMenuBlade/Compliance"
    static [string] $portalPolicyDetailedComplianceBladePrefix = "https://portal.azure.com/" + `
        "#blade/Microsoft_Azure_Policy/PolicyComplianceDetailedBlade/id/"
    static [string] $portalResourceLinkPrefix = "https://portal.azure.com/" + `
        "#@microsoft.onmicrosoft.com/resource"
    static [string] $recoveryNetworkSuffix = "-vnet"
    static [string] $replicationJobs = "replicationJobs"
    static [string] $replicationProtectedItems = "replicationProtectedItems"
    static [string] $resourceDeploymentFormat = "ASR-<ResourceGroupName>-<VMName>-<GUID>"
    static [string] $scopes = "scopes"
    static [string] $storageAccountRegex = "[^a-zA-Z0-9]"
    static [int] $storageServiceMaxLength = 24
    static [string] $subscriptions = "subscriptions"
}

class PolicyParameter
{
    static [string] $cacheStorageAccountName = "cacheStorageAccountName"
    static [string] $recoveryNetworkName = "recoveryNetworkName"
    static [string] $replicationPolicyName = "replicationPolicyName"
    static [string] $sourceContainerName = "sourceContainerName"
    static [string] $sourceFabricName = "sourceFabricName"
    static [string] $sourceRegion = "sourceRegion"
    static [string] $targetContainerName = "targetContainerName"
    static [string] $targetFabricName = "targetFabricName"
    static [string] $targetRegion = "targetRegion"
    static [string] $targetResourceGroupId = "targetResourceGroupId"
    static [string] $vaultId = "vaultId"
    static [string] $vaultResourceGroupId = "vaultResourceGroupId"
}
#EndRegion

#Region Errors

class Errors
{
    ### <summary>
    ###  Invalid location exception.
    ### </summary>
    ### <param name="invalidLocation">Invalid location string passed by user.</param>
    ### <param name="validLocations">List of valid locations.</param>
    ### <return>Error string.</return>
    static [string] InvalidLocation([string] $invalidLocation, [string[]] $validLocations)
    {
        return "The location user input - '" + $invalidLocation + "', is invalid. Only the " + `
            "following values are allowed - " + $($validLocations -Join ", ") + "."
    }

    ### <summary>
    ###  Source and target region can't be the same.
    ### </summary>
    ### <param name="sourceLocation">Source location.</param>
    ### <param name="targetLocation">Target location.</param>
    ### <return>Error string.</return>
    static [string] SameSourceAndTargetRegion([string] $sourceLocation, [string] $targetLocation)
    {
        return "Source location - '" + $sourceLocation + "', and target location - '" + `
            $targetLocation + "', cannot be the same."
    }

    ### <summary>
    ###  Invalid IP address reserved bits.
    ### </summary>
    ### <param name="reservedBits">Reserved bits value.</param>
    ### <return>Error string.</return>
    static [string] InvalidIPAddressReservedBits([int] $reservedBits)
    {
        return "Invalid number of bits reserved in the IP address input - '" + $reservedBits + `
            "'. The number of reserved bits should be less than 32."
    }

    ### <summary>
    ###  Invalid storage account location.
    ### </summary>
    ### <param name="storageAccountName">Storage account name.</param>
    ### <param name="storageAccountLocation">Storage account location.</param>
    ### <param name="desiredLocation">Desired location.</param>
    ### <return>Error string.</return>
    static [string] InvalidStorageAccountLocation(
        [string] $storageAccountName,
        [string] $storageAccountLocation,
        [string] $desiredLocation)
    {
        return "The storage account (" + $storageAccountName + ") is located in region - '" + `
            $storageAccountLocation + "', instead of the desired location - '" + `
            $desiredLocation + "'."
    }

    ### <summary>
    ###  Invalid virtual network location.
    ### </summary>
    ### <param name="virtualNetworkName">Virtual network name.</param>
    ### <param name="virtualNetworkLocation">Virtual network location.</param>
    ### <param name="desiredLocation">Desired location.</param>
    ### <return>Error string.</return>
    static [string] InvalidVirtualNetworkLocation(
        [string] $virtualNetworkName,
        [string] $virtualNetworkLocation,
        [string] $desiredLocation)
    {
        return "The virtual network (" + $virtualNetworkName + ") is located in region - '" + `
            $virtualNetworkLocation + "', instead of the desired location - '" + `
            $desiredLocation + "'."
    }

    ### <summary>
    ###  No subnets found in virtual network.
    ### </summary>
    ### <param name="virtualNetworkName">Virtual network name.</param>
    ### <return>Error string.</return>
    static [string] AtLeastOneSubnetRequired([string] $virtualNetworkName)
    {
        return "The virtual network (" + $virtualNetworkName + ") does not contain a single subnet."
    }

    ### <summary>
    ###  ASR job did not succeed.
    ### </summary>
    ### <param name="job">Site recovery job.</param>
    ### <return>Error string.</return>
    static [string] SiteRecoveryJobDidNotSucceed($job)
    {
        $serviceError = out-string -InputObject $job.Errors[0].ServiceErrorDetails

        return "ASR job with id - '" + $job.Name + "', completed with state - '" + $job.State + `
        "', instead of 'Succeeded'. Error recorded - `n" + $serviceError
    }

    ### <summary>
    ###  Vault region can't be the same as source location.
    ### </summary>
    ### <param name="vaultName">Recovery services vault name.</param>
    ### <param name="vaultRegion">Recovery services vault location.</param>
    ### <param name="sourceRegion">Source location.</param>
    ### <return>Error string.</return>
    static [string] InvalidVaultLocation(
        [string] $vaultName,
        [string] $vaultRegion,
        [string] $sourceRegion)
    {
        return "The recovery services vault (" + $vaultName +") is present in region - '" + `
            $vaultRegion + "', which matches the source region - '" + $sourceRegion + `
            "'. This is not allowed."
    }

    ### <summary>
    ###  Aborting policy assignment.
    ### </summary>
    ### <param name="policyAssignmentNames">List of policy assignment names.</param>
    ### <return>Error string.</return>
    static [string] AbortingPolicyAssignment(
        [string[]] $policyAssignmentNames)
    {
        return "Aborting policy assignment as the following policy assignments already exist " + `
        "with the same definition and scope - `n" + ($policyAssignmentNames -Join ",`n")
    }
    
    ### <summary>
    ###  Role assignment failure leading to manual creation.
    ### </summary>
    ### <param name="principalId">Service principal Id.</param>
    ### <param name="roleName">The role to be assigned.</param>
    ### <param name="retryCount">Total retries attempted.</param>
    ### <return>Error string.</return>
    static [string] RoleAssignmentFailed(
        [string] $principalId,
        [string] $roleName,
        [int] $retryCount)
    {
        return "$roleName role couldn't be assigned to service principal - $principalId." + `
        "`nAssignment creation couldn't complete successfully after $retryCount retries. " + `
        "`nPlease create role assignments for the target resource group, source resource " + `
        "group and vault resource group manually." + `
        "`nThis can be done through the following steps - " + `
        "`n1. Azure Portal - Visit the Detailed Policy Assignment Compliance page " + `
        "(link provided under Additional Urls), go to Edit Assignment option, and Review and " + `
        "Save. This will trigger creation again." + `
        "`n2. Azure Powershell - Run the following cmdlet once for each resource group. " + `
        "`n'New-AzRoleAssignment -ObjectId $principalId -ResourceGroupName " + `
        "<resourcegroupname> -RoleDefinitionName $roleName"
    }
}
#EndRegion

#Region Validation

### <summary>
### Validate and update script parameters as required.
### </summary>
### <param name="sourceLocation">Source region.</param>
### <param name="targetLocation">Target region.</param>
### <param name="msiLocation">Managed services identity location.</param>
### <param name="cacheStorageAccountName">Cache storage account name.</param>
### <param name="targetResourceGroupName">Target resource group name.</param>
### <param name="recoveryNetworkName">Recovery network name.</param>
### <param name="addressPrefix">Recovery network address prefix.</param>
function Confirm-ScriptParameters(
    [ref]$sourceLocation,
    [ref]$targetLocation,
    [ref]$msiLocation,
    [ref]$cacheStorageAccountName,
    [ref]$targetResourceGroupName,
    [ref]$recoveryNetworkName,
    [ref]$addressPrefix)
{
    $resourceProvider = Get-AzResourceProvider -ProviderNamespace Microsoft.Compute

    # Locations taken from resource type: availabilitySets instead of resource type:
    # Virtual machines, just to stay in parallel with the Portal.
    $locations = ($resourceProvider[0].Locations) | ForEach-Object { $_.Split(' ').tolower() `
        -join ''} | Sort-Object

    $sourceLocation.Value = $sourceLocation.Value.ToLower()
    $targetLocation.Value = $targetLocation.Value.ToLower()
    $msiLocation.Value = $msiLocation.Value.ToLower()

    if ($locations -notcontains $sourceLocation.Value)
    {
        throw [Errors]::InvalidLocation($sourceLocation.Value, $locations)
    }

    if ($locations -notcontains $targetLocation.Value)
    {
        throw [Errors]::InvalidLocation($targetLocation.Value, $locations)
    }

    if ($locations -notcontains $msiLocation.Value)
    {
        throw [Errors]::InvalidLocation($msiLocation.Value, $locations)
    }

    if ($sourceLocation.Value -eq $targetLocation.Value)
    {
        throw [Errors]::SameSourceAndTargetRegion($sourceLocation.Value, $targetLocation.Value)
    }

    # Storage account naming convention and length checks.
    if ([string]::IsNullOrEmpty($cacheStorageAccountName.Value))
    {
        $cacheStorageAccountName.Value =
            $vaultName + [ConstantStrings]::cacheStorageAccountString + $(New-Guid).Guid
    }

    $cacheStorageAccountName.Value = $cacheStorageAccountName.Value -replace `
        [ConstantStrings]::storageAccountRegex

    if ([ConstantStrings]::storageServiceMaxLength -lt $cacheStorageAccountName.Value.Length)
    {
        $cacheStorageAccountName.Value =
            $cacheStorageAccountName.Value.Substring(0, [ConstantStrings]::storageServiceMaxLength)
    }

    # Assigning default target RG name, if necessary.
    if ([string]::IsNullOrEmpty($targetResourceGroupName.Value))
    {
        $targetResourceGroupName.Value = $sourceResourceGroupName + [ConstantStrings]::asrSuffix
    }

    # Assigning default recovery network name, if necessary.
    if ([string]::IsNullOrEmpty($recoveryNetworkName.Value))
    {
        $recoveryNetworkName.Value = $sourceResourceGroupName + `
            [ConstantStrings]::recoveryNetworkSuffix + [ConstantStrings]::asrSuffix
    }

    # IP Address format and bit mask value checks.
    $addressStart = $addressPrefix.Value.Split("/")[0]
    $addressBits = [convert]::ToInt32($addressPrefix.Value.Split("/")[1], 10)

    if ((32 - $addressBits) -lt 0)
    {
        throw [Errors]::InvalidIPAddressReservedBits($addressBits)
    }

    $address = [System.Net.IPAddress]::Parse($addressStart)
}
#EndRegion

#Region Azure

### <summary>
### Sets Azure context.
### </summary>
function Set-Context()
{
    $context = Get-AzContext

    if ($null -eq $context)
    {
        $suppressOutput = Login-AzAccount
    }

    $suppressOutput = Select-AzSubscription -SubscriptionId $subscriptionId
}

### <summary>
### Creates a new resource group in the specified location.
### </summary>
### <param name="resourceGroupName">Resource group name.</param>
### <param name="location">Resource group location.</param>
### <return>Resource group.</return>
function New-ResourceGroup(
    [string]$resourceGroupName,
    [string]$location)
{
    $resourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction Ignore

    if ($null -eq $resourceGroup)
    {
        Write-Host -ForegroundColor Green "Creating a new resource group - "$resourceGroupName `
            ", at "$location"."

        $resourceGroup = New-AzResourceGroup -Name $resourceGroupName -Location $location
    }

    return $resourceGroup
}

### <summary>
### Creates a new storage account in the specified location. If one already exists then verifies its
### location.
### </summary>
### <param name="name">Storage account name.</param>
### <param name="location">Storage account location.</param>
### <param name="resourceGroupName">Resource group name.</param>
### <return>Storage account.</return>
function New-StorageAccount(
    [string]$name,
    [string]$location,
    [string]$resourceGroupName)
{
    $storageAccount = Get-AzStorageAccount -Name $name -ResourceGroupName `
        $resourceGroupName -ErrorAction Ignore

    if ($null -eq $storageAccount)
    {
        Write-Host -ForegroundColor Green "Creating a new storage account - "$name `
            ", in resource group - "$resourceGroupName", at "$location"."

        $storageAccount = New-AzStorageAccount -Name $name -ResourceGroupName `
            $resourceGroupName -Location $location -SkuName $cacheStorageAccountSkuName
    }

    if ($location -ne $storageAccount.Location)
    {
        throw [Errors]::InvalidStorageAccountLocation(
            $name,
            $storageAccount.Location,
            $location)
    }

    return $storageAccount
}

### <summary>
### Creates a new network in the specified location. If one already exists then verifies the
### following
### 1 - Location.
### 2 - Subnet count.
### </summary>
### <param name="name">Virtual network name.</param>
### <param name="subnetName">Default subnet name.</param>
### <param name="addressPrefix">Virtual network and subnet address prefix.</param>
### <param name="location">Virtual network location.</param>
### <param name="resourceGroupName">Resource group name.</param>
### <return>Virtual network.</return>
function New-VirtualNetwork(
    [string]$name,
    [string]$subnetName,
    [string]$addressPrefix,
    [string]$location,
    [string]$resourceGroupName)
{
    $network = Get-AzVirtualNetwork -Name $name -ResourceGroupName $resourceGroupName `
        -ErrorAction Ignore

    if ($null -eq $network)
    {
        Write-Host -ForegroundColor Green "Creating a new virtual network - "$name `
            ", in resource group - "$resourceGroupName", at "$location"."

        $subnet = New-AzVirtualNetworkSubnetConfig -Name $subnetName -AddressPrefix $addressPrefix
        $network = New-AzVirtualNetwork -Name $name -ResourceGroupName $resourceGroupName `
            -Location $location -AddressPrefix $addressPrefix -Subnet $subnet
    }

    if ($location -ne $network.Location)
    {
        throw [Errors]::InvalidVirtualNetworkLocation(
            $name,
            $network.Location,
            $location)
    }

    if ($network.Subnets.Count -lt 1)
    {
        throw [Errors]::AtLeastOneSubnetRequired($name)
    }

    return $network
}

### <summary>
### Creates the following Azure resources
### 1 - Source resource group
### 2 - Target resource group
### 3 - Cache storage account
### 4 - Recovery virtual network.
### </summary>
function New-AzureResources()
{
    Write-Host -ForegroundColor Green "`nCreating new Azure resources."

    $sourceResourceGroup = New-ResourceGroup -ResourceGroupName $sourceResourceGroupName -Location `
        $sourceLocation
    $targetResourceGroup = New-ResourceGroup -ResourceGroupName $targetResourceGroupName -Location `
        $targetLocation
    $cacheStorageAccount = New-StorageAccount -Name $cacheStorageAccountName -ResourceGroupName `
        $sourceResourceGroupName -Location $sourceLocation
    $recoveryNetwork = New-VirtualNetwork -Name $recoveryNetworkName -SubnetName `
        $recoverySubnetName -AddressPrefix $addressPrefix -Location $targetLocation `
        -ResourceGroupName $targetResourceGroupName

    # Adding required policy parameters
    $policyParams.Add([PolicyParameter]::cacheStorageAccountName, $cacheStorageAccountName)
    $policyParams.Add([PolicyParameter]::recoveryNetworkName, $recoveryNetworkName)
    $policyParams.Add([PolicyParameter]::sourceRegion, $sourceLocation)
    $policyParams.Add([PolicyParameter]::targetRegion, $targetLocation)
    $policyParams.Add([PolicyParameter]::targetResourceGroupId, $targetResourceGroup.ResourceId)
}

#EndRegion

#Region ASR

#Region Misc

### <summary>
### Waits for the replication job to be completed.
### </summary>
### <param name="JobName">Replication job GUID name.</param>
### <return>Value indicating if the job completed successfully.</return>
function Wait-ReplicationJobCompletion([string] $jobName)
{
    if ([string]::IsNullOrEmpty($jobName))
    {
        return $true
    }

    $job = Get-ASRJob -Name $jobName

    while($job.State -eq "InProgress")
    {
        Start-Sleep -Seconds 10
        $job = Get-ASRJob -Name $jobName
    }

    if ($job.State -ne "Succeeded")
    {
        throw [Errors]::SiteRecoveryJobDidNotSucceed($job)
    }

    return $true
}
#EndRegion

#Region ASR-Resources

### <summary>
### Creates new replication fabrics, if necessary.
### </summary>
### <return>Source Replication fabric.</return>
### <return>Target Replication fabric.</return>
function New-ReplicationFabric()
{
    $defaultNamePrefix = "asr-a2a-policy-"
    $sourceFabric = $targetFabric = $null
    $sourceJob = $targetJob = $null

    $fabrics = Get-ASRFabric

    if ($null -ne $fabrics)
    {
        $sourceFabric = $fabrics | where {$_.FabricSpecificDetails.Location.ToLower() -eq `
            $sourceLocation}
        $targetFabric = $fabrics | where {$_.FabricSpecificDetails.Location.ToLower() -eq `
            $targetLocation}
    }

    if ($null -eq $sourceFabric)
    {
        $sourceFabricName = $defaultNamePrefix + $sourceLocation

        Write-Host -ForegroundColor Green "Creating a new replication fabric - "$sourceFabricName `
            ", for "$sourceLocation"."

        $sourceJob = New-ASRFabric -Azure -Name $sourceFabricName -Location $sourceLocation
    }

    if ($null -eq $targetFabric)
    {
        $targetFabricName = $defaultNamePrefix + $targetLocation

        Write-Host -ForegroundColor Green "Creating a new replication fabric - "$targetFabricName `
            ", for "$targetLocation"."

        $targetJob = New-ASRFabric -Azure -Name $targetFabricName -Location $targetLocation
    }

    $suppressOutput = Wait-ReplicationJobCompletion -JobName $sourceJob.Name
    $suppressOutput = Wait-ReplicationJobCompletion -JobName $targetJob.Name

    $fabrics = Get-ASRFabric
    $sourceFabric = $fabrics | where {$_.FabricSpecificDetails.Location.ToLower() -eq `
        $sourceLocation}
    $targetFabric = $fabrics | where {$_.FabricSpecificDetails.Location.ToLower() -eq `
        $targetLocation}

    return $sourceFabric, $targetFabric
}

### <summary>
### Creates new replication protection containers, if necessary.
### </summary>
### <return>Source Replication protection container.</return>
### <return>Target Replication protection container.</return>
function New-ReplicationProtectionContainer()
{
    $containerSuffix = "-container"
    $isNewSourceContainer = $isNewTargetContainer = $false
    $sourceJob = $targetJob = $null
    $sourceContainerName = $sourceFabric.Name + $containerSuffix
    $targetContainerName = $targetFabric.Name + $containerSuffix

    $sourceContainer = Get-ASRProtectionContainer -Name $sourceContainerName -Fabric $sourceFabric `
        -ErrorAction Ignore
    $targetContainer = Get-ASRProtectionContainer -Name $targetContainerName -Fabric $targetFabric `
        -ErrorAction Ignore

    if ($null -eq $sourceContainer)
    {
        Write-Host -ForegroundColor Green "Creating a new replication container -" `
            $sourceContainerName", under fabric - "$sourceFabric.Name"."

        $isNewSourceContainer = $true
        $sourceJob = New-AzRecoveryServicesAsrProtectionContainer -Name $sourceContainerName `
            -Fabric $sourceFabric
    }

    if ($null -eq $targetContainer)
    {
        Write-Host -ForegroundColor Green "Creating a new replication container -" `
            $targetContainerName", under fabric - "$targetFabric.Name"."

        $isNewTargetContainer = $true
        $targetJob = New-AzRecoveryServicesAsrProtectionContainer -Name $targetContainerName `
            -Fabric $targetFabric
    }

    $suppressOutput = Wait-ReplicationJobCompletion -JobName $sourceJob.Name
    $suppressOutput = Wait-ReplicationJobCompletion -JobName $targetJob.Name

    if ($isNewSourceContainer)
    {
        $sourceContainer = Get-ASRProtectionContainer -Name $sourceContainerName -Fabric `
            $sourceFabric
    }

    if ($isNewTargetContainer)
    {
        $targetContainer = Get-ASRProtectionContainer -Name $targetContainerName -Fabric `
            $targetFabric
    }

    return $sourceContainer, $targetContainer
}

### <summary>
### Creates new replication policy, if necessary.
### </summary>
### <return>Replication policy.</return>
function New-ReplicationPolicy()
{
    $isNewReplicationPolicy = $false
    $job = $null
    $replicationPolicy = Get-ASRPolicy -Name $replicationPolicyName -ErrorAction Ignore

    if ($null -eq $replicationPolicy)
    {
        Write-Host -ForegroundColor Green "Creating a new replication policy -" `
            $replicationPolicyName

        $isNewReplicationPolicy = $true
        $job = New-ASRPolicy -AzureToAzure -Name $replicationPolicyName `
            -RecoveryPointRetentionInHours $pitRetentionInHours `
            -ApplicationConsistentSnapshotFrequencyInHours $appConsistentFrequencyInHours
    }

    $suppressOutput = Wait-ReplicationJobCompletion -JobName $job.Name

    if ($isNewReplicationPolicy)
    {
        $replicationPolicy = Get-ASRPolicy -Name $replicationPolicyName
    }

    return $replicationPolicy
}

### <summary>
### Creates new replication protection container mappings, if necessary.
### </summary>
### <return>Source-target replication protection container mapping.</return>
### <return>Target-source replication protection container mapping.</return>
function New-ReplicationProtectionContainerMapping()
{
    $isNewSourceTargetMapping = $isNewTargetSourceMapping = $false
    $sourceTargetJob = $targetSourceJob = $null
    $sourceTargetMapping = $targetSourceMapping = $null

    $containerMappings = $sourceContainer | Get-ASRProtectionContainerMapping

    if ($null -ne $containerMappings)
    {
        $sourceTargetMapping = $containerMappings | where {
            ($_.SourceProtectionContainerFriendlyName.ToLower() -eq `
                $sourceContainer.FriendlyName.ToLower()) -and `
            ($_.PolicyFriendlyName.ToLower() -eq $replicationPolicy.FriendlyName.ToLower())}

        $targetSourceMapping = $containerMappings | where {
            ($_.TargetProtectionContainerFriendlyName.ToLower() -eq `
                $sourceContainer.FriendlyName.ToLower()) -and `
            ($_.PolicyFriendlyName.ToLower() -eq $replicationPolicy.FriendlyName.ToLower())}
    }

    if ($null -eq $sourceTargetMapping)
    {
        Write-Host -ForegroundColor Green "Creating a new replication container mapping:" `
            "primary container - "$sourceContainer.FriendlyName", recovery container -" `
            $targetContainer.FriendlyName", replication policy - "$replicationPolicy.FriendlyName

        $isNewSourceTargetMapping = $true
        $sourceTargetMappingName = $sourceLocation + "-" + $targetLocation + "-" + `
            $replicationPolicyName
        $sourceTargetJob = New-ASRProtectionContainerMapping -Name $sourceTargetMappingName `
            -Policy $replicationPolicy -PrimaryProtectionContainer $sourceContainer `
            -RecoveryProtectionContainer $targetContainer
    }

    if ($null -eq $targetSourceMapping)
    {
        Write-Host -ForegroundColor Green "Creating a new replication container mapping:" `
            "primary container - "$targetContainer.FriendlyName", recovery container -" `
            $sourceContainer.FriendlyName", replication policy - "$replicationPolicy.FriendlyName

        $isNewTargetSourceMapping = $true
        $targetSourceMappingName = $targetLocation + "-" + $sourceLocation + "-" + `
            $replicationPolicyName
        $targetSourceJob = New-ASRProtectionContainerMapping -Name $targetSourceMappingName `
            -Policy $replicationPolicy -RecoveryProtectionContainer $sourceContainer `
            -PrimaryProtectionContainer $targetContainer
    }

    $suppressOutput = Wait-ReplicationJobCompletion -JobName $sourceTargetJob.Name
    $suppressOutput = Wait-ReplicationJobCompletion -JobName $targetSourceJob.Name

    if ($isNewSourceTargetMapping)
    {
        $sourceTargetMapping = Get-ASRProtectionContainerMapping -Name $sourceTargetMappingName `
            -ProtectionContainer $sourceContainer
    }

    if ($isNewTargetSourceMapping)
    {
        $targetSourceMapping = Get-ASRProtectionContainerMapping -Name $targetSourceMappingName `
            -ProtectionContainer $targetContainer
    }

    return $sourceTargetMapping, $targetSourceMapping
}
#EndRegion

#Region Vault

### <summary>
### Creates a new Recovery Services Vault. If one already exists then verifies the
### location.
### </summary>
### <param name="name">Recovery services vault name.</param>
### <param name="location">Recovery services vault location.</param>
### <param name="resourceGroupName">Resource group name.</param>
### <return>Virtual network.</return>
function New-RecoveryServicesVault(
    [string]$name,
    [string]$location,
    [string]$resourceGroupName)
{
    $vault = Get-AzRecoveryServicesVault -Name $name -ResourceGroupName $resourceGroupName `
        -ErrorAction Ignore

    if ($null -eq $vault)
    {
        Write-Host -ForegroundColor Green "Creating a new recovery services vault - "$name `
            ", in resource group - "$resourceGroupName", at "$location

        $vault = New-AzRecoveryServicesVault -Name $name -ResourceGroupName $resourceGroupName `
            -Location $location
    }

    return $vault
}

### <summary>
### Sets the Recovery Services Vault settings. Creates the vault resourcegroup and vault if
### necessary.
### </summary>
### <param name="name">Recovery services vault name.</param>
### <param name="location">Recovery services vault location.</param>
### <param name="resourceGroupName">Resource group name.</param>
### <return>Recovery services vault.</return>
### <return>Vault resource group.</return>
function Set-RecoveryServicesVaultConfiguration(
    [string]$name,
    [string]$location,
    [string]$resourceGroupName)
{
    $vaultResourceGroup = New-ResourceGroup -ResourceGroupName $resourceGroupName -Location `
        $location
    $vault = New-RecoveryServicesVault -Name $name -ResourceGroupName $resourceGroupName `
        -Location $location

    if ($sourceLocation.ToLower() -eq $vault.Location.ToLower())
    {
        throw [Errors]::InvalidVaultLocation($vault.Name, $vault.Location, $sourceLocation)
    }

    $suppressOutput = Set-AzRecoveryServicesAsrVaultSettings -Vault $vault

    return $vault, $vaultResourceGroup
}
#EndRegion

### <summary>
### Creates the following ASR resources, if necessary
### 1 - Vault resource group
### 2 - Recovery services vault
### 3 - Source and target replication fabrics
### 4 - Source and target replication protection containers
### 5 - Replication policy
### 6 - Source->target and target->source protection container mapping.
### </summary>
function New-ASRResources()
{
    Write-Host -ForegroundColor Green "`nCreating new ASR resources."

    $vault, $vaultResourcegroup = Set-RecoveryServicesVaultConfiguration -Name $vaultName `
        -ResourceGroupName $vaultResourceGroupName -Location $targetLocation
    $sourceFabric, $targetFabric = New-ReplicationFabric
    $sourceContainer, $targetContainer = New-ReplicationProtectionContainer
    $replicationPolicy = New-ReplicationPolicy
    $sourceTargetMapping, $targetSourceMapping = New-ReplicationProtectionContainerMapping

    # Adding required policy parameters
    $policyParams.Add([PolicyParameter]::replicationPolicyName, $replicationPolicyName)
    $policyParams.Add([PolicyParameter]::sourceContainerName, $sourceContainer.Name)
    $policyParams.Add([PolicyParameter]::targetContainerName, $targetContainer.Name)
    $policyParams.Add([PolicyParameter]::sourceFabricName, $sourceFabric.Name)
    $policyParams.Add([PolicyParameter]::targetFabricName, $targetFabric.Name)
    $policyParams.Add([PolicyParameter]::vaultId, $vault.Id)
    $policyParams.Add([PolicyParameter]::vaultResourceGroupId, $vaultResourcegroup.ResourceId)
}
#EndRegion

#Region Policy

#Region Log

### <summary>
### Logging all policy parameters.
### </summary>
function Log-PolicyParameters()
{
    Write-Host -ForegroundColor Green "`nPolicy Parameters:`n" $(Out-String -InputObject `
        $policyParams)

    $OutputLogger.Log(
        $MyInvocation,
        "`nPolicy Parameters:`n",
        [LogType]::OUTPUT)

    $OutputLogger.LogObject(
        $MyInvocation,
        $policyParams,
        [LogType]::OUTPUT)
}

### <summary>
### Logging policy definition.
### </summary>
function Log-PolicyDefinition()
{
    Write-Host -ForegroundColor Green "`nPolicy Definition:`n" $(Out-String -InputObject `
        $policyDefinition)

    $OutputLogger.Log(
        $MyInvocation,
        "`nPolicy Definition Information:`n",
        [LogType]::OUTPUT)

    $OutputLogger.LogObject(
        $MyInvocation,
        $policyDefinition,
        [LogType]::OUTPUT)
}

### <summary>
### Logging policy assignment.
### </summary>
function Log-PolicyAssignment()
{
    Write-Host -ForegroundColor Green "`nPolicy Assignment:`n" $(Out-String -InputObject `
        $policyAssignment)

    $OutputLogger.Log(
        $MyInvocation,
        "`nPolicy Assignment Information:`n",
        [LogType]::OUTPUT)

    $OutputLogger.LogObject(
        $MyInvocation,
        $policyAssignment,
        [LogType]::OUTPUT)
}
#EndRegion

### <summary>
### Assigns a new Owner role to the managed identity.
### </summary>
function Add-RoleAssignments()
{
    $objectId = $policyAssignment.Identity.principalId
    $sleepTimeInSeconds = 10
    $retryLimit = 15
    $retryCount = 0

    # Time delay between creation of service principal and delegation of role is causing the
    # NotFound error. Thus, introducing a sleep with limit (150s) to ensure service principal
    # exists.
    Write-Host -ForegroundColor Green "Waiting for the managed identity ("$objectId") creation to" `
        "complete."
    $servicePrincipal = Get-AzADServicePrincipal -ObjectId $objectId

    while (($null -eq $servicePrincipal) -and ($retryCount -lt $retryLimit))
    {
        $retryCount++
        Start-Sleep -Seconds $sleepTimeInSeconds

        $servicePrincipal = Get-AzADServicePrincipal -ObjectId $objectId
    }

    if ($null -ne $servicePrincipal)
    {
        $roleCreationLimit = 3
        $roleCreationCount = 0
        $isRoleCreationRequired = $true
        $message = "Creating new role assignments for managed identity with PrincipalId:" + `
            $objectId + "`n"

        Write-Host -ForegroundColor Green $message        
        $OutputLogger.Log(
            $MyInvocation,
            $message,
            [LogType]::INFO)

        while ($isRoleCreationRequired -and ($roleCreationCount -lt $roleCreationLimit))
        {
            $roleCreationCount++

            try
            {
                $suppressOutput = New-AzRoleAssignment -ObjectId $objectId -ResourceGroupName `
                    $sourceResourceGroupName -RoleDefinitionName Owner
                $suppressOutput = New-AzRoleAssignment -ObjectId $objectId -ResourceGroupName `
                    $targetResourceGroupName -RoleDefinitionName Owner
                $suppressOutput = New-AzRoleAssignment -ObjectId $objectId -ResourceGroupName `
                    $vaultResourceGroupName -RoleDefinitionName Owner
                $isRoleCreationRequired = $false
            }
            catch
            {
                $message = "Role assignment addition failed due to -"
                $message += "`n$(Out-String -InputObject $PSItem)`n"
                $message += "Retrying role assignment addition."
                
                Write-Host -ForegroundColor Yellow -BackgroundColor Black $message 
            
                $OutputLogger.Log($MyInvocation, $message, [LogType]::WARNING)
            }
        }

        if ($isRoleCreationRequired)
        {
            $message = [Errors]::RoleAssignmentFailed($objectId, "Owner", $roleCreationCount)
            
            Write-Host -ForegroundColor Yellow -BackgroundColor Black $message 

        }
    }
}

### <summary>
### Creates a new policy definition, if necessary.
### </summary>
### <return>Policy definition.</return>
function New-PolicyDefinition()
{
    $policyDefinitionDescription = [ConstantStrings]::policyDefinitionName + "`nPolicy " + `
        "definition URL: " + [ConstantStrings]::policyDefinitionUrl + "`nPolicy parameters " + `
        "URL: " + [ConstantStrings]::policyParametersUrl
    $policyDefinitionCategory = '{"category":"Disaster Recovery"}'

    $policyDefinition = Get-AzPolicyDefinition -Name ([ConstantStrings]::policyDefinitionName) `
        -SubscriptionId $subscriptionId -ErrorAction Ignore

    if ($null -eq $policyDefinition)
    {
        Write-Host -ForegroundColor Green "Creating new policy definition - "`
            ([ConstantStrings]::policyDefinitionName)

        $policyDefinition = New-AzPolicyDefinition -Mode All -SubscriptionId $subscriptionId -Name `
            ([ConstantStrings]::policyDefinitionName) -Policy `
            ([ConstantStrings]::policyDefinitionUrl) -Parameter `
            ([ConstantStrings]::policyParametersUrl) -Description $policyDefinitionDescription `
            -Metadata $policyDefinitionCategory
    }

    Log-PolicyDefinition

    return $policyDefinition
}

### <summary>
### Creates a new policy assignment.
### </summary>
### <return>Policy assignment.</return>
function New-PolicyAssignment()
{
    $policyAssignmentName = [ConstantStrings]::policyAssignmentPrefix + $(New-Guid).Guid

    if ([ConstantStrings]::policyAssignmentNameMaxLength -lt $policyAssignmentName.Length)
    {
        $policyAssignmentName =
            $policyAssignmentName.Substring(0, [ConstantStrings]::policyAssignmentNameMaxLength)
    }

    $targetResourceGroupDeploymentUrl = [ConstantStrings]::portalResourceLinkPrefix + `
        $policyParams[[PolicyParameter]::targetResourceGroupId] + "/" + `
        [ConstantStrings]::deploymentSuffix
    $vaultResourceGroupDeploymentUrl = [ConstantStrings]::portalResourceLinkPrefix + `
        $policyParams[[PolicyParameter]::vaultResourceGroupId] + "/" +
        [ConstantStrings]::deploymentSuffix
    $policyAssignmentDescription = "`nAvailabilitySet ResourceGroup Deployments -> " + `
        $targetResourceGroupDeploymentUrl + "`nVault ResourceGroup Deployments -> " + `
        $vaultResourceGroupDeploymentUrl + "`nDeployment Name Format -> " + `
        [ConstantStrings]::resourceDeploymentFormat

    $sourceResourceGroup = Get-AzResourceGroup -Name $sourceResourceGroupName

    $assignedPolicies = Get-AzPolicyAssignment -PolicyDefinitionId `
        $policyDefinition.PolicyDefinitionId -Scope $sourceResourceGroup.ResourceId -ErrorAction `
        Ignore

    if ($null -ne $assignedPolicies)
    {
        $title = "`nThe following assignments already exist with the same policy definition " + `
        "and scope:`n" + ($assignedPolicies.Name -Join ",`n")
        $message = "`nDo you want to proceed with the policy assignment?"
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Yes"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "No"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $choice=$host.ui.PromptForChoice($title, $message, $options, 1)

        if (1 -eq $choice)
        {
            throw [Errors]::AbortingPolicyAssignment($assignedPolicies.Name)
        }
    }

    $policyAssignment = New-AzPolicyAssignment -Name $policyAssignmentName -Description `
        $policyAssignmentDescription -Location $msiLocation -Scope $sourceResourceGroup.ResourceId `
        -PolicyDefinition $policyDefinition -PolicyParameterObject $policyParams -AssignIdentity `
        -DisplayName $policyAssignmentName

    Log-PolicyAssignment
    Add-RoleAssignments

    return $policyAssignment
}
#EndRegion

#Region Main

#Region Misc

### <summary>
### Logging the parameters passed during this script run.
### </summary>
function Log-ScriptParameters()
{
    $commandName = $PSCmdlet.MyInvocation.InvocationName;
    $parameterList = (Get-Command -Name $CommandName).Parameters;

    foreach ($parameter in $parameterList) {
        $parameters = Get-Variable -Name $Parameter.Values.Name -ErrorAction SilentlyContinue;
    }

    $OutputLogger.LogObject(
        $MyInvocation,
        $parameters,
        [LogType]::INFO)
}

### <summary>
### Logging all additional helpful URLs.
### </summary>
function Log-AdditionalURLs()
{
    $complianceDetailedBladeScope = '["/' + [ConstantStrings]::subscriptions + '/' + `
        $subscriptionId + '"]'
    $assignmentCompliancePage = [ConstantStrings]::portalPolicyDetailedComplianceBladePrefix + `
        [uri]::EscapeDataString($policyAssignment.ResourceId) + "/" + [ConstantStrings]::scopes + `
        "/" + [uri]::EscapeDataString($complianceDetailedBladeScope)
    $vaultResourceGroupDeploymentUrl = [ConstantStrings]::portalResourceLinkPrefix + `
        $policyParams[[PolicyParameter]::vaultResourceGroupId] + "/" +
        [ConstantStrings]::deploymentSuffix
    $targetResourceGroupDeploymentUrl = [ConstantStrings]::portalResourceLinkPrefix + `
        $policyParams[[PolicyParameter]::targetResourceGroupId] + "/" + `
        [ConstantStrings]::deploymentSuffix
    $replicatedItemsListUrl = [ConstantStrings]::portalResourceLinkPrefix + `
        $policyParams[[PolicyParameter]::vaultId] + "/" + `
        [ConstantStrings]::replicationProtectedItems
    $replicationJobsUrl = [ConstantStrings]::portalResourceLinkPrefix + `
        $policyParams[[PolicyParameter]::vaultId] + "/" + [ConstantStrings]::replicationJobs

    $urlOutput = "`nPolicy Compliance Page: " + [ConstantStrings]::portalPolicyCompliancePageLink
    $urlOutput += "`nDetailed Policy Assignment Compliance Page: " + $assignmentCompliancePage
    $urlOutput += "`nVault ResourceGroup Deployments: " + $vaultResourceGroupDeploymentUrl
    $urlOutput += "`nAvSet ResourceGroup Deployments: " + $targetResourceGroupDeploymentUrl
    $urlOutput += "`nReplicated Items List: " + $replicatedItemsListUrl
    $urlOutput += "`nSite Recovery Jobs: " + $replicationJobsUrl
    $urlOutput += "`n"


    Write-Host -ForegroundColor Green "Additional URLs:`n"$urlOutput

    $OutputLogger.Log(
        $MyInvocation,
        "`nAdditional URLs:`n" + $urlOutput,
        [LogType]::OUTPUT)
}

### <summary>
### Logging next steps. Can be removed later and shifted to a README.
### </summary>
function Log-NextSteps()
{
    $notes = "`n1. Go to the Detailed Policy Assignment Compliance page using the URL given above."
    $notes += "`n2. Wait ~15 mins for the policy to start."

    Write-Host -ForegroundColor Green "`nNext Steps:`n"$notes

    $OutputLogger.Log(
        $MyInvocation,
        "`nNext Steps:`n" + $notes,
        [LogType]::OUTPUT)
}
#EndRegion

#Region Resources

### <summary>
### Main flow for prerequisite resources creation.
### </summary>
function Start-PrerequisiteResourceCreation()
{
    Write-Host -ForegroundColor Green "`nStarting prerequisite resources creation."

    New-AzureResources
    New-ASRResources

    Log-PolicyParameters
}
#EndRegion

### <summary>
### Main flow for deployment of policy based replication setup.
### </summary>
function New-PolicyBasedReplicationSetup()
{
    Write-Host -ForegroundColor Green "Starting policy based replication setup."

    $policyParams = New-Object System.Collections.Hashtable

    Set-Context
    Confirm-ScriptParameters -SourceLocation ([ref]$sourceLocation) -TargetLocation `
        ([ref]$targetLocation) -MsiLocation ([ref]$msiLocation) -CacheStorageAccountName `
        ([ref]$cacheStorageAccountName) -TargetResourceGroupName ([ref]$targetResourceGroupName) `
        -RecoveryNetworkName ([ref]$recoveryNetworkName) -AddressPrefix ([ref]$addressPrefix)
    Start-PrerequisiteResourceCreation
    $policyDefinition = New-PolicyDefinition
    $policyAssignment = New-PolicyAssignment

    Log-AdditionalURLs
    Log-NextSteps
}
#EndRegion

$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop"
$StartTime = Get-Date -Format 'dd-MM-yyyy-HH-mm-ss'
$OutputLogger = [Logger]::new('PolicyBasedReplication-' + $StartTime, $null)
$OutputLogger.Log(
    $MyInvocation,
    "StartTime - $StartTime",
    [LogType]::INFO)

try
{
    Log-ScriptParameters
    
    New-PolicyBasedReplicationSetup
}
catch
{
    Write-Host -ForegroundColor Red -BackgroundColor Black $(Out-String -InputObject $PSItem)

    $OutputLogger.LogObject(
        $MyInvocation,
        $PSItem,
        [LogType]::ERROR)
}
finally
{
    $EndTime = Get-Date -Format 'dd-MM-yyyy-HH-mm-ss'
    $OutputLogger.Log(
        $MyInvocation,
        "EndTime - $EndTime",
        [LogType]::INFO)
}