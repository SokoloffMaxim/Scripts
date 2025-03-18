<#
.SYNOPSIS
    Converts Azure DevOps service connections from Service Principal (SP) to Workload Identity Federation (WIF) or reverts them back to SP.

.DESCRIPTION
    This script automates the conversion of Azure DevOps service connections from Service Principal (SP) authentication to Workload Identity Federation (WIF), a modern, secure, and token-based authentication method. It also supports reverting service connections back to SP if needed. 
    The script is designed to simplify identity management, reduce the risk of credential leakage, and enhance security in Azure DevOps environments.

    Based on the original implementation from:
    https://github.com/devopsabcs-engineering/azure-devops-workload-identity-federation/blob/main/scripts/Convert-ServicePrincipals.ps1

.REQUIREMENTS
    - The `_ca` Administrator account must be added to the **Endpoint Administrators** group at the **Project level** in Azure DevOps.
    - The **Application Administrator** role must be activated for the `_ca` Administrator account via **Privileged Identity Management (PIM)** to manage the service connections.
    - Ensure the script has access to the file path used for storing service connections:  
      i.e **`../data/service_connections.json`**. Note: this path can be modified if needed.
      The script fetches and writes service connection details to this file. Modify the path if necessary to suit your environment.
    - Ensure the script runs with "-refreshServiceConnectionsIfTheyExist  $true" flag every new run if the old exported file still exists in the json path folder.

.PARAMETER projectName
    (Optional) The name of the Azure DevOps project. If not provided, the script will prompt for it.

.PARAMETER organizationUrl
    (Optional) The URL of the Azure DevOps organization. If not provided, the script will prompt for it.

.PARAMETER isProductionRun
    (Optional) Set to `$true` to perform actual conversions/reversions. Default is `$false` (dry-run mode).

.PARAMETER revertAll
    (Optional) Set to `$true` to revert all service connections back to Service Principal (SP). Default is `$false`.

.PARAMETER refreshServiceConnectionsIfTheyExist
    (Optional) Set to `$true` to refresh service connections even if they already exist. Default is `$false`.

.PARAMETER ConfirmProcessing
    (Optional) Set to `$true` to prompt the user before processing each service connection. 
    Set to `$false` to run without user confirmation. Default is `$true`.

.PARAMETER ProcessSharedConnections
    (Optional) Set to `$true` to process shared service connections. 
    Set to `$false` to skip them. Default is `$true`.

.EXAMPLE
    # Convert Service Connections (Interactive Mode with Prompts)
    .\Convert-ServicePrincipals.ps1 -isProductionRun $true

.EXAMPLE
    # Convert Service Connections for a Specific Project and Organization (Non-Interactive)
    .\Convert-ServicePrincipals.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isProductionRun $true -ConfirmProcessing $false

.EXAMPLE
    # Revert All Service Connections to Service Principal (Non-Interactive)
    .\Convert-ServicePrincipals.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isProductionRun $true -revertAll $true -refreshServiceConnectionsIfTheyExist $true -ConfirmProcessing $false

.EXAMPLE
    # Skip Shared Service Connections but Run Fully Automated
    .\Convert-ServicePrincipals.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isProductionRun $true -ProcessSharedConnections $false -ConfirmProcessing $false

.EXAMPLE
    # Dry-Run Mode (No Actual Changes, Just Simulation)
    .\Convert-ServicePrincipals.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isProductionRun $false

.EXAMPLE
    # Convert Service Connections and Process Shared Connections Automatically
    .\Convert-ServicePrincipals.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isProductionRun $true -ProcessSharedConnections $true -ConfirmProcessing $false

.DEPENDENCIES
    - Azure CLI: Ensure the Azure CLI is installed and configured (`az login`).
    - Azure DevOps CLI: Ensure the Azure DevOps CLI extension is installed (`az extension add --name azure-devops`).
    - PowerShell: The script uses standard PowerShell modules and does not require additional installations.

.NOTES
    Original Source: https://github.com/devopsabcs-engineering/azure-devops-workload-identity-federation/blob/main/scripts/Convert-ServicePrincipals.ps1

    MODIFICATIONS AND ADDITIONS:
    - Made `-projectName` and `-organizationUrl` optional. If not provided, the script will prompt the user to enter them.
    - Added improved error handling to ensure the user cannot proceed without providing a valid `projectName` or `organizationUrl`.
    - Enhanced user interaction with interactive prompts for missing inputs and clear error messages.
    - Refactored code for better readability and maintainability.
    - Added parameters for **automated execution** (`-ConfirmProcessing` and `-ProcessSharedConnections`).
    - Included detailed examples showcasing **interactive and non-interactive** execution scenarios.
    - Documented the necessary Azure DevOps and Azure AD permissions required for execution.

#>

# Define all parameters
param (
    [int]    $jsonDepth = 10,
    [bool]   $isProductionRun = $false,
    [bool]   $refreshServiceConnectionsIfTheyExist = $false,
    [string] $apiVersion = "7.1",
    [bool]   $revertAll = $false,
    [string] $projectName = $null,
    [string] $organizationUrl = $null,
    [bool]   $ConfirmProcessing = $false,
    [bool]   $ProcessSharedConnections = $false
)

# Initialize counters and other global variables
$counters = @{
    # General tracking
    TotalArmServiceConnections                = 0  # Total detected
    ProcessedArmServiceConnections            = 0  # Successfully processed
    SkippedArmServiceConnections              = 0  # Skipped due to various reasons

    # Shared Service Connection tracking
    SharedArmServiceConnections               = 0  # Number of shared service connections
    SharedArmServiceConnectionsProcessed      = 0  # Shared connections actually processed

    # Authentication type tracking
    ArmServiceConnectionsWithWorkloadIdentityFederationAutomatic    = 0
    ArmServiceConnectionsWithWorkloadIdentityFederationManual       = 0
    ArmServiceConnectionsWithServicePrincipalAutomatic              = 0
    ArmServiceConnectionsWithServicePrincipalManual                 = 0
    ArmServiceConnectionsWithManagedIdentity                        = 0
    ArmServiceConnectionsWithPublishProfile                         = 0

    # Federated Credentials tracking
    FederatedCredentialsCreatedManually      = 0

    # Conversion & Reversion tracking
    ArmServiceConnectionsConverted           = 0  # Successful conversions
    ArmServiceConnectionsNotConverted        = 0  # Failed conversions
    ArmServiceConnectionsReverted            = 0  # Successful reversions
    ArmServiceConnectionsNotReverted         = 0  # Failed reversions
}

$hashTableAdoResources = @{}

# Define all functions at the top of the script

# Retrieves an overview of Azure DevOps organizations linked to a given tenant.
function Get-AzureDevOpsOrganizationOverview {
    [CmdletBinding()]
    param (
        [string] $tenantId
    )
    # Disconnect-AzAccount
    Clear-AzContext -Force

    $login = Connect-AzAccount -Tenant $tenantId

    if (!$login) {
        Write-Error 'Error logging in and validating your credentials.'
        return;
    }

    $adoResourceId = "499b84ac-1321-427f-aa17-267ca6975798" # Azure DevOps app ID
    $msalToken = (Get-AzAccessToken -ResourceUrl $adoResourceId).Token 

    if (!$tenantId) {
        $tenantId = $msalToken.tenantId
        Write-Verbose "Set TenantId to $tenantId (retrieved from MSAL token)"
    }

    # URL retrieved thanks to developer mod at page https://dev.azure.com/<organizationName>/_settings/organizationAad
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"    
    $headers.Add("Authorization", "Bearer ${msalToken}")

    $response = Invoke-WebRequest -Uri "https://aexprodweu1.vsaex.visualstudio.com/_apis/EnterpriseCatalog/Organizations?tenantId=$tenantId" `
        -Method get -ContentType "application/json" `
        -Headers $headers | Select-Object -ExpandProperty content | ConvertFrom-Csv

    $responseJson = $response | ConvertTo-Json -Depth $jsonDepth

    $outputFile = "../data/organizations_${tenantId}.json"
    Set-Content -Value $responseJson -Path $outputFile
}

# Fetches the Azure DevOps organization ID by its name.
function Get-OrganizationId {
    param (
        [Parameter(Mandatory = $true)]
        [string] $organizationName,
        
        [Parameter(Mandatory = $true)]
        [string] $tenantId
    )

    $outputFile = "../data/organizations_${tenantId}.json"

    # Ensure the organizations file exists, fetch if missing
    if (-not (Test-Path -Path $outputFile -PathType Leaf)) {
        Write-Output "File '$outputFile' not found. Fetching organizations..."
        Get-AzureDevOpsOrganizationOverview -tenantId $tenantId
    }

    # Read and parse the JSON file
    $allOrganizationsJson = Get-Content -Path $outputFile | ConvertFrom-Json

    # Find organization by name
    $organizationFound = $allOrganizationsJson | Where-Object { $_."Organization Name" -eq $organizationName }

    if ($organizationFound) {
        $organizationId = $organizationFound."Organization Id"

        # Ensure that we return only the ID without printing unnecessary output
        if ($organizationId) {
            Write-Output "Successfully found Organization ID: $organizationId"
            return $organizationId
        }
    }

    # Organization not found
    Write-Warning "Organization '$organizationName' not found in tenant '$tenantId'."
    return $null
}

# Retrieves a list of all projects under a given Azure DevOps organization.
function Get-Projects {
    param (
        [string] $organizationUrl
    )

    $allProjects = @()
    $token = $null

    do {
        $projectsRawJson = if ($token) {
            az devops project list --organization $organizationUrl --continuation-token $token
        } else {
            az devops project list --organization $organizationUrl
        }

        $projectsRaw = $projectsRawJson | ConvertFrom-Json -Depth $jsonDepth
        $allProjects += $projectsRaw.value
        $token = $projectsRaw.ContinuationToken
    }
    while ($null -ne $token)

    return $allProjects
}

# Fetches all service connections for a given Azure DevOps project and organization.
function Get-ServiceConnections {
    param (
        [Parameter(Mandatory = $true)]
        [string] $tenantId,
        [Parameter(Mandatory = $true)]
        [string] $serviceConnectionJsonPath,
        [string] $organizationsOutputFile = "organizations_${tenantId}.json",
        [bool]   $refreshServiceConnectionsIfTheyExist = $false,
        [string] $filterType = "azurerm",
        [string] $projectName = $null,
        [string] $organizationUrl = $null
    )

    # Ensure organization data is available
    if (!(Test-Path $organizationsOutputFile)) {
        Write-Output "File $organizationsOutputFile not found. Fetching organizations..."
        Get-AzureDevOpsOrganizationOverview -tenantId $tenantId
    }

    # Load organization data
    $allOrganizations = Get-Content -Path $organizationsOutputFile | ConvertFrom-Json

    # Check if service connections should be skipped
    if ((Test-Path $serviceConnectionJsonPath) -and (-not $refreshServiceConnectionsIfTheyExist)) {
        Write-Output "File $serviceConnectionJsonPath already exists. Skipping fetch."
        return $true
    }

    $allServiceConnections = @()

    foreach ($organization in $allOrganizations) {
        $organizationName = $organization."Organization Name"
        $organizationId = $organization."Organization Id"
        $organizationUrl = $organization."Url"

        # Get project(s) for processing
        $projects = if ($projectName) { @(@{ name = $projectName }) } else { Get-Projects -organizationUrl $organizationUrl }

        foreach ($project in $projects) {
            $currentProjectName = $project.name
            Write-Output "Fetching service connections for Org: ${organizationName}, Proj: ${currentProjectName}..."

            # Get service connections for the specific project
            $serviceEndpointsJson = az devops service-endpoint list --organization $organizationUrl --project $currentProjectName
            $serviceEndpoints = $serviceEndpointsJson | ConvertFrom-Json -Depth $jsonDepth

            if (!$serviceEndpoints) {
                Write-Output "No service endpoints found for project '$currentProjectName'."
                continue
            }

            # Filter service connections by type (default: azurerm)
            $armServiceEndpoints = $serviceEndpoints | Where-Object { $_.type -eq $filterType }

            foreach ($armServiceEndpoint in $armServiceEndpoints) {
                $endpointId = $armServiceEndpoint.id
                $endpointProjectRefs = $armServiceEndpoint.serviceEndpointProjectReferences

                # Validate endpoint references
                if (!$endpointProjectRefs) {
                    Write-Warning "Skipping Service Connection '$($armServiceEndpoint.name)' due to missing project reference."
                    continue
                }

                foreach ($ref in $endpointProjectRefs) {
                    if ($ref.projectReference.name -eq $currentProjectName) {
                        $allServiceConnections += $armServiceEndpoint
                        Write-Output "Matched Service Connection: $($armServiceEndpoint.name) in '$currentProjectName'"

                        $projSvcEndpoint = @{
                            "organizationName" = $organizationName
                            "organizationId"   = $organizationId
                            "projectName"      = $currentProjectName
                            "serviceEndpoint"  = $armServiceEndpoint
                        }

                        if ($hashTableAdoResources.ContainsKey($endpointId)) {
                            Write-Warning "Service Connection $endpointId already exists. Checking if shared..."
                            if (-not $armServiceEndpoint.isShared -and -not $refreshServiceConnectionsIfTheyExist) {
                                throw "Conflict: endpointId $endpointId exists but is not shared! Use -refreshServiceConnectionsIfTheyExist `$true` to update."
                            }
                            Write-Output "Updating existing non-shared Service Connection: '$($armServiceEndpoint.name)'"
                        }

                        $hashTableAdoResources[$endpointId] = $projSvcEndpoint
                    }
                }
            }
        }
    }

    # Save results
    if ($allServiceConnections.Count -gt 0) {
        Write-Output "Saving service connections to $serviceConnectionJsonPath..."
        $allServiceConnections | ConvertTo-Json -Depth $jsonDepth | Set-Content -Path $serviceConnectionJsonPath
    } else {
        Write-Warning "No service connections found to save."
    }

    return $true
}

# Converts a Service Principal-based service connection to Workload Identity Federation.
function ConvertTo-WorkloadIdentityFederation {
    param (
        [string] $body,
        [string] $accessToken,
        [string] $organizationName,
        [string] $organizationId,
        [string] $endpointId,
        [string] $serviceConnectionName,
        [string] $appObjectId,
        [string] $projectName
    )

    # Ensure required parameters are not empty
    if (-not $organizationId -or $organizationId -eq "") {
        Write-Error "ERROR: organizationId is missing. Cannot proceed."
        return
    }
    if (-not $appObjectId -or $appObjectId -eq "") {
        Write-Error "ERROR: appObjectId is missing. Ensure the service connection is linked to an App Registration."
        return
    }

    # API Request Headers
    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }

    # API URI for converting authentication scheme
    $uri = "https://dev.azure.com/${organizationName}/_apis/serviceendpoint/endpoints/${endpointId}?operation=ConvertAuthenticationScheme&api-version=7.1"

    # Debugging Output
    Write-Output "INFO: Calling API to convert authentication scheme..."
    Write-Output "API URL: $uri"
    Write-Output "Request Body: $body"

    try {
        Write-Output "DEBUG: Sending JSON to Azure DevOps API..."
        Write-Output $body
        
        # Convert Service Connection to Workload Identity Federation (WIF)
        $response = Invoke-RestMethod -Uri $uri -Method 'PUT' -Headers $headers -Body $body

        if ($response) {
            Write-Output "API Request Succeeded. Service Connection converted to Workload Identity Federation."
        } else {
            Write-Warning "API Response is empty. Conversion might not have succeeded."
            return $null
        }
    }
    catch {
        Write-Error "ERROR: API request failed - $_"
        return $null
    }
}


# Retrieves an Azure access token for interacting with Azure DevOps APIs.
function Get-AzureAccessToken {
    param (
        [string] $resource = "499b84ac-1321-427f-aa17-267ca6975798" # Azure DevOps resource ID
    )

    $accessToken = az account get-access-token --resource $resource --query accessToken -o tsv
    if (-not $accessToken) {
        Write-Output "ERROR: Failed to retrieve access token. Ensure you are logged in with 'az login'."
        return $null
    }
    return $accessToken
}

# Reverts a Workload Identity Federation-based service connection back to Service Principal authentication.
function Restore-WorkloadIdentityFederation {
    param (
        [string] $body,
        [string] $accessToken,
        [string] $organizationName,
        [string] $organizationId,
        [string] $endpointId,
        [string] $serviceConnectionName,
        [string] $appObjectId,
        [string] $projectName
    )

    # Headers for the REST API request
    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }

    # Construct API URI
    $uri = "https://dev.azure.com/${organizationName}/_apis/serviceendpoint/endpoints/${endpointId}?operation=ConvertAuthenticationScheme&api-version=7.1"

    # Additional Information
    Write-Output "INFO: Calling API at URL: $uri"
    Write-Output "INFO: API Request Body: $body"

    Try {
        # Perform API Request
        $response = Invoke-RestMethod -Uri $uri -Method 'PUT' -Headers $headers -Body $body

        # Debugging API Response
        if ($response) {
            Write-Output "API Request Succeeded. Response:"
            Write-Output ($response | ConvertTo-Json -Depth $jsonDepth)
        } else {
            Write-Warning "API Response is empty. Reversion might not have succeeded."
        }

        return $response
    }
    Catch {
        $errorMessage = $_.Exception.Message
        Write-Error "ERROR: API request failed - $errorMessage"

        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $detailedError = $_.ErrorDetails.Message
            Write-Error "Detailed API Error: $detailedError"
        }

        return $null  # Ensure that we return null in case of error
    }
}

# Constructs the JSON payload for API requests to update service connections.
function Get-Body {
    param (
        [string] $id,
        [string] $type,
        [string] $authorizationScheme,
        [array] $serviceEndpointProjectReferences
    )

    # Ensure project references are included
    if (-not $serviceEndpointProjectReferences -or $serviceEndpointProjectReferences.Count -eq 0) {
        throw "Missing project reference in service connection update payload"
    }

    # Create a custom object to hold the body of the request.
    $myBody = [PSCustomObject]@{
        id                               = $id
        type                             = $type
        authorization                    = [PSCustomObject]@{
            scheme = $authorizationScheme
        }
        serviceEndpointProjectReferences = $serviceEndpointProjectReferences
    }

    # Convert the custom object to JSON.
    $myBodyJson = $myBody | ConvertTo-Json -Depth $jsonDepth

    return $myBodyJson
}

# This function retrieves a human-readable authentication scheme name for a given Azure DevOps service connection.
function Get-AuthenticodeMode {
    param (
        [object] $serviceConnection
    )

    $authorizationScheme = $serviceConnection.authorization.scheme
    $creationMode = $serviceConnection.data.creationMode

    # Define mapping of schemes to human-readable formats
    $authSchemeMap = @{
        "WorkloadIdentityFederation" = "Workload Identity Federation"
        "ServicePrincipal"           = "Service Principal"
        "ManagedServiceIdentity"     = "Managed Identity"
        "PublishProfile"             = "Publish Profile"
    }

    # Retrieve the formatted name from the hash table or throw an error if not found
    if ($authSchemeMap.ContainsKey($authorizationScheme)) {
        return if ($creationMode) { "$($authSchemeMap[$authorizationScheme]) ($creationMode)" } else { $authSchemeMap[$authorizationScheme] }
    }
    else {
        throw "Unexpected authorization scheme: $authorizationScheme"
    }
}


# Main script logic
try {
    # Login to Azure and Get Service Connections
    Write-Output 'Logging into Azure... Please ensure you have the correct permissions.'

    az account clear
    $login = az login --only-show-errors

    if (!$login) {
        Write-Error 'Error logging in. Ensure your credentials are valid.'
        exit 1
    }

    # Retrieve Tenant ID
    $accountJson = az account show | ConvertFrom-Json
    $currentTenantId = $accountJson.tenantId
    Write-Output "Current Tenant ID: $currentTenantId"

    # Prompt for Organization URL if not provided
    if (-not $organizationUrl) {
        $organizationUrl = Read-Host "Enter your Azure DevOps organization URL (e.g., https://dev.azure.com/your-organization)"
    }

    # Extract Organization Name from URL
    if ($organizationUrl -match "https://dev\.azure\.com/([^/]+)") {
        $organizationName = $matches[1]
        Write-Output "Using organization name: $organizationName"
    } else {
        Write-Error "ERROR: Invalid organization URL format. Expected format: https://dev.azure.com/your-organization"
        exit 1
    }

    # Retrieve Organization ID
    $organizationId = Get-OrganizationId -organizationName $organizationName -tenantId $currentTenantId
    if (-not $organizationId) {
        Write-Error "ERROR: Failed to retrieve Organization ID. Ensure the organization exists in Azure DevOps."
        exit 1
    }
    Write-Output "Organization ID retrieved: $organizationId"

    # Prompt for Project Name if not provided
    if (-not $projectName) {
        $projectName = Read-Host "Enter the Azure DevOps project name"
    }

    # Validate Project Name
    if ([string]::IsNullOrWhiteSpace($projectName)) {
        Write-Error "[ERROR] A project name is required. Exiting..."
        exit 1
    }
    Write-Output "Using project name: $projectName"

    # Define Service Connection JSON Path
    $serviceConnectionJsonPath = "../data/service_connections_${currentTenantId}.json"

    # Fetch Service Connections
    $exported = Get-ServiceConnections `
        -serviceConnectionJsonPath $serviceConnectionJsonPath `
        -refreshServiceConnectionsIfTheyExist $refreshServiceConnectionsIfTheyExist `
        -tenantId $currentTenantId `
        -projectName $projectName `
        -organizationUrl $organizationUrl

    if (-not $exported) {
        Write-Error "ERROR: Failed to retrieve service connections."
        exit 1
    }
}
catch {
    Write-Error "An unexpected error occurred: $_"
    exit 1
}

# Prompt user for processing shared service connections
if (-not $ProcessSharedConnections) {
    Write-Output "Skipping shared service connections as per parameter setting."
} else {
    Write-Output "Processing shared service connections as per parameter setting."
}

Write-Output ($processSharedConnections -eq "N" ? "Skipping shared service connections." : "Processing shared service connections.")

# Process service connections if they were successfully exported
if ($exported) {
    Write-Output "`nProcessing Service Connections for Project: '$projectName'..."

    # Loop through all service connections in the project
    foreach ($entry in $hashTableAdoResources.Values) {
        $serviceConnection = $entry.serviceEndpoint
        $organizationName = $entry.organizationName
        $organizationId = $entry.organizationId
        $serviceConnectionName = $serviceConnection.name

        # Ensure isShared property exists before checking its value
        $isShared = $false
        if ($serviceConnection.PSObject.Properties.Name -contains "isShared") {
            $isShared = $serviceConnection.isShared
        }
        $sharedStatus = if ($isShared) { "Yes" } else { "No" }

        # Always count shared service connections, even if skipped
        if ($isShared) {
            $counters.SharedArmServiceConnections++
        }

        # Skip shared service connections if the user opted out
        if ($isShared -and -not $ProcessSharedConnections) {
            Write-Output "Skipping shared service connection: '$serviceConnectionName' as per user preference."
            $counters.SkippedArmServiceConnections++
            continue
        }

        # Increment total counter
        $counters.TotalArmServiceConnections++

        # Only increment shared counter if we are processing shared connections
        if ($isShared -and $ProcessSharedConnections) {
            $counters.SharedArmServiceConnectionsProcessed++
        }

        Write-Output "`n-----------------------"
        Write-Output "Processing Service Connection: $serviceConnectionName"

        # Extract details
        $applicationRegistrationClientId = $serviceConnection.authorization.parameters.serviceprincipalid
        $tenantId = $serviceConnection.authorization.parameters.tenantid
        $authorizationScheme = $serviceConnection.authorization.scheme
        $endpointId = $serviceConnection.id
        $revertSchemeDeadline = $serviceConnection.data.revertSchemeDeadline
        $TimeSpan = if ($revertSchemeDeadline) { $revertSchemeDeadline - (Get-Date -AsUTC) } else { [timespan]::Zero }
        $totalDays = [math]::Round($TimeSpan.TotalDays, 2)
        $canRevert = $totalDays -gt 0

        # Display service connection details
        Write-Output "App Registration Client Id   : $applicationRegistrationClientId"
        Write-Output "Tenant ID                    : $tenantId"
        Write-Output "Authorization Scheme         : $authorizationScheme"
        Write-Output "Service Connection Name      : $serviceConnectionName"
        Write-Output "Endpoint ID                  : $endpointId"
        Write-Output "Revert Scheme Deadline       : $revertSchemeDeadline"
        Write-Output "Can Revert or Convert        : $canRevert"
        Write-Output "Total Days left to Revert    : $totalDays"
        Write-Output "Shared Status                : $sharedStatus"

        # Prompt for confirmation
        if ($ConfirmProcessing) {
            $confirmation = Read-Host "Proceed with processing Service Connection '$serviceConnectionName'? (Y/N)"
            if ($confirmation.ToUpper() -ne "Y") {
                Write-Output "Skipping Service Connection '$serviceConnectionName' as per user request."
                $counters.SkippedArmServiceConnections++
                continue
            }
        } else {
            Write-Output "Automatically proceeding with Service Connection '$serviceConnectionName' as per parameter setting."
        }

        # Extract project references
        $projectReferences = $serviceConnection.serviceEndpointProjectReferences

        # Validate project references before proceeding
        if (-not $projectReferences -or $projectReferences.Count -eq 0) {
            Write-Warning "Skipping Service Connection '$serviceConnectionName' (missing project reference)."
            $counters.SkippedArmServiceConnections++
            continue
        }

        # Determine whether to revert or convert
        $destinationAuthorizationScheme = switch ($authorizationScheme) {
            "ServicePrincipal"          { "WorkloadIdentityFederation" }
            "WorkloadIdentityFederation" { "ServicePrincipal" }
            default                     { $null }
        }

        if (-not $destinationAuthorizationScheme) {
            Write-Warning "Skipping Service Connection '$serviceConnectionName' (unrecognized authorization scheme)."
            $counters.SkippedArmServiceConnections++
            continue
        }

        # Generate new request body with updated authentication scheme
        $myNewBodyJson = Get-Body -id $endpointId -type $serviceConnection.type `
            -authorizationScheme $destinationAuthorizationScheme `
            -serviceEndpointProjectReferences $projectReferences

        if (-not $myNewBodyJson) {
            Write-Warning "Skipping Service Connection '$serviceConnectionName' (failed body generation)."
            $counters.SkippedArmServiceConnections++
            continue
        }

        # Get Access Token
        $accessToken = Get-AzureAccessToken
        if (-not $accessToken) {
            Write-Error "Failed to retrieve access token. Exiting."
            exit 1
        }

        # Revert to Service Principal (SP)
        if ($revertAll -and $authorizationScheme -eq "WorkloadIdentityFederation" -and $canRevert -and $isProductionRun) {
            Write-Output "Reverting Service Connection '$serviceConnectionName' back to Service Principal..."

            # Call the Restore Function
            $responseJson = Restore-WorkloadIdentityFederation `
                -body $myNewBodyJson `
                -organizationName $organizationName `
                -organizationId $organizationId `
                -endpointId $endpointId `
                -accessToken $accessToken `
                -serviceConnectionName $serviceConnectionName `
                -appObjectId $applicationRegistrationClientId `
                -projectName $projectName

            if ($responseJson) {
                Write-Output "Successfully Reverted Service Connection: $serviceConnectionName"
                $counters.ArmServiceConnectionsReverted++
            } else {
                Write-Warning "Revert failed for Service Connection: $serviceConnectionName"
                $counters.ArmServiceConnectionsNotReverted++
            }
        }

        # Convert to Workload Identity Federation (WIF)
        elseif ($authorizationScheme -eq "ServicePrincipal" -and $isProductionRun) {
            Write-Output "Converting Service Connection '$serviceConnectionName' to Workload Identity Federation..."

            # Call the Convert Function
            $responseJson = ConvertTo-WorkloadIdentityFederation `
                -body $myNewBodyJson `
                -organizationName $organizationName `
                -organizationId $organizationId `
                -endpointId $endpointId `
                -accessToken $accessToken `
                -serviceConnectionName $serviceConnectionName `
                -appObjectId $applicationRegistrationClientId `
                -projectName $projectName

            # Handle Response
            if ($responseJson) {
                Write-Output "Successfully Converted Service Connection: $serviceConnectionName"
                $counters.ArmServiceConnectionsConverted++
            } else {
                Write-Warning "Conversion failed for Service Connection: $serviceConnectionName"
                $counters.ArmServiceConnectionsNotConverted++
            }
        }

        Write-Output "`n-----------------------"
    }

    # Display Summary
    Write-Output "`nSummary of Processed Service Connections:"
    Write-Output "----------------------------------------"
    foreach ($key in $counters.Keys | Sort-Object) {
        Write-Output "$key`: $($counters[$key])"
    }
    Write-Output "----------------------------------------"
}
