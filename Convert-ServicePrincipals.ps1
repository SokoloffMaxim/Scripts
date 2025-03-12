<#
.SYNOPSIS
    Converts Azure DevOps service connections from Service Principal (SP) to Workload Identity Federation (WIF) or reverts them back to SP.

.DESCRIPTION
    This script automates the conversion of Azure DevOps service connections from Service Principal (SP) authentication to Workload Identity Federation (WIF), a modern, secure, and token-based authentication method. It also supports reverting service connections back to SP if needed. The script is designed to simplify identity management, reduce the risk of credential leakage, and enhance security in Azure DevOps environments.

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
    (Optional) Set to `$true` to perform actual conversions/reversions. Default is `$false`.

.PARAMETER revertAll
    (Optional) Set to `$true` to revert all service connections back to Service Principal (SP). Default is `$false`.

.PARAMETER refreshServiceConnectionsIfTheyExist
    (Optional) Set to `$true` to refresh service connections even if they already exist. Default is `$false`.

.EXAMPLE
    # Convert Service Connections (Interactive Mode)
    .\Convert-ServicePrincipals3.ps1 -isProductionRun $true

.EXAMPLE
    # Convert Service Connections (Specify Project and Organization)
    .\Convert-ServicePrincipals3.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isProductionRun $true

.EXAMPLE
    # Revert Service Connections
    .\Convert-ServicePrincipals3.ps1 -projectName "YourProjectName" -organizationUrl "https://dev.azure.com/YourOrganization" -isproduction $true -revertAll $true -refreshServiceConnectionsIfTheyExist  $true
    Note: Order is important.

.DEPENDENCIES
    - Azure CLI: Ensure the Azure CLI is installed and configured (`az login`).
    - Azure DevOps CLI: Ensure the Azure DevOps CLI extension is installed (`az extension add --name azure-devops`).
    - PowerShell: The script uses standard PowerShell modules and does not require additional installations.

.NOTES
    Original Source: https://github.com/devopsabcs-engineering/azure-devops-workload-identity-federation/blob/main/scripts/Convert-ServicePrincipals.ps1

    Contributions, bug reports, and feedback are welcome! Please open an issue or submit a pull request on the original GitHub repository:
    https://github.com/devopsabcs-engineering/azure-devops-workload-identity-federation

    MODIFICATIONS AND ADDITIONS:
    - Made `-projectName` and `-organizationUrl` optional. If not provided, the script will prompt the user to enter them.
    - Added improved error handling to ensure the user cannot proceed without providing a valid `projectName` or `organizationUrl`.
    - Enhanced user interaction with interactive prompts for missing inputs and clear error messages.
    - Refactored code for better readability and maintainability.
    - Added detailed script documentation, including a synopsis, description, parameters, examples, dependencies, and license information.
    - Documented the necessary Azure DevOps and Azure AD permissions required for execution.

.LICENSE
    This script is provided under the MIT License. Refer to the original repository for more details.
#>

# Define all parameters
param (
    [string] $serviceConnectionJsonPath = "../data/service_connections.json",
    [int]    $jsonDepth = 100,
    [bool]   $isProductionRun = $false,
    [bool]   $refreshServiceConnectionsIfTheyExist = $false,
    [string] $apiVersion = "7.1",
    [bool]   $skipPauseAfterError = $false,
    [bool]   $skipPauseAfterWarning = $false,
    [bool]   $revertAll = $false,
    [string] $projectName = $null,
    [string] $organizationUrl = $null
)

# Initialize counters and other global variables
$counters = @{
    TotalArmServiceConnections                                      = 0
    ArmServiceConnectionsWithWorkloadIdentityFederationAutomatic    = 0
    ArmServiceConnectionsWithWorkloadIdentityFederationManual       = 0
    ArmServiceConnectionsWithServicePrincipalAutomatic              = 0
    ArmServiceConnectionsWithServicePrincipalManual                 = 0
    ArmServiceConnectionsWithManagedIdentity                        = 0
    ArmServiceConnectionsWithPublishProfile                         = 0
    FederatedCredentialsCreatedManually                             = 0
    SharedArmServiceConnections                                     = 0
    ArmServiceConnectionsConverted                                  = 0
    ArmServiceConnectionsNotConverted                               = 0
    ArmServiceConnectionsReverted                                   = 0
    ArmServiceConnectionsNotReverted                                = 0
}

$hashTableAdoResources = @{}

# Define all functions at the top of the script
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

    $outputFile = "organizations_${tenantId}.json"
    Set-Content -Value $responseJson -Path $outputFile
}

function Get-OrganizationId {
    param (
        [string] $organizationName,
        [string] $tenantId
    )
    $outputFile = "organizations_${tenantId}.json"
    $exists = Test-Path -Path $outputFile -PathType Leaf
    if (-not $exists) {
        Write-Output "File $outputFile not found..."
        Get-AzureDevOpsOrganizationOverview -tenantId $tenantId
    }
    $allOrganizationsJson = Get-Content -Path $outputFile 
    $allOrganizations = $allOrganizationsJson | ConvertFrom-Json

    $organizationFound = $allOrganizations | Where-Object { $_."Organization Name" -eq $organizationName }
    
    if ($organizationFound) {
        Write-Output $organizationFound
        $organizationId = $organizationFound[0]."Organization Id"
        Write-Output "Organization $organizationName has id ${organizationId}"
        return $organizationId
    }
    else {
        Write-Warning "did not find org $organizationName in tenant $tenantId"
        return ""
    }
}

function Get-Projects {
    param (
        [string] $organizationUrl
    )
    # Get projects - Implement continuation token
    $token = $null
    $allProjects = @()  

    do {
        if ($null -eq $token) {
            $projectsRawJson = az devops project list --organization $organizationUrl
        }
        else {
            $projectsRawJson = az devops project list --organization $organizationUrl --continuation-token $Token
        }

        $projectsRaw = $projectsRawJson | ConvertFrom-Json -Depth $jsonDepth
        $projects = $projectsRaw.value
        $token = $projectsRaw.ContinuationToken
        
        $allProjects += $projects
    }
    while ($null -ne $token)

    return $projects
}

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

    #$exported = $false
    $organizationsOutputFileExists = Test-Path -Path $organizationsOutputFile -PathType Leaf
    if (-not $organizationsOutputFileExists) {
        Write-Output "File $organizationsOutputFile not found... Fetching organizations."
        Get-AzureDevOpsOrganizationOverview -tenantId $tenantId
    }
    $allOrganizationsJson = Get-Content -Path $organizationsOutputFile 
    $allOrganizations = $allOrganizationsJson | ConvertFrom-Json

    # Skip fetching service connections if the file exists and refresh is disabled
    $serviceConnectionsOutputFileExists = Test-Path -Path $serviceConnectionJsonPath -PathType Leaf
    $skipFetchingServiceConnections = $serviceConnectionsOutputFileExists -and (-not $refreshServiceConnectionsIfTheyExist)

    if ($skipFetchingServiceConnections) {
        Write-Output "File $serviceConnectionJsonPath already exists. Skipping fetch."
        return $true
    }

    $allServiceConnections = @()

    foreach ($organization in $allOrganizations) {
        $organizationName = $organization."Organization Name"
        $organizationId = $organization."Organization Id"
        $organizationUrl = $organization."Url"

        if ($projectName) {
            Write-Output "Fetching service connections for project '$projectName' in organization '$organizationName'..."
            $projects = @(@{ name = $projectName })
        } else {
            Write-Output "Fetching all projects for organization '$organizationName'..."
            $projects = Get-Projects -organizationUrl $organizationUrl
        }

        foreach ($project in $projects) {
            $currentProjectName = $project.name
            Write-Output "Processing Org: ${organizationName}, Proj: ${currentProjectName}"

            # Get service connections for the specific project
            $serviceEndpointsJson = az devops service-endpoint list --organization $organizationUrl --project $currentProjectName
            $serviceEndpoints = $serviceEndpointsJson | ConvertFrom-Json -Depth 100            

            Write-Output "Found $($serviceEndpoints.Length) service endpoints for project $currentProjectName."

            $armServiceEndpoints = $serviceEndpoints | Where-Object { $_.type -eq $filterType }

            # Ensure project name matches service connections
            foreach ($armServiceEndpoint in $armServiceEndpoints) {
                $endpointProjectRefs = $armServiceEndpoint.serviceEndpointProjectReferences
                if ($endpointProjectRefs) {
                    foreach ($ref in $endpointProjectRefs) {
                        $refProjectName = $ref.projectReference.name
                        if ($refProjectName -eq $currentProjectName) {
                            $allServiceConnections += $armServiceEndpoint

                            Write-Output "✅ Matched Service Connection: $($armServiceEndpoint.name) for project '$currentProjectName'"

                            $projSvcEndpoint = @{
                                "organizationName" = $organizationName
                                "organizationId"   = $organizationId
                                "projectName"      = $currentProjectName
                                "serviceEndpoint"  = $armServiceEndpoint
                            }

                            if ($hashTableAdoResources.ContainsKey("$($armServiceEndpoint.id)")) {
                                Write-Warning "Service Connection $($armServiceEndpoint.id) already exists. Checking if it's shared."
                            
                                if (-not $armServiceEndpoint.isShared) {
                                    if (-not $refreshServiceConnectionsIfTheyExist) {
                                        throw "Conflict: endpointId $($armServiceEndpoint.id) exists but is not shared! Use -refreshServiceConnectionsIfTheyExist `$true` to update existing connections."
                                    } else {
                                        Write-Output "⚠️ Service Connection '$($armServiceEndpoint.id)' exists but is not shared. Updating..."
                                        $hashTableAdoResources["$($armServiceEndpoint.id)"] = $projSvcEndpoint  # Update instead of error
                                    }
                                }
                            } else {
                                $hashTableAdoResources.Add("$($armServiceEndpoint.id)", $projSvcEndpoint)
                            }
                        }
                    }
                }
            }
        }
    }

    Write-Output "Saving service connections to $serviceConnectionJsonPath..."
    $allServiceConnectionsJson = $allServiceConnections | ConvertTo-Json -Depth 100
    Set-Content -Value $allServiceConnectionsJson -Path $serviceConnectionJsonPath

    return $true
}

function New-FederatedCredential {
    param (
        [Parameter(mandatory = $true)]
        [string] $organizationName,
        [Parameter(mandatory = $true)]
        [string] $projectName,
        [Parameter(mandatory = $true)]
        [string] $serviceConnectionName,
        [Parameter(mandatory = $true)]
        [string] $appObjectId,
        [Parameter(mandatory = $true)]
        [string] $endpointId,
        [Parameter(mandatory = $true)]
        [string] $organizationId
    )
    $minifiedString = Get-Content .\credential.template.json | Out-String
    $parametersJsonContent = (ConvertFrom-Json $minifiedString) | ConvertTo-Json -Depth 100 -Compress; # For PowerShell 7.3

    #$issuer = "https://vstoken.dev.azure.com/${organizationId}"
    $parametersJsonContent = $parametersJsonContent.Replace("__ENDPOINT_ID__", $endpointId)
    $parametersJsonContent = $parametersJsonContent.Replace("__ORGANIZATION_NAME__", $organizationName)
    $parametersJsonContent = $parametersJsonContent.Replace("__PROJECT_NAME__", $projectName)
    $parametersJsonContent = $parametersJsonContent.Replace("__SERVICE_CONNECTION_NAME__", $serviceConnectionName)
    $parametersJsonContent = $parametersJsonContent.Replace("__ORGANIZATION_ID__", $organizationId)

    Set-Content -Value $parametersJsonContent -Path .\credential.json

    $responseJson = az ad app federated-credential create --id $appObjectId --parameters credential.json

    return $responseJson
}

function PauseOn {
    param (
        [bool] $boolValue
    )
    if ($boolValue) {
        Write-Output 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        Write-Output ""
    }
}

function Get-AzureAccessToken {
    param (
        [string] $resource = "499b84ac-1321-427f-aa17-267ca6975798" # Azure DevOps resource ID
    )
    # Get the access token for Azure DevOps
    $accessToken = az account get-access-token --resource $resource --query accessToken -o tsv
    if (-not $accessToken) {
        Write-Error "Failed to retrieve access token. Ensure you are logged in with 'az login'."
        return $null
    }
    return $accessToken
}

function ConvertTo-OrRevertFromWorkloadIdentityFederation {
    param (
        [string] $body,
        [string] $accessToken,
        [string] $organizationName,
        [string] $endpointId
    )

    # Headers for the REST API request
    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }

    # Construct API URI
    $uri = "https://dev.azure.com/${organizationName}/_apis/serviceendpoint/endpoints/${endpointId}?operation=ConvertAuthenticationScheme&api-version=7.1"

    # Debugging Information
    Write-Output "DEBUG: Calling API at URL: $uri"
    Write-Output "DEBUG: API Request Body: $body"

    Try {
        # Perform API Request
        $response = Invoke-RestMethod -Uri $uri -Method 'PUT' -Headers $headers -Body $body

        # Debugging API Response
        if ($response) {
            Write-Output "✅ API Request Succeeded. Response:"
            Write-Output ($response | ConvertTo-Json -Depth 10)
        } else {
            Write-Warning "⚠️ API Response is empty. Conversion might not have succeeded."
        }

        return $response
    }
    Catch {
        $errorMessage = $_.Exception.Message
        Write-Error "❌ ERROR: API request failed - $errorMessage"

        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $detailedError = $_.ErrorDetails.Message
            Write-Error "💡 Detailed API Error: $detailedError"

            if ($detailedError.Contains("is neither an upgrade or a downgrade and is not supported")) {                
                Write-Warning "⚠️ API Error: Invalid conversion detected."
                return $null
            }
            elseif ($detailedError.Contains("Azure Stack environment")) {
                Write-Warning "⚠️ Azure Stack environment issue detected."
                return $null
            }
        }

        return $null  # Ensure that we return null in case of error
    }
}


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


function Get-AuthenticodeMode {
    param (
        [object] $serviceConnection
    )
    $authorizationScheme = $($serviceConnection.authorization.scheme)
    $creationMode = $($serviceConnection.data.creationMode)

    if ($authorizationScheme -eq "WorkloadIdentityFederation") {
        return "Workload Identity Federation ($creationMode)"
    }
    elseif ($authorizationScheme -eq "ServicePrincipal") {
        return "Service Principal ($creationMode)"
    }
    elseif ($authorizationScheme -eq "ManagedServiceIdentity") {
        return "Managed Identity"
    }
    elseif ($authorizationScheme -eq "PublishProfile") {
        return "Publish Profile"
    }
    else {
        throw "Unexpected authorization scheme $authorizationScheme"
        return $authorizationScheme
    }
}

# Main script logic
try {
    # STEP 1: Login to Azure and Get Service Connections
    Write-Output 'Login to your Azure account using az login (use an account that has access to your Microsoft Entra ID) ...'

    az account clear
    $login = az login --only-show-errors

    if (!$login) {
        Write-Error 'Error logging in and validating your credentials.'
        return;
    }

    $accountJson = az account show
    $account = $accountJson | ConvertFrom-Json
    $currentTenantId = $($account.tenantId)
    Write-Output "Current Tenant ID: $currentTenantId"

    Write-Output "Step 1: Get Service Connections using az devops CLI and export to JSON $serviceConnectionJsonPath ..."

    # If the project name is not provided as an argument, ask the user
    if (-not $projectName) {
        $projectName = Read-Host "Please enter the Azure DevOps project name"
    }

    # Ensure the user does not enter an empty project name
    if (-not $projectName -or $projectName -match "^\s*$") {
        Write-Error "[ERROR] A project name is required. Exiting..."
        exit 1
    }

    Write-Output "Using project name: $projectName"

    # If the organization URL is not provided as an argument, ask the user
    if (-not $organizationUrl) {
        $organizationUrl = Read-Host "Please enter your Azure DevOps organization URL (e.g., https://dev.azure.com/your-organization)"
    }

    # Extract the organization name from the URL
    if ($organizationUrl -match "https://dev\.azure\.com/([^/]+)") {
        $organizationName = $matches[1]  # Extract the organization name from the URL
        Write-Output "Organization name extracted from URL: $organizationName"
    } else {
        Write-Error "Invalid organization URL. Please provide a URL in the format: https://dev.azure.com/your-organization"
        exit 1
    }

    # Use the extracted organization name in the script
    Write-Output "Using organization name: $organizationName"

    $serviceConnectionJsonPath = "../data/service_connections_${currentTenantId}.json"
    
    $exported = Get-ServiceConnections `
        -serviceConnectionJsonPath $serviceConnectionJsonPath `
        -refreshServiceConnectionsIfTheyExist $refreshServiceConnectionsIfTheyExist `
        -tenantId $currentTenantId `
        -projectName $projectName `
        -organizationUrl $organizationUrl

    $hashTableAdoResourcesJson = $hashTableAdoResources | ConvertTo-Json -Depth $jsonDepth
    Set-Content -Value $hashTableAdoResourcesJson -Path "hashTableAdoResources.json"
}
catch {
    Write-Error "An error occurred: $_"
    throw
}

# Ask the user if they want to process shared service connections
$processSharedConnections = Read-Host "Do you want to process shared service connections? (Y/N)"

# Convert the input to uppercase for case-insensitive comparison
$processSharedConnections = $processSharedConnections.ToUpper()

# Validate the user's input
while ($processSharedConnections -notin @("Y", "N")) {
    Write-Output "Invalid input. Please enter 'Y' for Yes or 'N' for No."
    $processSharedConnections = Read-Host "Do you want to process shared service connections? (Y/N)"
    $processSharedConnections = $processSharedConnections.ToUpper()  # Convert to uppercase again
}

# Handle the user's choice
if ($processSharedConnections -eq "N") {
    Write-Output "Skipping shared service connections as per user request."
} else {
    Write-Output "Processing shared service connections."
}

# Call the function with the user-entered project name
$exported = Get-ServiceConnections -serviceConnectionJsonPath $serviceConnectionJsonPath `
    -refreshServiceConnectionsIfTheyExist $refreshServiceConnectionsIfTheyExist `
    -tenantId $currentTenantId `
    -projectName $projectName `
    -organizationUrl $organizationUrl


# Process service connections if they were successfully exported
if ($exported) {
    Write-Output "`nStep 2: Processing Service Connections for Project: '$projectName'..."

    # Filter service connections for the specified project
    $filteredEntries = $hashTableAdoResources.Values | Where-Object { $_.projectName -eq $projectName }

    if ($filteredEntries.Count -eq 0) {
        Write-Output "[INFO] No service connections found for project '$projectName'. Exiting..."
        return
    }

    foreach ($entry in $filteredEntries) {
        $serviceConnection = $entry.serviceEndpoint
        $organizationName = $entry.organizationName
        $organizationId = $entry.organizationId

        # **Skip Service Connections Immediately if not using -revertAll $true and if authorization scheme already WorkloadIdentity Federation**
        if (-not $revertAll -and $serviceConnection.authorization.scheme -eq "WorkloadIdentityFederation") {
            Write-Output "⚠️ Skipping Service Connection '$($serviceConnection.name)' due to due to service connection using Workload Identity Federation authorization scheme."
            continue
        }

        # **Skip Service Connections if not using -revertAll $true and the authorization scheme is already Service Principal**
        if ($revertAll -and $serviceConnection.authorization.scheme -eq "ServicePrincipal") {
            Write-Output "⚠️ Skipping Service Connection '$($serviceConnection.name)' because it is already using Service Principal"
            continue
        }

        # **Skip Shared Service Connections Immediately if User Chose "N"**
        if ($serviceConnection.isShared -and $processSharedConnections -eq "N") {
            Write-Output "⚠️  Skipping shared service connection: $($serviceConnection.name) (User chose not to process shared connections)"
            continue  # Skip the rest of the loop iteration
        }

        $counters.TotalArmServiceConnections++

        # Determine Shared Status Icon (✅ for No, ⚠️ for Yes)
        $isSharedIcon = if ($serviceConnection.isShared) { "⚠️  Yes" } else { "✅ No" }

        Write-Output "`n-----------------------"
        Write-Output "Processing Service Connection: $($serviceConnection.name)"

        # Extract details
        $applicationRegistrationClientId = $serviceConnection.authorization.parameters.serviceprincipalid
        $tenantId = $serviceConnection.authorization.parameters.tenantid
        $authorizationScheme = $serviceConnection.authorization.scheme
        $endpointId = $serviceConnection.id
        $revertSchemeDeadline = $serviceConnection.data.revertSchemeDeadline
        $creationMode = $serviceConnection.data.creationMode

        # Time Calculation for Reverting
        $TimeSpan = if ($revertSchemeDeadline) { $revertSchemeDeadline - (Get-Date -AsUTC) } else { [timespan]::Zero }
        $totalDays = [math]::Round($TimeSpan.TotalDays, 2)
        $canRevert = $totalDays -gt 0

        # Print service connection details with shared status
        Write-Output "App Registration Client Id   : $applicationRegistrationClientId"
        Write-Output "Tenant ID                    : $tenantId"
        Write-Output "Authorization Scheme         : $authorizationScheme"
        Write-Output "Service Connection Name      : $serviceConnection.name"
        Write-Output "Endpoint ID                  : $endpointId"
        Write-Output "Revert Scheme Deadline       : $revertSchemeDeadline"
        Write-Output "Can Revert or Convert        : $canRevert"
        Write-Output "Total Days left to Revert    : $totalDays"
        Write-Output "Shared Service Connection    : $isSharedIcon"

        # Count Shared Service Connections (Only if User Allowed Processing)
        if ($serviceConnection.isShared) {
            Write-Warning "Shared Service Connection detected!"
            $counters.SharedArmServiceConnections++
        }

        # Extract the project references from the service connection
        $projectReferences = $serviceConnection.serviceEndpointProjectReferences

        # Validate project references before proceeding
        if (-not $projectReferences -or $projectReferences.Count -eq 0) {
            Write-Warning "⚠️ Skipping Service Connection '$($serviceConnection.name)' due to missing project reference."
            $counters.ArmServiceConnectionsNotConverted++
            continue
        }

        # Determine if we need to revert or convert the service connection
        $destinationAuthorizationScheme = switch ($authorizationScheme) {
            "ServicePrincipal"          { "WorkloadIdentityFederation" }
            "WorkloadIdentityFederation" { "ServicePrincipal" }
            default                     { $null }
        }

        if (-not $destinationAuthorizationScheme) {
            Write-Warning "⚠️ Skipping Service Connection '$($serviceConnection.name)' due to unrecognized authorization scheme."
            continue
        }

        # Generate the new body with updated authorization scheme
        $myNewBodyJson = Get-Body -id $endpointId -type $serviceConnection.type `
            -authorizationScheme $destinationAuthorizationScheme `
            -serviceEndpointProjectReferences $projectReferences

        if (-not $myNewBodyJson) {
            Write-Warning "⚠️ Skipping Service Connection '$($serviceConnection.name)' due to failed body generation."
            continue
        }

        # Get Access Token
        $accessToken = Get-AzureAccessToken
        if (-not $accessToken) {
            Write-Error "Failed to retrieve access token. Exiting."
            exit 1
        }

        # Determine whether to revert or convert
        if ($revertAll -and $authorizationScheme -eq "WorkloadIdentityFederation" -and $canRevert -and $isProductionRun) {

            Write-Output "🔄 Reverting Service Connection '$($serviceConnection.name)' back to Service Principal..."
            
            # API Call to revert
            $responseJson = ConvertTo-OrRevertFromWorkloadIdentityFederation `
                -body $myNewBodyJson `
                -organizationName $organizationName `
                -endpointId $endpointId `
                -accessToken $accessToken

            if ($responseJson) {
                Write-Output "✅ Successfully Reverted Service Connection: $($serviceConnection.name)"
                $counters.ArmServiceConnectionsReverted++
            } else {
                Write-Warning "⚠️ Revert failed for Service Connection: $($serviceConnection.name)"
                $counters.ArmServiceConnectionsNotReverted++
            }
        } elseif ($authorizationScheme -eq "ServicePrincipal" -and $isProductionRun) {
            Write-Output "🔄 Converting Service Connection '$($serviceConnection.name)' to Workload Identity Federation..."
            
            # API Call to convert
            $responseJson = ConvertTo-OrRevertFromWorkloadIdentityFederation `
                -body $myNewBodyJson `
                -organizationName $organizationName `
                -endpointId $endpointId `
                -accessToken $accessToken

            if ($responseJson) {
                Write-Output "✅ Successfully Converted Service Connection: $($serviceConnection.name)"
                $counters.ArmServiceConnectionsConverted++
            } else {
                Write-Warning "⚠️ Conversion failed for Service Connection: $($serviceConnection.name)"
                $counters.ArmServiceConnectionsNotConverted++
            }
        }

        Write-Output "`n-----------------------"
    }

    # Display Summary **(Moved Outside the Loop to Avoid Duplicates)**
    Write-Output "`nSummary of Processed Service Connections:"
    Write-Output "----------------------------------------"
    foreach ($key in $counters.Keys | Sort-Object) {
        Write-Output "$key`: $($counters[$key])"
    }
    Write-Output "----------------------------------------"
}
