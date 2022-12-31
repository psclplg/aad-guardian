<#
.SYNOPSIS
    AAD-Guardian is here to deliver basic protection for your Azure AD tenant.
.DESCRIPTION
    This is the main AAD-Guradian script file.
    The script spans across multiple Azure AD topics and provides best practice approaches to deliver secure configurations.
    Thanks to Break Glass accounts and their linked security group you can avoid loss of access to your tenant.
    With the basic Conditional Access policies you can protect your identities and access to your data by following a zero trust approach. 
.COMPONENT
    The following Azure AD and Azure services will be used to reach the targeted state:
    - Azure AD Users
    - Azure AD Groups
    - Azure AD Conditional Access
.NOTES
    Author...............: Pascal Plaga
        Github...........: https://github.com/psclplg 
        LinkedIn.........: https://www.linkedin.com/in/pascalplaga
    Version..............: 0.1
    TBD..................: - Monitoring for Sign-Ins of Break Glass Accounts and w/o CA policy applied. 
                           - Define scopes for least privileges for MS Graph authentication
#>

# function loginGraph {
#     param (
#         [String]$scopes = ""
#     )
#     Connect-MgGraph -Scopes $scopes
# }

function breakGlassAccounts {
    param (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$userName,
        [String]$displayName,
        [String]$givenName,
        [String]$surname,
        [SecureString]$password
    )
    $script:cloudDomain = Get-MgDomain | Where-Object {$_.Id -like "*.onmicrosoft.com"} | Select-Object -ExpandProperty Id
    $roleId = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq 'Global Administrator'" | Select-Object -ExpandProperty Id 
    $userPrincipalName = "$($userName)@$($cloudDomain)"
    $passwordProfile = @{}
    $passwordProfile["Password"] = ConvertFrom-SecureString $password -AsPlainText
    $passwordProfile["ForceChangePasswordNextSignIn"] = $false
    try {
        New-MgUser -UserPrincipalName $userPrincipalName -DisplayName $displayName -GivenName $givenName -Surname $surname -MailNickName $userName -PasswordProfile $passwordProfile -PasswordPolicies "DisablePasswordExpiration" -AccountEnabled -ShowInAddressList:$false -UsageLocation "DE" -ErrorAction Stop | Out-Null
        $breakGlassUser = Get-MgUser -Filter "UserPrincipalName eq '$($userPrincipalName)'"
    }
    catch {
        Write-Host ""
        Write-Host "There was a problem creating the user $($userPrincipalName)" -ForegroundColor Yellow
        Write-Host "See error message for details:" -ForegroundColor Yellow
        Write-Host "$($Error[0])" -ForegroundColor Red
    }
    if ($null -ne $breakGlassUser -and $null -ne $roleId) {
        try {
            New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $breakGlassUser.Id -RoleDefinitionId $roleId -DirectoryScopeId "/" -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host ""
            Write-Host "There was a problem with the role assignment for the user $($breakGlassUser.UserPrincipalName)" -ForegroundColor Yellow
            Write-Host "See error message for details:" -ForegroundColor Yellow
            Write-Host "$($Error[0])" -ForegroundColor Red
        }
    }
    $script:breakGlassUsers += $breakGlassUser.Id
    $roleAssignment = Get-MgRoleManagementDirectoryRoleAssignment -Filter "RoleDefinitionId eq '$($roleId)' and PrincipalId eq '$($breakGlassUser.Id)'" -ErrorAction SilentlyContinue
    if ($null -ne $roleAssignment) {
        Write-Host ""
        Write-Host "[*] User $($breakGlassUser.UserPrincipalName) exists and is assigned the 'Global Administrator' role." -ForegroundColor Green
        Write-Host "    Please make sure to try out the user account, store the credentials in a safe place and rotate the password from time to time." -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host ""
        Write-Host "[!] There was a problem executing this part of the script." -ForegroundColor Yellow
        Write-Host "    See error messages above for details." -ForegroundColor Yellow
    }
}

function breakGlassGroup {
    param (
        [String]$groupName
    )
    try {
        New-MgGroup -DisplayName $groupName -MailEnabled:$false  -MailNickName $groupName -SecurityEnabled | Out-Null
        $group = Get-MgGroup -Filter "DisplayName eq '$($groupName)'"
        Write-Host "[*] Group $($groupName) was successfully created." -ForegroundColor Green
        $script:breakGlassGroup = $group
    }
    catch {
        Write-Host ""
        Write-Host "There was a problem creating the group $($groupName)" -ForegroundColor Yellow
        Write-Host "See error message for details:" -ForegroundColor Yellow
        Write-Host "$($Error[0])" -ForegroundColor Red
    }
    if ($null -ne $group) {
        foreach ($user in $breakGlassUsers) {
            try {
                $user = Get-MgUser -Filter "Id eq '$($user)'"
                New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id | Out-Null
                Write-Host "[*] User $($user.UserPrincipalName) was successfully added as member of group $($groupName)." -ForegroundColor Green
            }
            catch {
                Write-Host ""
                Write-Host "[!] There was a problem executing this part of the script." -ForegroundColor Yellow
                Write-Host "    User with Id $($user) was NOT added as member of group $($groupName)." -ForegroundColor Yellow
            }
        }
    }
}

function conditionalAccess {
    param (
        $breakGlassGroup = $breakGlassGroup,
        [String]$mfaGroupName = "SEC_CA_MFA_All_Users"
    )
    Write-Host "Do you want to use an existing security group for MFA for all users or create a new one?"
    Write-Host "Provide the name of the existing group or type 'new'."
    $mfaGroupInput = Read-Host "Your input"
    if ($mfaGroupInput -eq "new") {
        New-MgGroup -DisplayName $mfaGroupName -MailEnabled:$false  -MailNickName $mfaGroupName -SecurityEnabled | Out-Null
        $mfaGroup = Get-MgGroup -Filter "DisplayName eq '$($mfaGroupName)'" 
        Write-Host ""
        Write-Host "The security group $($mfaGroup.DisplayName) was successfully created."
        Write-Host "Please add all users required to use MFA to the new group."
        Write-Host ""
    }
    else {
        $mfaGroup = Get-MgGroup -Filter "DisplayName eq '$($mfaGroupInput)'" 
        Write-Host ""
        Write-Host "Found security group $($mfaGroup.DisplayName) with Id $($mfaGroup.Id)"
        Write-Host
    }
    $conditionalAccessPolicyTemplates = Get-ChildItem -Path ./ca-policies/*.json
    foreach ($conditionalAccessPolicyTemplate in $conditionalAccessPolicyTemplates) {
        try {
            (Get-Content $conditionalAccessPolicyTemplate) -replace "<<breakGlass_Group>>",$breakGlassGroup.Id | Set-Content $conditionalAccessPolicyTemplate
            (Get-Content $conditionalAccessPolicyTemplate) -replace "<<mfaAllUsers_Group>>",$mfaGroup.Id | Set-Content $conditionalAccessPolicyTemplate
            $conditionalAccessPolicy = Get-Content $conditionalAccessPolicyTemplate | ConvertFrom-Json -AsHashtable
            New-MgIdentityConditionalAccessPolicy -BodyParameter $conditionalAccessPolicy | Out-Null
            Write-Host "[*] Conditional Access policy '$($conditionalAccessPolicy.DisplayName)' was successfully created and is enabled in reporting mode." -ForegroundColor Green
        }
        catch {
            Write-Host ""
            Write-Host "There was a problem creating the policy $($conditionalAccessPolicyTemplate)" -ForegroundColor Yellow
            Write-Host "See error message for details:" -ForegroundColor Yellow
            Write-Host "$($Error[0])" -ForegroundColor Red
        }
    }
}

Clear-Host
Write-Host "`n--------------- WELCOME TO AAD-GURADIAN ---------------`n" -ForegroundColor Magenta
Write-Host "This script walks you through some of the basic Azure AD protection settings, tools and configurations."
Write-Host "Best part is that it even provides these basic security functionalities if you want it to."
Write-Host "Make sure you have sufficient privileges within Azure AD and Azure to execute the following tasks.`n" -ForegroundColor Yellow
Write-Host "[ ] Create AAD Break Glass account(s)"
Write-Host "[ ] Create security group for the AAD Break Glass account(s)"
Write-Host "[ ] Set up monitoring of AAD Break Glass account(s) and group membership with Azure Monitor"
Write-Host "[ ] Create basic Conditional Access policies for MFA and to block legacy authentication"
Write-Host "[ ] Set up monitorung of logins w/o Conditional Access policies"
Write-Host ""
Write-Host "Let's get started!!!" -ForegroundColor Cyan
Write-Host ""

#loginGraph

Write-Host ""
Write-Host "--------------- BREAK GLASS ACCOUNTS ---------------" -ForegroundColor Magenta
$varBreakGlassAccounts = Read-Host "Do you want to create Break Glass accounts? (y/n)"
if ($varBreakGlassAccounts -eq "y") {
    $varNumberBreakGlassAccounts = Read-Host "Would you like to create one or two Break Glass accounts? (1/2)"
    $breakGlassUsers = @()
    $i = 1
    while ($i -le $varNumberBreakGlassAccounts) {
        Write-Host ""
        Write-Host "Please enter infos for Break Glass account #$($i)" -ForegroundColor Cyan
        $userName = Read-Host "userName"
        $displayName = Read-Host "displayName"
        $givenName = Read-Host "givenName"
        $surname = Read-Host "surname"
        $password = Read-Host "password" -AsSecureString
        try {
            breakGlassAccounts -userName $userName -displayName $displayName -givenName $givenName -surname $surname -password $password
            $i++
        }
        catch {
            Write-Host ""
            Write-Host "$($Error[0])" -ForegroundColor Red
            Write-Host ""
            $skip = Read-Host "[S]kip this step or [r]etry?"
            if ($skip -eq "s") {
                break
            }
        }
    }
}

Write-Host ""
Write-Host "--------------- BREAK GLASS SECURITY GROUP ---------------" -ForegroundColor Magenta
$varBreakGlassGroup = Read-Host "Do you want to create a security group for the Break Glass accounts and add them as members? (y/n)"
if ($varBreakGlassGroup -eq "y") {
    Write-Host ""
    Write-Host "Please enter infos for Break Glass group" -ForegroundColor Cyan
    Write-Host "To choose the default name 'SEC_BreakGlass_Accounts', leave blank and hit ENTER." 
    $groupName = Read-Host "groupName"
    if ($groupName -eq "") {
        $groupName = "SEC_BreakGlass_Accounts"
    }
    breakGlassGroup -groupName $groupName
}

Write-Host ""
Write-Host "--------------- CONDITIONAL ACCESS POLICIES ---------------" -ForegroundColor Magenta
$varConditionalAccess = Read-Host "Do you want to create basic Conditional Access policies? (y/n)"
if ($varConditionalAccess -eq "y") {
    Write-Host ""
    conditionalAccess
    Write-Host ""
}

Write-Host ""
Write-Host "--------------- THANKS for using AAD-Guardian ---------------" -ForegroundColor Magenta
Write-Host "Your feedback is appreaciated and feel free to make suggestions on how to further improve the script."