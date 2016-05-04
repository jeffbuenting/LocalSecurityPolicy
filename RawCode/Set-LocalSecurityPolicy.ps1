Function Set-LocalSecurityPolicy {

<#
    .Synopsis
        Edits a computers Local Security Policy

    .Description
        Allows Editing of the Local Security Policy on a computer.  

        This came about as setting a services logon account does not give that account the logon as a service right.  As it does via the GUI.

    .Parameter ComputerName
        Will get the policy from this computer.

    .Parameter SecurityPolicy
        This is a text file containing the exported local security policy.  Use Get-LocalSecurityPolicy to retrieve the policy.

    .Parameter LogonAsAService
        User object of the user to grant the logon as a service right.

    .Example
        These three line will get the user object, the local security policy and then sets the logon as a service right.

        $User = Get-ADUser -Filter { Name -eq "Jeff Buenting"} 

        $Pol = Get-LocalSecurityPolicy 

        Set-LocalSecurityPolicy  -SecurityPolicy $Pol -LogonAsAService $user -Verbose

    .Link
        http://stackoverflow.com/questions/23260656/modify-local-security-policy-using-powershell

    .Note
        Author : Jeff Buenting
        Date : 2016 APR 06
#>

    [CmdletBinding()]
    Param (
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter( Mandatory = $True )]
        [String[]]$SecurityPolicy,

        [Microsoft.ActiveDirectory.Management.ADUser]$LogonAsAService
    )

    Process {
        
        Write-Verbose "Set-LocalSecurityPolicy : Setting local security policy for $ComputerName"

        if ( $LogonAsAService ) {
            Write-Verbose "Set-LocalSecurityPolicy : Granting $($LogonAsAService.Name) the Log on as a Service Permission"
            $OldPolicy = $SecurityPolicy | Select-String -Pattern 'SeServiceLogonRight'

            # ----- Check if the user already has the Logon as a service right
            if ( $OldPolicy -notmatch $LogonAsAService.SID ) {
                    Write-Verbose "OldPolicy = $OldPolicy"
                    # ----- Adding a star in front of the SID.  Required in the Security policy but not actually part of the SID.
                    $SecurityPolicy = $SecurityPolicy.Replace( $OldPolicy, "$OldPolicy,*$($LogonAsAService.SID)") 

                    Write-Verbose "NewPolicy = $($SecurityPolicy | Select-String -Pattern 'SeServiceLogonRight')"
                }
                else {
                    Write-Verbose "Set-LocalSecurityPolicy : Account already has the Log on as a Service Right"
            }
        }


        # ----- Save the Setting
        Invoke-Command -ComputerName $ComputerName -ArgumentList (,$SecurityPolicy) -ScriptBlock {
            Param (
                [String[]]$SecurityPolicy
            )


            # ----- Set the remote computers Verbose pref    
            $VerbosePreference=$Using:VerbosePreference

            Write-Verbose "Set-LocalSecurityPolicy : Saving new security policy"
            $SecurityPolicy | out-File  $env:APPDATA\secpol.cfg
                
            Secedit /configure /db C:\windows\security\secedit.sdb /cfg $env:APPDATA\secpol.cfg

            # # ----- Deleting the file to clean up
            Write-Verbose "Set-LocalSecurityPolicy : Clean up tempory file"
            Remove-Item -Path $env:APPDATA\secpol.cfg
        }
    }
}

$User = Get-ADUser -Filter { Name -eq "Jeff Buenting"} 

$Pol = Get-LocalSecurityPolicy 

Set-LocalSecurityPolicy  -SecurityPolicy $Pol -LogonAsAService $user -Verbose