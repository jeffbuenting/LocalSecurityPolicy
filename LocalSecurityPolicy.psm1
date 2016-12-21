#---------------------------------------------------------------------------------
# Module: LocalSecurityPolicy.psm1
#
# Cmdlets to facilitate Local Security Policy Settings
#
# Author : Jeff Buenting
#---------------------------------------------------------------------------------

Function Get-LocalSecurityPolicy {

<#
    .Synopsis
        Exports the Local Security Policy from a computer

    .Description
        Exports the Local Security Policy from a computer

    .Parameter ComputerName
        Will get the policy from this computer.

    .Example
        Retrieve the Local Security Policy from the local Computer

        Get-LocalSecurityPolicy

    .Link
        https://technet.microsoft.com/en-us/library/hh875548.aspx

    .Link
        http://stackoverflow.com/questions/23260656/modify-local-security-policy-using-powershell

    .Note
        Author : Jeff Buenting
        Date : 2016 Apr 06
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String[]]$ComputerName = $env:COMPUTERNAME

        #[PSCredential]$Credential,

        #[String]$Path = "$env:APPDATA"
    )

    Process {
        # ---- Had to add this check to prevent the double hop issue.
        if ( $ComputerName -eq $env:COMPUTERNAME ) {
                Write-Verbose "Running on Local host"

                Write-Verbose "Get-LocalSecurityPolicy : Exporting the local security policies to : $env:APPDATA"
                Secedit /export /cfg $env:APPDATA\secpol.cfg | out-null
                $SecPOL = Get-Content -Path $env:APPDATA\secpol.cfg

                # ----- Deleting the file to clean up
                Write-Verbose "Get-LocalSecurityPolicy : Clean up tempory file"
         #       Remove-Item -Path $env:APPDATA\secpol.cfg
                
                Write-Output $SECPol
            }
            else {
                Write-Verbose "Running on on Remote Computers"
                Foreach ( $C in $ComputerName ) {
                    Write-Verbose "Get-LocalSecurityPolicy : Getting local security policy from $C"

                    $SecPOL = Invoke-Command -ComputerName $C -ScriptBlock {
               
                        # ----- Set the remote computers Verbose pref    
                        $VerbosePreference=$Using:VerbosePreference

                        Write-Verbose "Get-LocalSecurityPolicy : Exporting the local security policies to : $env:APPDATA"
                        Secedit /export /cfg $env:APPDATA\secpol.cfg | out-null
                        $Policy = Get-Content -Path $env:APPDATA\secpol.cfg
                       
                        # ----- Deleting the file to clean up
                        Write-Verbose "Get-LocalSecurityPolicy : Clean up tempory file"
                        Remove-Item -Path $env:APPDATA\secpol.cfg
                  
                        write-output $Policy
                    }

                    Write-Output $SecPOL
                }
        }
    }
}

#---------------------------------------------------------------------------------

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
        Account Name of the user to grant the logon as a service right.

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

        [String]$LogonAsAService
    )

    Process {
        
        Write-Verbose "Set-LocalSecurityPolicy : Setting local security policy for $ComputerName"

        if ( $LogonAsAService ) {
            Write-Verbose "Set-LocalSecurityPolicy : Granting $($LogonAsAService) the Log on as a Service Permission"
            $OldPolicy = $SecurityPolicy | Select-String -Pattern 'SeServiceLogonRight'

            # ----- Get user's SID.  NOTE : Can't use AD Object here because we might not have AD module installed on system.
            $sid = $Null
            try {
	                $ntprincipal = new-object System.Security.Principal.NTAccount "$LogonAsAService"
	                $sid = ($ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])).Value.ToString()
	                
                } catch {
	                Throw "Set-LocalSecurityPolicy : Log on as a Service : $LogonAsAService account does not exist.`n$($_.Exception.Gettype().FullName)"
            }

            # ----- Check if the user already has the Logon as a service right
            if ( $OldPolicy -notmatch $SID ) {
                    Write-Verbose "Set-LocalSecurityPolicy : OldPolicy = $OldPolicy"
                    # ----- Adding a star in front of the SID.  Required in the Security policy but not actually part of the SID.
                    $SecurityPolicy = $SecurityPolicy.Replace( $OldPolicy, "$OldPolicy,*$SID") 

                    Write-Verbose "Set-LocalSecurityPolicy : NewPolicy = $($SecurityPolicy | Select-String -Pattern 'SeServiceLogonRight')"
                }
                else {
                    Write-Verbose "Set-LocalSecurityPolicy : Account already has the Log on as a Service Right"
            }
        }
        
        # ---- Had to add this check to prevent the double hop issue.
        # ----- Save the Setting
        Write-Verbose "Set-LocalSecurityPolicy : Saving Security Policy"
        if ( $ComputerName -eq $env:COMPUTERNAME ) {
                Write-Verbose "Set-LocalSecurityPolicy : on local computer"

                Write-Verbose "Set-LocalSecurityPolicy : Saving new security policy"
                $SecurityPolicy | out-File  $env:APPDATA\secpol.cfg
                
                Secedit /configure /db C:\windows\security\secedit.sdb /cfg $env:APPDATA\secpol.cfg | Write-verbose

                # # ----- Deleting the file to clean up
                Write-Verbose "Set-LocalSecurityPolicy : Clean up tempory file"
                Remove-Item -Path $env:APPDATA\secpol.cfg
            }
            Else {
                Write-Verbose "Set-LocalSecurityPolicy : on remote computer $ComputerName"
                Invoke-Command -ComputerName $ComputerName -ArgumentList (,$SecurityPolicy) -ScriptBlock {
                    Param (
                        [String[]]$SecurityPolicy
                    )


                    # ----- Set the remote computers Verbose pref    
                    $VerbosePreference=$Using:VerbosePreference

                    Write-Verbose "Set-LocalSecurityPolicy : Saving new security policy"
                    $SecurityPolicy | out-File  $env:APPDATA\secpol.cfg
                
                    Secedit /configure /db C:\windows\security\secedit.sdb /cfg $env:APPDATA\secpol.cfg | Write-Verbose

                    # # ----- Deleting the file to clean up
                    Write-Verbose "Set-LocalSecurityPolicy : Clean up tempory file"
                    Remove-Item -Path $env:APPDATA\secpol.cfg
                }
        }
    }
}

#---------------------------------------------------------------------------------

