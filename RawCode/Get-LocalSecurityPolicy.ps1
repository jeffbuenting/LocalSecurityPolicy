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
        http://stackoverflow.com/questions/23260656/modify-local-security-policy-using-powershell
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String[]]$ComputerName = $env:COMPUTERNAME
    )

    Process {
        Foreach ( $C in $ComputerName ) {
            Write-Verbose "Get-LocalSecurityPolicy : Getting local security policy from $C"

            $SecPOL = Invoke-Command -ComputerName $C -ScriptBlock {
            
                # ----- Set the remote computers Verbose pref    
                $VerbosePreference=$Using:VerbosePreference

                Write-Verbose "Get-LocalSecurityPolicy : Exporting the local security policies"
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

Get-LocalSecurityPolicy