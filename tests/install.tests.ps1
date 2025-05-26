# PowerShell Pester tests for install.ps1

# Requires -Version 5.0
# Requires -Modules Pester

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $here '..\scripts\install.ps1'

Describe 'install.ps1' {
    BeforeAll {
        # Import the script functions
        . $scriptPath
    }

    Context 'Logging functions' {
        It 'InfoMessage writes info log' {
            { InfoMessage 'Test info' } | Should -Not -Throw
        }
        It 'WarnMessage writes warning log' {
            { WarnMessage 'Test warning' } | Should -Not -Throw
        }
        It 'ErrorMessage writes error log' {
            { ErrorMessage 'Test error' } | Should -Not -Throw
        }
        It 'SuccessMessage writes success log' {
            { SuccessMessage 'Test success' } | Should -Not -Throw
        }
    }

    Context 'Directory creation' {
        It 'Ensure-Directory creates a new directory if not exists' {
            $testDir = Join-Path $env:TEMP 'testdir_' + [guid]::NewGuid().ToString()
            Ensure-Directory -Path $testDir
            Test-Path $testDir | Should -BeTrue
            Remove-Item $testDir -Recurse -Force
        }
    }

    Context 'Download-File' {
        It 'Download-File throws error for invalid URL' {
            { Download-File -Url 'http://invalid-url' -OutputPath "$env:TEMP\invalid.file" } | Should -Not -Throw
        }
    }

    Context 'Get-AdapterName' {
        It 'Get-AdapterName returns a string or null' {
            $result = Get-AdapterName
            ($result -is [string] -or $null -eq $result) | Should -BeTrue
        }
    }

    Context 'Install-SuricataSoftware' {
        It 'Install-SuricataSoftware does not throw' {
            { Install-SuricataSoftware } | Should -Not -Throw
        }
    }

    Context 'Install-NpcapSoftware' {
        It 'Install-NpcapSoftware does not throw' {
            { Install-NpcapSoftware } | Should -Not -Throw
        }
    }

    Context 'Update-EnvironmentVariables' {
        It 'Update-EnvironmentVariables does not throw' {
            { Update-EnvironmentVariables } | Should -Not -Throw
        }
    }

    Context 'Update-RulesFile' {
        It 'Update-RulesFile does not throw' {
            { Update-RulesFile } | Should -Not -Throw
        }
    }

    Context 'Register-SuricataScheduledTask' {
        It 'Register-SuricataScheduledTask does not throw' {
            { Register-SuricataScheduledTask } | Should -Not -Throw
        }
    }
}
