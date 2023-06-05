# Microsoft.PowerShell_profile.ps1
# Our PowerShell profile. Microsoft's equivalent to .bash_profile.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Go into our profile directory.
Push-Location (Split-Path -Parent $PROFILE)

# Source all of our snippets in the right order.
. .\exports.ps1
. .\aliases.ps1



# Import the Git integration module.
Import-Module posh-git

# Setup our prompt.
. .\prompt.ps1

# Go back to the current directory.
Pop-Location
