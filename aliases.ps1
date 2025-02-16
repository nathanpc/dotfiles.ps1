﻿# aliases.ps1
# Our PowerShell aliases to make us type less.
#
# Author: Nathan Campos <nathan@innoveworkshop.com>

# Make sure we don't conflict with the proper wget command.
If (Get-Command wget.exe -ErrorAction SilentlyContinue | Test-Path) {
	Remove-Item Alias:wget
}

# Handy little alias to use as an alternative to bash's &
Function bg() {
    Start-Process -NoNewWindow @args
}

# Since we always want to start Emacs in the background...
Function emacs() {
	bg emacs @args
}

# We sure love our symbolic links from Unixland...
Function ln() {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Target,
        [Parameter(Mandatory = $true)]
        [String]$Path
    )

    New-Item -ItemType SymbolicLink -Path $Path -Target $Target
}

# The feature Windows should've gotten by default.
Function sudo() {
    If ($args.Length -eq 1) {
        Start-Process $args[0] -Verb "runAs"
    }

    If ($args.Length -gt 1) {
        Start-Process $args[0] -ArgumentList $args[1..$args.Length] -verb "runAs"
    }
}

# Prevent Git alias conflicts with built-in aliases.
Remove-Alias gc -Force -ErrorAction SilentlyContinue
Remove-Alias gps -Force -ErrorAction SilentlyContinue
Remove-Alias gcm -Force -ErrorAction SilentlyContinue
Remove-Alias gl -Force -ErrorAction SilentlyContinue

# Git aliases.
Function gs {
	git status $args
}
Function gl {
	git log $args
}
Function glt {
	git log --pretty=oneline --abbrev-commit --decorate --graph --format=format:'%C(bold blue)%h%C(reset) - %C(bold green)(%ar)%C(reset) %C(white)%s%C(reset) %C(dim white)- %an%C(reset)%C(auto)%d%C(reset)' --all $args
}
Function ga {
	git add $args
}
Function gc {
	git commit $args
}
Function gca {
	git commit --amend $args
}
Function gcm {
	git commit -m $args
}
Function gdf {
	git diff $args
}
Function gps {
	git push $args
}
Function gpl {
	git pull $args
}
