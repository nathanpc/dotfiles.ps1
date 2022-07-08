# Make sure we don't conflict with the proper wget command.
If (Test-Path Alias:wget) {
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
