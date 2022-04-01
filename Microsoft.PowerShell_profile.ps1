# Make sure we don't conflict with the proper wget command.
Remove-Item Alias:wget

# Handy little alias to use as an alternative to bash's &
Function bg() {
    Start-Process -NoNewWindow @args
}
