# ~/.bash_profile

# autostart sway
if [ -z "$WAYLAND_DISPLAY" ] && [ -n "XDG_VTNR" ] && [ "$XDG_VTNR" -eq 1 ] ; then
    exec sway
fi


# ~/.bash_profile
[[ -f ~/.bashrc ]] && source ~/.bashrc



# system settings
export BROWSER=firefox
export EDITOR=nvim
export PAGER=less

