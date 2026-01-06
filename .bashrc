PS1='\w > '

alias vim="nvim"

set -o vi

# Für Insert-Modus
bind -m vi-insert '"\C-l": clear-screen'

# Für Normal-Modus
bind -m vi-command '"\C-l": clear-screen'


export INPUTRC="$HOME/.inputrc"

# ~/.bashrc
export PATH="$HOME/bin:$PATH"

export PATH="$HOME/.local/share/gem/ruby/3.4.0/bin:$PATH"
