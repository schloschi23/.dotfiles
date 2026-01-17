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



# --- Pavlov Punish
pavlov_punish() {
    local exit_code=$?

    if [[ $PAVLOV_ENABLED -eq 1 && $exit_code -ne 0 && $exit_code -ne 130 ]]; then
        echo
        echo "❌ Fehler. Denkpause."

        # Terminal in Rohmodus (keine Eingaben)
        stty -icanon -echo

        for ((i=PAVLOV_LOCK_TIME; i>0; i--)); do
            printf "\r⏳ %2d Sekunden verbleiben..." "$i"
            sleep 1
        done

        printf "\r✅ slow is smooth. smooth is fast. Weiter geht's.                    \n"

        # Terminal zurücksetzen
        stty sane
    fi
}
