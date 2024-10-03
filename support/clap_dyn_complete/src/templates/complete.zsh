#compdef __COMMAND_NAME__

___COMMAND_NAME__() {
    toks=("${(z)LBUFFER}")

    while IFS= read -r line; do
        # don't compadd empty lines
        if [[ $line = *[!\ ]* ]]; then
            cmd=("$line")
            _describe 'command' cmd -o nosort
        else
            # fallback to default completion there were no completions
            _default
        fi
    done <<< "$(
        "${toks[1]}" __COMPLETION_SUBCOMMAND__ \
            --position $CURSOR \
            --raw "$LBUFFER$RBUFFER" \
            "${(z)LBUFFER}" \
            2>/dev/null
    )"
}

___COMMAND_NAME__

# ZSH completions are commonly stored in any directory listed in your `$fpath`
# variable. To use these completions, you must either add the generated script
# to one of those directories, or add your own to this list.
#
# Adding a custom directory is often the safest bet if you are unsure of which
# directory to use. First create the directory; for this example we'll create a
# hidden directory inside our `$HOME` directory:
#
#     mkdir ~/.zfunc
#
# Then add the following lines to your `.zshrc` just before `compinit`:
#
#     fpath+=~/.zfunc
#
# Now you can install the completions script using the following command:
#
#     __COMMAND_NAME__ completions zsh > ~/.zfunc/_ohcldiag-dev
