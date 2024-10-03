function ___COMMAND_NAME_NODASH___complete
    set -l buffer (commandline)
    set -l cursor_pos (commandline -C)

    # Parse the command line using the fish tokenizer
    set -l tokens (fish -c "string split ' ' \"$buffer\"")

    # TODO: doesn't properly handle completing commandlines that include
    # subcommands. e.g: `$ foo build (echo $bar)` will not actually resolve
    # `(echo $bar)` before handing things off to the binary...

    # Check if the last element is an empty string
    set last_element $tokens[-1]
    if test -z "$last_element"
        set -e tokens[-1]
    end

    # set -g -x RUST_LOG debug # uncomment to debug
    $tokens[1] __COMPLETION_SUBCOMMAND__ --raw "$buffer" --position "$cursor_pos" $tokens
end

complete -c __COMMAND_NAME__ -f -a "(___COMMAND_NAME_NODASH___complete)"
