_cargo-xtask() {
    # By default, use the "slow path" of invoking xtask via `cargo xtask`
    XTASK=("cargo" "xtask")

    # ...but if the xtask has already been run once, it's faster to use `cargo
    # locate-project` in conjunction with the `xtask-path` file in order to
    # invoke the xtask binary directly
    root_dir=${${$(cargo locate-project)#"{\"root\":\""}%"\"}"}
    xtask_path="$(dirname "$root_dir")/target/xtask-path"
    if [ -f "$xtask_path" ]; then
        XTASK=("$(cat "$xtask_path")")
    fi

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
        "${XTASK[@]}" complete \
            --position "$CURSOR" \
            --raw "$BUFFER" \
            "${(z)LBUFFER}" \
            2>/dev/null # uncomment to debug
    )"
}
