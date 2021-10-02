#!/usr/bin/env bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:${PATH}"
export PATH="${HOME}/.local/bin:/snap/bin:${PATH}"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

[[ -f "${DIR}/.env" ]] && source "${DIR}/.env"
[[ -f "${PWD}/.env" ]] && source "${PWD}/.env"

: ${PY_EXE="python2.7"}
: ${ABE_PORT="8545"}
: ${HEALTH_URL="http://127.0.0.1"}
: ${CONFIG_FILE="${DIR}/abe.conf"}
: ${ABESTART_LINE=""}
: ${DEBUG=0}

dbg() {
    (( DEBUG )) && >&2 echo -e " [DEBUG]" "$@" || true
}

#ABESTART=()

export CONFIG_FILE ABE_PORT PY_EXE
gen-abestart() {
    (( $# > 0 )) && CONFIG_FILE="$1"
    (( $# > 1 )) && PY_EXE="$2"
    ABXT="${PY_EXE} -m Abe.abe --config ${CONFIG_FILE}"
    export ABXT
    dbg "Generated ABESTART line. Line is: $ABXT"
    echo "$ABXT"
}

dump-config() {
    debug "Reading config file: $CONFIG_FILE"
    cat "$CONFIG_FILE"
}

dump-env() {
    debug "Reading example ENV file at ${DIR}/dkr/example.env"
    cat "${DIR}/dkr/example.env"
}

abe-loader() {
    dbg "ABESTART at start of abe-loader / before appending abe-loader args:" "${ABESTART[@]}"
    if (( $# > 0 )); then
        ABESTART+=("$@")
        dbg "ABESTART after appending abe-loader args:" "${ABESTART[@]}"
    fi
    >&2 echo -e "\n >>> Starting ABE block indexer. Command: ${ABESTART[*]} --no-serve \n\n"
    "${ABESTART[@]}" --no-serve "$@"
}

print-help() {
    echo -e " Abe Block Explorer - CLI Wrapper Tool"
    echo -e " Official Repo: https://github.com/bitcoin-abe/bitcoin-abe \n"

    echo -e " This CLI Abe wrapper tool was originally written by Someguy123 @ Privex Inc. - https://www.privex.io/"
    echo -e " Consider hosting your Abe instance at Privex - privacy friendly server hosting starting from \$0.99/mo"
    echo -e " And YES, we take crypto (LTC/BTC/BCH/XMR/DOGE/EOS/HIVE/HBD) \n"

    echo -e " Arguments/Flags: \n"
    echo -e "     -c/--config [file]       Override the env var CONFIG_FILE with the config path specified."
    echo -e "     -p/--port [port]         Override the env var ABE_PORT with the port number specified."
    echo -e "     -P/--python [exe_file]   Override the env var PY_EXE with the alternative Python interpreter specified. \n"

    echo -e " Commands: \n"
    echo -e "     (load/index/blocks/chain/read) - Run Abe block loader/indexer - indexes blockchain into DB"
    echo -e "     (srv/serve/web/site/publish/net/http) - Run Abe web server (def port: ${ABE_PORT}) - should be placed behind nginx/caddy\n"

    echo -e "     (env|dumpenv|dump-env) - Read the example ENV file at ${DIR}/dkr/example.env to STDOUT (for generating a base ENV file)"
    echo -e "     (conf|cfg|config|dumpconf|dumpcfg|dump-conf|dump-cfg|exampleconf) - Read the current config file at ${CONFIG_FILE} to STDOUT (for generating a base config file). For a default Abe install, CONFIG_FILE is likely pointed at an example config file.\n"

    echo -e "     (shell|bash|sh) - Launch a bash shell. Primarily intended for use inside of the Abe docker container, to allow launching a bash shell for debugging/diagnostics while run.sh is the entrypoint."
    >&2 echo -e "     (python|py|python2|py2) - Launch a python2.7 (or PY_EXE) shell. Primarily intended for use inside of the Abe docker container, to allow launching a bash shell for debugging/diagnostics while run.sh is the entrypoint."
    echo -e "     (python3|python(3.6/3.7/3.8/3.9)) - Launch a python3, python3.7, or other python3 version shell. Primarily intended for use inside of the Abe docker container, to allow launching a bash shell for debugging/diagnostics while run.sh is the entrypoint.\n"
}

abe-server() {
    local abeport="$ABE_PORT"
    (( $# > 0 )) && abeport="$1" && shift
    dbg "ABESTART at start of abe-server / before appending abe-server args:" "${ABESTART[@]}"
    if (( $# > 0 )); then
        ABESTART+=("$@")
        dbg "ABESTART after appending abe-server args:" "${ABESTART[@]}"
    fi

    >&2 echo -e "\n >>> Starting ABE web server on port ${abeport}. Command: ${ABESTART[*]} --no-load --port $abeport \n\n"
    "${ABESTART[@]}" --no-load --port "$abeport"
}

if [[ -n "$ABESTART_LINE" ]]; then
    ABESTART=($ABESTART_LINE)
    dbg "ABESTART_LINE is non-empty. Set ABESTART to: $ABESTART_LINE"
else
    abst="$(gen-abestart)"
    ABESTART=($abst)
    dbg "ABESTART_LINE is empty. Generating ABESTART. Set ABESTART to: $abst"
fi
dbg "Current ABESTART[0] is: ${ABESTART[0]}"
dbg "Current ABESTART[-1] is: ${ABESTART[-1]}"
export ABESTART

while (( $# > 0 )); do
    if (( $# > 0 )) && [[ "$1" == "-c" || "$1" == "--config" ]]; then
        CONFIG_FILE="$2"
        dbg "Set CONFIG_FILE to: $CONFIG_FILE"
        shift; shift; continue;
    fi
    if (( $# > 0 )) && [[ "$1" == "-p" || "$1" == "--port" ]]; then
        ABE_PORT="$2"
        dbg "Set ABE_PORT to: $ABE_PORT"
        shift; shift; continue;
    fi
    if (( $# > 0 )) && [[ "$1" == "-P" || "$1" == "--python" ]]; then
        PY_EXE="$2"
        dbg "Set PY_EXE to: $PY_EXE"
        shift; shift; continue;
    fi
    export CONFIG_FILE ABE_PORT PY_EXE
    if [[ -n "$ABESTART_LINE" ]]; then
        ABESTART=($ABESTART_LINE)
        dbg "ABESTART_LINE is non-empty. Set ABESTART to: $ABESTART_LINE"
    else
        abst="$(gen-abestart)"
        ABESTART=($abst)
        dbg "ABESTART_LINE is empty. Generating ABESTART. Set ABESTART to: $abst"
    fi
    dbg "Current ABESTART[0] is: ${ABESTART[0]}"
    dbg "Current ABESTART[-1] is: ${ABESTART[-1]}"
    export ABESTART

    case "$1" in
        load*|index*|bloc*|chai*|rea*)
            abe-loader "${@:2}"
            exit $?
            ;;
        srv*|serv*|web*|sit*|pub*|net*|ht*)
            abe-server "${@:2}"
            exit $?
            ;;
        # This subcommand is intended specifically for use with the docker image.
        # It allows users to launch a bash shell while run.sh is the entrypoint.
        shell|bash|sh|zsh|'/bin/bash'|'/bin/sh'|'/usr/bin/bash'|'/usr/bin/sh')
            bash "${@:2}"
            exit $?
            ;;
        py|py2|python|python2|python2.7)
            "$PY_EXE"
            exit $?
            ;;
        python3|python3.6|python3.7|python3.8|python3.9)
            "$1" "${@:2}"
            exit $?
            ;;
        env*|dumpenv*|dump-env*)
            dump-env
            ;;
        conf*|dumpconf*|cfg|dump-conf*|dumpcfg|dump-cfg|exampleconf*|examplecfg*)
            dump-config
            ;;
        help|-h|--help|'-?'|'/?'|'/h'|'/help')
            print-help
            ;;
        *)
            >&2 echo -e "\n [!!!] Invalid sub-command.\n"
            >&2 print-help
            exit 5
            ;;
    esac
    #>&2 echo -e "\n [!!!] Impossible code was ran! All case statements should exit... \n"
    exit 0
done

if [[ -n "$ABESTART_LINE" ]]; then
    ABESTART=($ABESTART_LINE)
    dbg "ABESTART_LINE is non-empty. Set ABESTART to: $ABESTART_LINE"
else
    abst="$(gen-abestart)"
    ABESTART=($abst)
    dbg "ABESTART_LINE is empty. Generating ABESTART. Set ABESTART to: $abst"
fi
dbg "Current ABESTART[0] is: ${ABESTART[0]}"
dbg "Current ABESTART[-1] is: ${ABESTART[-1]}"
export ABESTART
abe-server
exit $?
# >&2 echo -e "\n [!!!] No sub-command specified - please specify a subcommand.\n"
# >&2 echo -e   "       Commands: (load/index/blocks/chain/read) or (srv/serve/web/site/publish/net/http)\n"

# exit 4

