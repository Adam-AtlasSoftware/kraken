# Environment for the real-Ghidra tests and the Ghidra extension build. Source it:
#
#   . scripts/dev-env.sh
#
# It points KRAKEN_GHIDRA_HOME / GHIDRA_INSTALL_DIR and KRAKEN_JAVA_HOME / JAVA_HOME at the
# pinned Ghidra 12.1.4 and JDK 21, looked for in ~/.cache/kraken-dev (the CI layout) and then in
# what `kraken setup` installed ($XDG_DATA_HOME/kraken/runtime, default ~/.local/share/...).
# Run `kraken setup` first if neither exists.

_kraken_pick() { # <subdir> <prefix>: the first directory whose name starts with it
  for _root in "$HOME/.cache/kraken-dev" "${XDG_DATA_HOME:-$HOME/.local/share}/kraken/runtime"; do
    [ -d "$_root/$1" ] || continue
    for _d in "$_root/$1"/*; do
      case "${_d##*/}" in
        "$2"*) [ -d "$_d" ] && { printf '%s\n' "$_d"; return 0; } ;;
      esac
    done
  done
  return 1
}

if _ghidra=$(_kraken_pick ghidra ghidra_12.1.4_PUBLIC) && _jdk=$(_kraken_pick jdk jdk-21); then
  export KRAKEN_GHIDRA_HOME="$_ghidra" GHIDRA_INSTALL_DIR="$_ghidra"
  export KRAKEN_JAVA_HOME="$_jdk" JAVA_HOME="$_jdk"
  echo "Ghidra: $_ghidra"
  echo "JDK:    $_jdk"
else
  echo "no Ghidra 12.1.4 and JDK 21 found; run \`kraken setup\` first" >&2
fi
unset -f _kraken_pick
unset _root _d _ghidra _jdk
