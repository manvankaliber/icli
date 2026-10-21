#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo install --path "$root" --locked --force
cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
case ":${PATH:-}:" in
  *":$cargo_bin:"*) ;;
  *)
    export PATH="$cargo_bin:$PATH"
    line="export PATH=\"$cargo_bin:\$PATH\" # icli dev installer"
    for profile in "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.zprofile" "$HOME/.zshrc"; do
      if [ -f "$profile" ] && grep -Fq '# icli dev installer' "$profile"; then continue; fi
      printf '\n%s\n' "$line" >> "$profile"
    done
    ;;
esac
icli --version
printf 'Local icli is ready. Try: icli help\n'
