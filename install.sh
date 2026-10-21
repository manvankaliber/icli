#!/bin/sh
set -eu

REPO="manvankaliber/icli"
BASE_URL="https://github.com/$REPO"

fail() {
  printf 'icli installer: %s\n' "$1" >&2
  exit 1
}

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

if [ "$os" = linux ]; then
  target="${arch}-unknown-linux-gnu"
else
  target="${arch}-apple-darwin"
fi

command -v curl >/dev/null 2>&1 || fail "curl is required to download icli"
tag_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$BASE_URL/releases/latest") || fail "could not find a published release"
tag=${tag_url##*/}
asset="icli-${tag}-${target}.tar.gz"
checksum="$asset.sha256"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

curl -fsSL "$BASE_URL/releases/download/$tag/$asset" -o "$tmp/$asset" || fail "no release binary found for $os/$arch ($target)"
curl -fsSL "$BASE_URL/releases/download/$tag/$checksum" -o "$tmp/$checksum" || fail "could not download the release checksum"
expected=$(tr -d '\r\n ' < "$tmp/$checksum")
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
else
  actual=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
fi
[ "$actual" = "$expected" ] || fail "release checksum did not match"
tar -xzf "$tmp/$asset" -C "$tmp"

bindir="${ICLI_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$bindir"
install -m 755 "$tmp/icli" "$bindir/icli"

case ":${PATH:-}:" in
  *":$bindir:"*) ;;
  *)
    line="export PATH=\"$bindir:\$PATH\" # icli installer"
    for profile in "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.zprofile" "$HOME/.zshrc"; do
      if [ -f "$profile" ] && grep -Fq '# icli installer' "$profile"; then continue; fi
      printf '\n%s\n' "$line" >> "$profile"
    done
    ;;
esac

printf 'Installed icli %s to %s/icli\n' "$tag" "$bindir"
case ":${PATH:-}:" in
  *":$bindir:"*) printf 'Run: icli --help\n' ;;
  *) printf 'Open a new terminal, then run: icli --help\n' ;;
esac
