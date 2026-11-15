class Icli < Formula
  desc "Agent-friendly CLI for Apple iCloud"
  homepage "https://github.com/manvankaliber/icli"
  version "1.4.1"
  license "MIT"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.1/icli-v1.4.1-aarch64-apple-darwin.tar.gz"
      sha256 "38f5356ac97e7e5b086aa8ca81dceccf33903bfe3f553f832165797c6fda2167"
    else
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.1/icli-v1.4.1-x86_64-apple-darwin.tar.gz"
      sha256 "6669df67aea21081d912259d65fe4787b499af1672886bc3e7c08ac45873f5c9"
    end
  else
    depends_on "dbus"
    if Hardware::CPU.arm?
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.1/icli-v1.4.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ee868ef30ce0a5016c66c11e43eda2ea77dea4a0a0413525ad9cf46fd6b7abc9"
    else
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.1/icli-v1.4.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "18ea0961fdb42ab539e4a16774c66d4dd0d8768534b79fe0038b9efef2b6d70f"
    end
  end

  def install
    bin.install "icli"
  end

  test do
    assert_match "icli #{version}", shell_output("#{bin}/icli --version")
  end
end
