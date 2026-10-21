class Icli < Formula
  desc "Agent-friendly CLI for iCloud Calendar, Mail, and Contacts"
  homepage "https://github.com/manvankaliber/icli"
  version "0.1.0"
  license "MIT"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/manvankaliber/icli/releases/download/v0.1.0/icli-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "e37d48cb846e33b1bc486ed31e5aa6d28594df0f5e79057c0b5a7310bff1c6b9"
    else
      url "https://github.com/manvankaliber/icli/releases/download/v0.1.0/icli-v0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "4abec4ecc982594b28e688409cd6145b4d4fe43e24d79bc06d1600b2bee7f332"
    end
  else
    depends_on "dbus"
    if Hardware::CPU.arm?
      url "https://github.com/manvankaliber/icli/releases/download/v0.1.0/icli-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b2b4c44abc5b207912732958bbac0a3afc949e5fa9be4f2ab80795b49d3c5f8a"
    else
      url "https://github.com/manvankaliber/icli/releases/download/v0.1.0/icli-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0c01c6631a81c08420e8f03d051c304ad1a7307eb787232f0de20de0e3cbea98"
    end
  end

  def install
    bin.install "icli"
  end

  test do
    assert_match "icli #{version}", shell_output("#{bin}/icli --version")
  end
end
