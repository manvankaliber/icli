class Icli < Formula
  desc "Agent-friendly CLI for Apple iCloud"
  homepage "https://github.com/manvankaliber/icli"
  version "1.4.0"
  license "MIT"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.0/icli-v1.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "3cbeb66a0e150c90054618a67267883f14cd77bd63414a83f5990d7053b4eb1f"
    else
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.0/icli-v1.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "d8318353a7e9892c4354134617e25e4370a849945725cf6dfa59fb148a94d766"
    end
  else
    depends_on "dbus"
    if Hardware::CPU.arm?
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.0/icli-v1.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c3095a5c0ff51152edde2043e8bf66a69cbdb893f4d6e5d6d96790c3b6e08cdf"
    else
      url "https://github.com/manvankaliber/icli/releases/download/v1.4.0/icli-v1.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "e6d86394021af8794f490b38067cb2244af2c22afbc239aa50e9bd05a4aa17df"
    end
  end

  def install
    bin.install "icli"
  end

  test do
    assert_match "icli #{version}", shell_output("#{bin}/icli --version")
  end
end
