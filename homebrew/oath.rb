class Oath < Formula
  desc "Security-first npm/npx replacement with malware scanning"
  homepage "https://github.com/generalized-labs/oath"
  url "https://github.com/generalized-labs/oath/releases/download/v0.3.0/oath-aarch64-apple-darwin.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  version "0.3.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/generalized-labs/oath/releases/download/v0.3.0/oath-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_ARM64"
    else
      url "https://github.com/generalized-labs/oath/releases/download/v0.3.0/oath-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_X86_64"
    end
  end

  def install
    bin.install "oath"
  end

  test do
    assert_match "oath", shell_output("#{bin}/oath --version")
  end
end
