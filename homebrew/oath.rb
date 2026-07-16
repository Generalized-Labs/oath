# typed: strict
# frozen_string_literal: true

# Oath installs the security-first JavaScript package workflow CLI.
class Oath < Formula
  desc "Security-first JavaScript package workflow and assessed npx alternative"
  homepage "https://github.com/Generalized-Labs/oath"
  url "https://github.com/Generalized-Labs/oath/archive/refs/tags/v0.2.4.tar.gz"
  sha256 "49e687698000e4e7ec9d66b25432b28437a31c580eba52d828186b43733785a1"
  license "Apache-2.0"
  head "https://github.com/Generalized-Labs/oath.git", branch: "master"

  # Build from source: only the source-tarball sha256 above needs updating per
  # release (deterministic from the tag), and building locally is a good fit for
  # a security tool. On a new tag, bump `url` + `sha256` and you're done.
  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--bin", "oath",
           "--root", prefix, "--path", "crates/oath-cli"
  end

  test do
    assert_match "oath #{version}", shell_output("#{bin}/oath --version")
  end
end
