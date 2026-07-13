class Oath < Formula
  desc "Security-first JavaScript package workflow and assessed npx alternative"
  homepage "https://github.com/Generalized-Labs/oath"
  url "https://github.com/Generalized-Labs/oath/archive/refs/tags/v0.1.7.tar.gz"
  sha256 "283ab6b3ad8c8b9cd02c28918eb16d43104a71504c7719a1a622e3ebc2482659"
  license "MIT"
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
