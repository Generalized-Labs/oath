class Oath < Formula
  desc "Security-first npm/npx replacement with malware scanning"
  homepage "https://github.com/Generalized-Labs/oath"
  url "https://github.com/Generalized-Labs/oath/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "70dc445f9da3e40209ee57a9c9c8946c86e32159cd8dbca8b81eb2225fc4b71b"
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
