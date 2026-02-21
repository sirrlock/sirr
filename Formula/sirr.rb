class Sirr < Formula
  desc "Sirr (سر) — ephemeral secret vault: TTL + read-limit, single binary"
  homepage "https://github.com/yourorg/sirr"
  license "BUSL-1.1"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/yourorg/sirr/releases/download/v#{version}/sirr-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_AARCH64_DARWIN"
    end
    on_intel do
      url "https://github.com/yourorg/sirr/releases/download/v#{version}/sirr-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_X86_64_DARWIN"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/yourorg/sirr/releases/download/v#{version}/sirr-aarch64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_AARCH64_LINUX"
    end
    on_intel do
      url "https://github.com/yourorg/sirr/releases/download/v#{version}/sirr-x86_64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_X86_64_LINUX"
    end
  end

  def install
    bin.install "sirr"
  end

  test do
    # Verify binary runs and help flag exits cleanly.
    assert_match "sirr", shell_output("#{bin}/sirr --help 2>&1", 0)
  end
end
