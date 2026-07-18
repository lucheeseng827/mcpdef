# PLACEHOLDER — the release workflow (.github/workflows/release.yml) regenerates this file on
# every real `v*` tag with the published version + the four real sha256 checksums, and commits
# it to the mirror's main branch. It is intentionally NOT synced from the monorepo (see
# .ossync.yaml), so this placeholder never ships a broken tap. Kept here for reference only.
class Mcpdef < Formula
  desc "Fast, self-hostable, single-binary MCP gateway & governance plane"
  homepage "https://github.com/lucheeseng827/mcpdef"
  version "0.0.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/lucheeseng827/mcpdef/releases/download/v0.0.0/mcpdef-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/lucheeseng827/mcpdef/releases/download/v0.0.0/mcpdef-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/lucheeseng827/mcpdef/releases/download/v0.0.0/mcpdef-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/lucheeseng827/mcpdef/releases/download/v0.0.0/mcpdef-x86_64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "mcpdef"
  end

  test do
    assert_match "mcpdef", shell_output("#{bin}/mcpdef version")
  end
end
