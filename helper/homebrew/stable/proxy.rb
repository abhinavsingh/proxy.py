class Proxy < Formula
  include Language::Python::Virtualenv

  desc "⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging."
  homepage "https://github.com/abhinavsingh/proxy.py"
  url "https://github.com/abhinavsingh/proxy.py/archive/master.zip"
  sha256 "715687cebd451285d266f29d6509a64becc93da21f61ba9b4414e7dc4ecaaeed"
  version "2.3.1"

  depends_on "python"

  def install
    virtualenv_install_with_resources
  end
end
