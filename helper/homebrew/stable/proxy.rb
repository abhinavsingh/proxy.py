class Proxy < Formula
  include Language::Python::Virtualenv

  desc "⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging."
  homepage "https://github.com/abhinavsingh/proxy.py"
  url "https://github.com/abhinavsingh/proxy.py.git", :using => :git, :branch => "master"
  version "stable"

  depends_on "python@3.10"

  def install
    virtualenv_install_with_resources
  end
end
