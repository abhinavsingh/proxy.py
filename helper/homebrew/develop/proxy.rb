class Proxy < Formula
  include Language::Python::Virtualenv

  desc "⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging."
  homepage "https://github.com/abhinavsingh/proxy.py"
  url "https://github.com/abhinavsingh/proxy.py/archive/develop.zip"
  version "develop"

  depends_on "python"

  resource "typing-extensions" do
    url "https://files.pythonhosted.org/packages/6a/28/d32852f2af6b5ead85d396249d5bdf450833f3a69896d76eb480d9c5e406/typing_extensions-3.7.4.2.tar.gz"
    sha256 "79ee589a3caca649a9bfd2a8de4709837400dfa00b6cc81962a1e6a1815969ae"
  end

  def install
    virtualenv_install_with_resources
  end
end
