class Proxy < Formula
  desc "⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging."
  homepage "https://github.com/abhinavsingh/proxy.py"
  url "https://github.com/abhinavsingh/proxy.py/archive/master.zip"
  version "1.1.1"

  depends_on "python"

  def install
    system "python3", *Language::Python.setup_install_args(libexec)
    bin.install Dir[libexec/"bin/*"]
    bin.env_script_all_files(libexec/"bin", :PYTHONPATH => ENV["PYTHONPATH"])
  end
end
