from urllib import parse as urlparse
from proxy import HttpProxyPlugin, ProxyRejectRequest


class RedirectToCustomServerPlugin(HttpProxyPlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    def __init__(self):
        super(RedirectToCustomServerPlugin, self).__init__()

    def handle_request(self, request):
        if request.method != 'CONNECT':
            request.url = urlparse.urlsplit(b'http://localhost:9999')
        return request


class FilterByTargetDomainPlugin(HttpProxyPlugin):
    """Only accepts specific requests dropping all other requests."""

    def __init__(self):
        super(FilterByTargetDomainPlugin, self).__init__()
        self.allowed_domains = [b'google.com', b'www.google.com', b'google.com:443', b'www.google.com:443']

    def handle_request(self, request):
        # TODO: Refactor internals to cleanup mess below, due to how urlparse works, hostname/path attributes
        # are not consistent between CONNECT and non-CONNECT requests.
        if (request.method != b'CONNECT' and request.url.hostname not in self.allowed_domains) or \
                (request.method == b'CONNECT' and request.url.path not in self.allowed_domains):
            raise ProxyRejectRequest(status_code=418, body='I\'m a tea pot')
        return request
