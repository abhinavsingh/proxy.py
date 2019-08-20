from urllib import parse as urlparse
from proxy import HttpProtocolBasePlugin, ProxyRequestRejected


class RedirectToCustomServerPlugin(HttpProtocolBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    def __init__(self):
        super(RedirectToCustomServerPlugin, self).__init__()

    def on_request_complete(self):
        if self.request.method != 'CONNECT':
            self.request.url = urlparse.urlsplit(b'http://localhost:9999')


class FilterByTargetDomainPlugin(HttpProtocolBasePlugin):
    """Only accepts specific requests dropping all other requests."""

    def __init__(self):
        super(FilterByTargetDomainPlugin, self).__init__()
        self.allowed_domains = [b'google.com', b'www.google.com', b'google.com:443', b'www.google.com:443']

    def on_request_complete(self):
        # TODO: Refactor internals to cleanup mess below, due to how urlparse works, hostname/path attributes
        # are not consistent between CONNECT and non-CONNECT requests.
        if (self.request.method != b'CONNECT' and self.request.url.hostname not in self.allowed_domains) or \
                (self.request.method == b'CONNECT' and self.request.url.path not in self.allowed_domains):
            raise ProxyRequestRejected(status_code=418, body='I\'m a tea pot')


class SaveHttpResponses(HttpProtocolBasePlugin):
    """Saves Http Responses locally on disk."""

    def __init__(self):
        super(SaveHttpResponses, self).__init__()

    def handle_response_chunk(self, chunk):
        return chunk
