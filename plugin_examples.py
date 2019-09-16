from urllib import parse as urlparse
import proxy


class RedirectToCustomServerPlugin(proxy.HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    def __init__(self, config, client, request):
        super(RedirectToCustomServerPlugin, self).__init__(config, client, request)

    def before_upstream_connection(self):
        if self.request.method != b'CONNECT':
            # Redirect all non-https requests to inbuilt WebServer.
            self.request.url = urlparse.urlsplit(b'http://localhost:8899')

    def on_upstream_connection(self):
        pass

    def handle_upstream_response(self, raw):
        return raw


class FilterByTargetDomainPlugin(proxy.HttpProxyBasePlugin):
    """Only accepts specific requests dropping all other requests."""

    def __init__(self, config, client, request):
        super(FilterByTargetDomainPlugin, self).__init__(config, client, request)
        self.filtered_domain = b'google.com'

    def before_upstream_connection(self):
        # TODO: Refactor internals to cleanup mess below, due to how urlparse works, hostname/path attributes
        # are not consistent between CONNECT and non-CONNECT requests.
        if (self.request.method != b'CONNECT' and self.filtered_domain in self.request.url.hostname) or \
                (self.request.method == b'CONNECT' and self.filtered_domain in self.request.url.path):
            raise proxy.HttpRequestRejected(status_code=418, body=b'I\'m a tea pot')

    def on_upstream_connection(self):
        pass

    def handle_upstream_response(self, raw):
        return raw


class SaveHttpResponses(proxy.HttpProxyBasePlugin):
    """Saves Http Responses locally on disk."""

    def __init__(self, config, client, request):
        super(SaveHttpResponses, self).__init__(config, client, request)

    def handle_upstream_response(self, chunk):
        return chunk

    def before_upstream_connection(self):
        pass

    def on_upstream_connection(self):
        pass
