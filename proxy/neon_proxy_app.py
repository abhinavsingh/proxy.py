from .proxy import entry_point

from .statistics_exporter.prometheus_proxy_server import PrometheusProxyServer


class NeonProxyApp:

    def start(self):
        PrometheusProxyServer()
        entry_point()
