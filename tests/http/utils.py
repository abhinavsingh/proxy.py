from typing import Type
from proxy.http.proxy import HttpProxyBasePlugin

from plugin_examples import modify_post_data
from plugin_examples import mock_rest_api
from plugin_examples import redirect_to_custom_server
from plugin_examples import filter_by_upstream
from plugin_examples import cache_responses
from plugin_examples import man_in_the_middle


def get_plugin_by_test_name(test_name: str) -> Type[HttpProxyBasePlugin]:
    plugin: Type[HttpProxyBasePlugin] = modify_post_data.ModifyPostDataPlugin
    if test_name == 'test_modify_post_data_plugin':
        plugin = modify_post_data.ModifyPostDataPlugin
    elif test_name == 'test_proposed_rest_api_plugin':
        plugin = mock_rest_api.ProposedRestApiPlugin
    elif test_name == 'test_redirect_to_custom_server_plugin':
        plugin = redirect_to_custom_server.RedirectToCustomServerPlugin
    elif test_name == 'test_filter_by_upstream_host_plugin':
        plugin = filter_by_upstream.FilterByUpstreamHostPlugin
    elif test_name == 'test_cache_responses_plugin':
        plugin = cache_responses.CacheResponsesPlugin
    elif test_name == 'test_man_in_the_middle_plugin':
        plugin = man_in_the_middle.ManInTheMiddlePlugin
    return plugin
