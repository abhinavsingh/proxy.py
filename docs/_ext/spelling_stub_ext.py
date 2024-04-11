"""Sphinx extension for making the spelling directive noop."""

from typing import List, Dict, Any

from sphinx.util.nodes import nodes
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxDirective


class SpellingNoOpDirective(SphinxDirective):
    """Definition of the stub spelling directive."""

    has_content = True

    def run(self) -> List[nodes.Node]:
        """Generate nothing in place of the directive."""
        return []


def setup(app: Sphinx) -> Dict[str, Any]:
    """Initialize the extension."""
    app.add_directive('spelling', SpellingNoOpDirective)

    return {
        'parallel_read_safe': True,
        'version': 'builtin',
    }
