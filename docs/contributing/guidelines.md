```{spelling}
de
facto
Pre
reStructuredText
Towncrier
```

```{include} ../../CONTRIBUTING.md
```

# Contributing docs

We use [Sphinx] to generate our docs website. You can trigger
the process locally by executing:

```shell-session
$ tox -e build-docs
```

It is also integrated with [Read The Docs] that builds and
publishes each commit to the main branch and generates live
docs previews for each pull request.

The sources of the [Sphinx] documents use reStructuredText as a
de-facto standard. But in order to make contributing docs more
beginner-friendly, we have integrated [MyST parser] allowing us
to also accept new documents written in an extended version of
Markdown that supports using Sphinx directives and roles. {ref}`Read
the docs <myst:intro/writing>` to learn more on how to use it.


[MyST parser]: https://pypi.org/project/myst-parser/
[Read The Docs]: https://readthedocs.org
[Sphinx]: https://www.sphinx-doc.org

```{include} ../changelog-fragments.d/README.md
```
