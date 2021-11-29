# Adding change notes with your PRs

It is very important to maintain a log for news of how
updating to the new version of the software will affect
end-users. This is why we enforce collection of the change
fragment files in pull requests as per [Towncrier philosophy].

The idea is that when somebody makes a change, they must record
the bits that would affect end-users only including information
that would be useful to them. Then, when the maintainers publish
a new release, they'll automatically use these records to compose
a change log for the respective version. It is important to
understand that including unnecessary low-level implementation
related details generates noise that is not particularly useful
to the end-users most of the time. And so such details should be
recorded in the Git history rather than a changelog.

# Alright! So how do I add a news fragment?

To submit a change note about your PR, add a text file into the
`docs/changelog-fragments.d/` folder. It should contain an
explanation of what applying this PR will change in the way
end-users interact with the project. One sentence is usually
enough but feel free to add as many details as you feel necessary
for the users to understand what it means.

**Use the past tense** for the text in your fragment because,
combined with others, it will be a part of the "news digest"
telling the readers **what changed** in a specific version of
the library *since the previous version*. You should also use
[MyST Markdown] syntax for highlighting code (inline or block),
linking parts of the docs or external sites.
At the end, sign your change note by adding ```-- by
{user}`github-username``` (replace `github-username` with
your own!).

Finally, name your file following the convention that Towncrier
understands: it should start with the number of an issue or a
PR followed by a dot, then add a patch type, like `feature`,
`bugfix`, `doc`, `misc` etc., and add `.md` as a suffix. If you
need to add more than one fragment, you may add an optional
sequence number (delimited with another period) between the type
and the suffix.

# Examples for changelog entries adding to your Pull Requests

File `docs/changelog-fragments.d/112.doc.md`:

```md
Added a `{user}` role to Sphinx config -- by {user}`webknjaz`
```

File `docs/changelog-fragments.d/105.feature.md`:

```md
Added the support for keyboard-authentication method
-- by {user}`Qalthos`
```

File `docs/changelog-fragments.d/57.bugfix.md`:

```md
Fixed flaky SEGFAULTs in `pylibsshext.channel.Channel.exec_command()`
calls -- by {user}`ganeshrn`
```

```{tip}
See `pyproject.toml` for all available categories
(`tool.towncrier.type`).
```


[MyST Markdown]:
https://myst-parser.rtfd.io/en/latest/syntax/syntax.html
[Towncrier philosophy]:
https://towncrier.rtfd.io/en/actual-freaking-docs/#philosophy
