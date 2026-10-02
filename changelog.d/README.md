# Changelog fragments

Each pull request with a user-visible change adds one file here, named after
the pull request number (`123.md`). Parallel pull requests therefore never
conflict on `CHANGELOG.md`.

A fragment uses the Keep a Changelog sections that apply, with one bullet per
change, written for SDK users (what changed and what they must do):

```markdown
### Changed

- `rl_init` rejects configs whose `struct_size` is smaller than ABI 3 requires.
  Rebuild against the new `routeloom.h`.
```

Sections: `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
Breaking changes start with **Breaking:**. At release, the fragments are merged
into a new version section of `CHANGELOG.md` and deleted in the same commit.

For a review-only Unreleased section, run `python3 tools/assemble_changelog.py`
from the repository root. It prints the fragments in section order without
changing `CHANGELOG.md`, deleting fragments or creating a tag.
