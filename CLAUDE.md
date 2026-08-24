# CLAUDE.md

## Branches

`main` and `TCP53` are independent. They share no code, dependencies, or
architecture, and are not to be merged into each other.

- `main` — Python/Flask web dashboard for connection testing.
- `TCP53` — TCP/53 block detection. Two implementations sharing one
  configuration file and one log format: Windows PowerShell 5.1 at the
  repository root, and Python 3 standard library under `linux/`. No
  external dependencies, no network service, on either.

Do not introduce one branch's dependencies or assumptions into the other.
Keep the repository to these two branches.

## Commits

Commit in small, self-contained increments. One logical change per commit,
rather than accumulating work into a single large commit.

## Pull requests

Every fix or change goes through a pull request targeting the branch it
belongs to (`main` or `TCP53`) — never commit a fix straight to that branch.
Do not merge a PR until its CI/CD checks pass; once they do, merge it back
into the target branch.

## Documentation

Documentation states what the code does and how to run it. It does not
record decisions, rationale for past changes, or conversation history.
