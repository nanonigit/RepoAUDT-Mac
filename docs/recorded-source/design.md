# Recorded source design

Lazyweb references for GitHub code review and Cursor Bugbot emphasize placing evidence alongside the relevant line. The existing finding shows the four recorded steps, their exact commit links and the original fix diff. The live comparison stays in its own area. When it is unavailable, show the preserved audited route and no current version.

Record only redacted snippets from the checked-out pinned revision. Validate file, line and full hash against the saved finding before returning an offline fallback. Never promote a failed live comparison to a verdict. Shell subprocess errors expose only classified diagnostic codes.

[Lazyweb design references](https://www.lazyweb.com/agentic-search/8530daaf-9c5c-4325-b6ba-78a857d05db0)
