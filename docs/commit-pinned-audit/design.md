# Commit-pinned audit design

ARTEX / NetworkPNTR keeps exact versioned evidence and separates acquisition errors from confirmed findings. RepoAUDT applies the same principle to source: resolve the target through GitHub, fetch the exact commit into a temporary checkout, compare its commit and tree IDs to GitHub, then scan. Do not consult or reset a same-named local clone. Keep the resolved branch or requested commit in the report. Explicit local paths retain their working-tree semantics and distinct provenance.

The checkout uses an isolated Git configuration, skips hooks, filters and submodules, and materializes symlinks as text. This change is backend only. Lazyweb is out of scope.
