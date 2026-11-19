# Design

Lazyweb's GitHub code review reference keeps the review status next to the code change. Present both SHA identifiers and the scoped result within the original finding, alongside the existing diff check. Require a full commit SHA, a matching GitHub origin and ancestry from the audit commit. Read both pinned source blobs from local Git with no replacement objects, grafts or lazy fetch. No working-tree reads or execution. A missing or unreadable source path yields an unavailable check. Local evidence does not assert remote branch status or a general security result.
