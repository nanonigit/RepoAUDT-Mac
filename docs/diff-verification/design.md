# Local diff verification design

Lazyweb code-review references showed checks next to the diff. Use the existing finding and repair details with a bounded verification action and a compact before/after receipt.

Use immutable Git objects from an origin-matched clone when available. Check the commit, tree and blob identity. Fall back to the existing exact GitHub checkout if needed. Prepare the supported removal patch again from the original bytes and compare it with the stored diff. Apply only that patch in a temporary directory, parse the new source and rerun the same static rule. Never run repository code or accept a patch or shell command from the UI.
