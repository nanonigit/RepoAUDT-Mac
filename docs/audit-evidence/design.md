# Design

Lazyweb desktop references included GitHub Discussions' contextual navigation and GitHub Copilot's code-adjacent assistance. Keep source evidence in the finding and open a separate, focused conversation from the sidebar or the finding. Put commit and file links next to the evidence and retain the existing palette.

Use read-only GitHub API calls through the user's existing gh authentication. Resolve the default branch first and pin all subsequent reads to its SHA. Resolve legacy abbreviated audit SHAs separately. Compare unchanged files by blob ID and changed files by unique line or unique assignment name. Unknown evidence stays unknown.

Suppress only complete Terraform Secrets Manager ARN references in the generic password rule. Keep literal-secret rules active. Show the finding line locally. Supply only structured evidence to the AI provider along with the user's request and conversation history. The AI has no tools or write access.
