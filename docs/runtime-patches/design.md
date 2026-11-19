# Runtime patch design

Existing audit presentation is reused. Lazyweb is out of scope for this backend change.

Read bounded repository version files, official Docker image pins in Dockerfiles and YAML, and root runtime constraints. Distinguish pinned releases from constraints, floating tags, and bundled or distribution versions. Never contact a running deployment. The feeds are fixed official URLs and never receive repository data.

PHP uses the latest 50 php-src public advisories, requiring a supported numeric range and a documented patch. nginx uses product advisories, considering the fixed-version exception within a stable branch even when the broad vulnerable range overlaps it. Node.js uses the official release index security flag and the release schedule. A security release with unknown per-CVE applicability is an update recommendation, not a CVE match. Cache feeds for up to one hour and record feed failures. New runtime findings contain no generated install command.

The component inventory also records unmapped images and additional version declarations from CI settings and tool-version files. Go uses official release history and PostgreSQL uses the branch/fixed release table. Each declared version retains a lookup status, and matched advisories are exported by the existing MCP report. PHP advisory symbols are looked up lexically in bounded source files to provide possible usage locations.

Official sources: [php-src advisories](https://github.com/php/php-src/security/advisories), [PHP unsupported branches](https://www.php.net/eol.php), [nginx advisories](https://nginx.org/en/security_advisories.html), [Node.js releases](https://nodejs.org/en/about/previous-releases), [Go release history](https://go.dev/doc/devel/release), [PostgreSQL security](https://www.postgresql.org/support/security/).

For Dockerfiles, track simple numeric global `ARG` defaults before the first `FROM` and substitute plain `$NAME` and `${NAME}` references in the image tag of a known official image. Reuse version and digest validation after expansion. Scope ends at the first stage, and dynamic expressions, missing values, and non-version text stay unresolved. Preserve the original `FROM` value, evidence lines and the resolved default version. Findings state that build overrides can change the actual version. No Docker build, environment lookup or registry query is performed. See the [Dockerfile ARG reference](https://docs.docker.com/reference/dockerfile/#understand-how-arg-and-from-interact).
