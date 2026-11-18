"""Transport validation shared by local inference and configured MCP connections."""

import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(
            "Redirects are not allowed for configured connection endpoints"
        )


def validate_endpoint(value, local_only=False):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Invalid endpoint URL")
    url = urllib.parse.urlsplit(value.strip())
    loopback = url.hostname in ("localhost", "127.0.0.1", "::1")
    if (
        url.scheme not in ("http", "https")
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
    ):
        raise ValueError(
            "Use an HTTP(S) endpoint without credentials, query or fragment"
        )
    if local_only and not loopback:
        raise ValueError("Local LLM endpoints must use localhost, 127.0.0.1 or ::1")
    if url.scheme == "http" and not loopback:
        raise ValueError("Remote MCP endpoints require HTTPS")
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError("Invalid endpoint port")
    return value.strip().rstrip("/")


def open_endpoint(request, timeout=20):
    # Ignore proxy environment variables so local inference stays on loopback.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    ).open(request, timeout=timeout)
