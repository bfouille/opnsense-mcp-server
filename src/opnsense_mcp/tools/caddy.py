"""Caddy tools (os-caddy plugin) — status, Caddyfile, configuration CRUD, service management.

Secrets never leave these tools: every field name flagged by ``is_sensitive_tag``
(e.g. ``TlsDnsApiKey``, ``basicauthpass``, ``StaticKey``) is redacted from API
responses, and the generated Caddyfile is scrubbed of the same values.
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import Context

from opnsense_mcp.api_client import ENDPOINT_REGISTRY, OPNsenseAPI
from opnsense_mcp.config_cache import is_sensitive_tag
from opnsense_mcp.server import get_api, get_config_cache, mcp

# resource_type -> (API kind, request body key)
_CADDY_RESOURCES: dict[str, tuple[str, str]] = {
    "domains": ("reverse_proxy", "reverse"),
    "subdomains": ("subdomain", "subdomain"),
    "handlers": ("handle", "handle"),
    "access_lists": ("access_list", "accesslist"),
    "layer4": ("layer4", "layer4"),
}

# General settings safe to return (everything else may hold or hint at secrets).
_GENERAL_FIELDS = ("enabled", "EnableLayer4", "HttpPort", "HttpsPort", "DisableSuperuser")

# Field names that match a sensitive pattern but are plain flags.
_NOT_SENSITIVE: frozenset[str] = frozenset({"logcredentials"})

_REDACTED = "[REDACTED]"
_BCRYPT_RE = re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}")
_KEY_BLOCK_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)
_TLS_MODES = {"http": "0", "https": "1", "h2c": "2"}
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

ENDPOINT_REGISTRY.update(
    {
        "caddy.service.status": ("caddy/service/status", "caddy/service/status"),
        "caddy.service.reconfigure": ("caddy/service/reconfigure", "caddy/service/reconfigure"),
        "caddy.general.get": ("caddy/general/get", "caddy/general/get"),
        "caddy.general.set": ("caddy/general/set", "caddy/general/set"),
        "caddy.diagnostics.caddyfile": ("caddy/diagnostics/caddyfile", "caddy/diagnostics/caddyfile"),
    }
)


def _endpoint(verb: str, kind: str) -> str:
    """Register a reverse_proxy controller endpoint on demand and return its logical name."""
    logical = f"caddy.reverse_proxy.{verb}_{kind}"
    if logical not in ENDPOINT_REGISTRY:
        camel = verb + "".join(part.capitalize() for part in kind.split("_"))
        ENDPOINT_REGISTRY[logical] = (
            f"caddy/reverse_proxy/{camel}",
            f"caddy/reverse_proxy/{verb}_{kind}",
        )
    return logical


def _resource(resource_type: str) -> tuple[str, str] | None:
    return _CADDY_RESOURCES.get(resource_type)


def _invalid(resource_type: str) -> dict[str, Any]:
    valid = ", ".join(sorted(_CADDY_RESOURCES))
    return {"error": f"Invalid resource_type '{resource_type}'. Must be one of: {valid}"}


def _sensitive(name: str) -> bool:
    return name.lower() not in _NOT_SENSITIVE and is_sensitive_tag(name)


def _redact_value(data: object) -> object:
    """Recursively replace values of sensitive field names."""
    if isinstance(data, dict):
        return {k: (_REDACTED if _sensitive(str(k)) else _redact_value(v)) for k, v in data.items()}
    if isinstance(data, list):
        return [_redact_value(v) for v in data]
    return data


def _redact(data: dict[str, Any]) -> dict[str, Any]:
    return {k: (_REDACTED if _sensitive(k) else _redact_value(v)) for k, v in data.items()}


def _selected(field: object) -> str:
    """Plain value of an option/relation field as returned by a get_* call."""
    if isinstance(field, dict):
        return ",".join(str(k) for k, v in field.items() if isinstance(v, dict) and v.get("selected"))
    if isinstance(field, list):  # some option fields come back as a list indexed by value
        return ",".join(str(i) for i, v in enumerate(field) if isinstance(v, dict) and v.get("selected"))
    return "" if field is None else str(field)


async def _general_raw(api: OPNsenseAPI) -> dict[str, Any]:
    data = await api.get("caddy.general.get")
    general: dict[str, Any] = data.get("caddy", {}).get("general", {})
    return general


def _saved(result: dict[str, Any]) -> bool:
    return result.get("result") == "saved"


# --- Read tools ---------------------------------------------------------------------


@mcp.tool()
async def opn_caddy_status(ctx: Context) -> dict[str, Any]:
    """Get the Caddy reverse proxy service status (running / stopped / disabled).

    Note: Requires the Caddy plugin (os-caddy).
    Returns: dict with 'status'.
    """
    api = get_api(ctx)
    return await api.get("caddy.service.status")


@mcp.tool()
async def opn_caddy_general(ctx: Context) -> dict[str, Any]:
    """Get the non-secret Caddy general settings.

    Returns only: enabled, EnableLayer4, HttpPort, HttpsPort, DisableSuperuser,
    each as a plain string ("1"/"0", port number). DNS-provider credentials and
    other settings are never returned.
    """
    api = get_api(ctx)
    general = await _general_raw(api)
    return {k: _selected(general.get(k)) for k in _GENERAL_FIELDS}


@mcp.tool()
async def opn_caddy_search(
    ctx: Context,
    resource_type: str,
    search: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """Search Caddy reverse proxy resources by type.

    Resource types and their key fields:
    - domains: FromDomain (e.g. *.example.com), FromPort, CustomCertificate, accesslist
    - subdomains: FromDomain (FQDN), reverse (parent domain), accesslist
    - handlers: reverse, subdomain, HandlePath ("" = catch-all), ToDomain, ToPort,
      HttpTls ("0" http, "1" https, "2" h2c)
    - access_lists: accesslistName, clientIps, invert
    - layer4: Matchers (e.g. tlssni), FromDomain, ToDomain, ToPort, TerminateTls

    Secret fields are redacted. Returns: dict with 'rows' and 'rowCount'.
    """
    res = _resource(resource_type)
    if res is None:
        return _invalid(resource_type)
    api = get_api(ctx)
    result = await api.post(
        _endpoint("search", res[0]),
        {"current": 1, "rowCount": min(limit, 500), "searchPhrase": search},
    )
    return _redact(result)


@mcp.tool()
async def opn_caddy_get(
    ctx: Context,
    resource_type: str,
    uuid: str,
) -> dict[str, Any]:
    """Get every field of one Caddy resource (domains, subdomains, handlers, access_lists, layer4).

    Option and relation fields come back as {value: {value, selected}} maps.
    For domains, the CustomCertificate options list the available certificates
    by refid. Secret fields are redacted.
    Returns: dict keyed by the resource's body key (reverse, subdomain, handle, accesslist, layer4).
    """
    res = _resource(resource_type)
    if res is None:
        return _invalid(resource_type)
    api = get_api(ctx)
    result = await api.get(_endpoint("get", res[0]), path_suffix=uuid)
    return _redact(result)


@mcp.tool()
async def opn_caddy_caddyfile(ctx: Context) -> dict[str, Any]:
    """Get the Caddyfile that OPNsense generated from the current configuration.

    Use this to review what Caddy actually runs (sites, handlers, ports) after a
    change and opn_reconfigure_caddy. DNS API keys, basic-auth hashes and key
    blocks are replaced by [REDACTED].
    Returns: dict with 'status' and 'content' (str).
    """
    api = get_api(ctx)
    data = await api.get("caddy.diagnostics.caddyfile")
    content = str(data.get("content", ""))
    general = await _general_raw(api)
    for name, value in general.items():
        if _sensitive(name) and isinstance(value, str) and value:
            content = content.replace(value, _REDACTED)
    content = _BCRYPT_RE.sub(_REDACTED, content)
    content = _KEY_BLOCK_RE.sub(_REDACTED, content)
    return {"status": data.get("status", "unknown"), "content": content}


# --- Write tools --------------------------------------------------------------------


@mcp.tool()
async def opn_reconfigure_caddy(ctx: Context) -> dict[str, Any]:
    """Apply pending Caddy configuration changes (regenerates the Caddyfile and reloads Caddy).

    Changes made with the opn_caddy_* write tools take effect only after this.
    Check the result with opn_caddy_caddyfile and opn_caddy_status.
    Returns: dict with 'status' and 'service'.
    """
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("caddy.service.reconfigure", {})
    get_config_cache(ctx).invalidate()
    return {"status": result.get("status", "unknown"), "service": "caddy"}


@mcp.tool()
async def opn_caddy_add(
    ctx: Context,
    resource_type: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Create a Caddy resource (domains, subdomains, handlers, access_lists, layer4).

    config holds field name/value pairs as strings; omitted fields get defaults.
    Examples:
    - access_lists: {"accesslistName": "internal", "clientIps": "192.168.1.0/24"}
    - subdomains: {"reverse": "<domain-uuid>", "FromDomain": "app.example.com",
      "accesslist": "<acl-uuid or empty>"}
    - handlers: {"reverse": "<domain-uuid>", "subdomain": "<subdomain-uuid>",
      "HandlePath": "", "HandleDirective": "reverse_proxy", "ToDomain": "10.0.0.5",
      "ToPort": "8080", "HttpTls": "0"}  (HttpTls "1" https, "2" h2c;
      add "HttpTlsInsecureSkipVerify": "1" for self-signed upstreams)
    - layer4: {"Type": "listener_wrappers", "Protocol": "tcp", "Matchers": "tlssni",
      "FromDomain": "nas.example.com", "ToDomain": "10.0.0.6", "ToPort": "443",
      "TerminateTls": "0"}
    For the common "new service" case use opn_caddy_add_service.

    NOTE: Not applied until opn_reconfigure_caddy.
    Returns: dict with 'result' ("saved") and 'uuid', or 'validations' on failure.
    """
    res = _resource(resource_type)
    if res is None:
        return _invalid(resource_type)
    if not config:
        return {"error": "config must not be empty"}
    api = get_api(ctx)
    api.require_writes()
    result = await api.post(_endpoint("add", res[0]), {res[1]: config})
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_caddy_update(
    ctx: Context,
    resource_type: str,
    uuid: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Update fields of a Caddy resource; omitted fields keep their values.

    To enable/disable explicitly, set config={"enabled": "1"} or {"enabled": "0"}.
    NOTE: Not applied until opn_reconfigure_caddy.
    Returns: dict with 'result' ("saved") or 'validations'.
    """
    res = _resource(resource_type)
    if res is None:
        return _invalid(resource_type)
    if not config:
        return {"error": "config must not be empty"}
    api = get_api(ctx)
    api.require_writes()
    result = await api.post(_endpoint("set", res[0]), {res[1]: config}, path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_caddy_delete(
    ctx: Context,
    resource_type: str,
    uuid: str,
) -> dict[str, Any]:
    """Delete a Caddy resource by UUID.

    Delete handlers before the subdomain/domain they belong to, and subdomains
    before their domain. NOTE: Not applied until opn_reconfigure_caddy.
    Returns: dict with 'result' ("deleted").
    """
    res = _resource(resource_type)
    if res is None:
        return _invalid(resource_type)
    api = get_api(ctx)
    api.require_writes()
    result = await api.post(_endpoint("del", res[0]), {}, path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_caddy_toggle(
    ctx: Context,
    resource_type: str,
    uuid: str,
) -> dict[str, Any]:
    """Flip a Caddy resource between enabled and disabled.

    For an explicit state use opn_caddy_update with {"enabled": "0"|"1"}.
    NOTE: Not applied until opn_reconfigure_caddy.
    Returns: dict with 'result' and 'changed'.
    """
    res = _resource(resource_type)
    if res is None:
        return _invalid(resource_type)
    api = get_api(ctx)
    api.require_writes()
    result = await api.post(_endpoint("toggle", res[0]), {}, path_suffix=uuid)
    get_config_cache(ctx).invalidate()
    return result


@mcp.tool()
async def opn_caddy_set_general(
    ctx: Context,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Change Caddy general settings, e.g. {"enabled": "1"}, {"HttpPort": "80", "HttpsPort": "443"},
    {"EnableLayer4": "1"}, {"DisableSuperuser": "0"}.

    Secret settings (DNS-provider API keys) are refused: set those in the GUI.
    NOTE: Not applied until opn_reconfigure_caddy.
    Returns: dict with 'result' ("saved") or 'validations'.
    """
    if not config:
        return {"error": "config must not be empty"}
    secret = sorted(k for k in config if _sensitive(k))
    if secret:
        return {"error": f"Refusing to set secret fields through the MCP: {', '.join(secret)}"}
    api = get_api(ctx)
    api.require_writes()
    result = await api.post("caddy.general.set", {"caddy": {"general": config}})
    get_config_cache(ctx).invalidate()
    return result


async def _find_uuid(api: OPNsenseAPI, kind: str, field: str, value: str) -> str | None:
    found = await api.post(_endpoint("search", kind), {"current": 1, "rowCount": -1, "searchPhrase": ""})
    for row in found.get("rows", []):
        if row.get(field) == value and (kind != "reverse_proxy" or not row.get("FromPort")):
            uuid: str = row["uuid"]
            return uuid
    return None


@mcp.tool()
async def opn_caddy_add_service(
    ctx: Context,
    fqdn: str,
    to_host: str,
    to_port: int,
    tls: str = "http",
    insecure_skip_verify: bool = False,
    access_list: str = "",
    domain: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Publish a new service in one call: a subdomain plus its catch-all handler.

    Use this to add a service such as app.example.com -> 10.0.0.5:8080.
    - fqdn: the public name (app.example.com).
    - to_host / to_port: the upstream.
    - tls: how Caddy talks to the upstream: "http" (default), "https", or "h2c".
    - insecure_skip_verify: accept a self-signed upstream certificate (https only).
    - access_list: name or UUID of an access list to restrict clients (empty = everyone).
    - domain: parent domain UUID or name; default is the wildcard "*.<parent of fqdn>".
    If the handler cannot be created, the new subdomain is deleted again.

    NOTE: Not applied until opn_reconfigure_caddy.
    Returns: dict with 'domain_uuid', 'subdomain_uuid', 'handler_uuid', or 'error'.
    """
    tls_mode = _TLS_MODES.get(tls)
    if tls_mode is None:
        return {"error": f"Invalid tls '{tls}'. Must be one of: {', '.join(_TLS_MODES)}"}
    api = get_api(ctx)
    api.require_writes()

    if _UUID_RE.fullmatch(domain):
        domain_uuid: str | None = domain
    else:
        name = domain or "*." + fqdn.split(".", 1)[-1]
        domain_uuid = await _find_uuid(api, "reverse_proxy", "FromDomain", name)
        if domain_uuid is None:
            return {"error": f"Caddy domain '{name}' not found; create it or pass domain=<uuid>"}

    acl_uuid: str | None = ""
    if access_list:
        acl_uuid = access_list if _UUID_RE.fullmatch(access_list) else None
        if acl_uuid is None:
            acl_uuid = await _find_uuid(api, "access_list", "accesslistName", access_list)
        if acl_uuid is None:
            return {"error": f"Caddy access list '{access_list}' not found"}

    desc = description or fqdn
    sub = await api.post(
        _endpoint("add", "subdomain"),
        {
            "subdomain": {
                "enabled": "1",
                "reverse": domain_uuid,
                "FromDomain": fqdn,
                "accesslist": acl_uuid,
                "description": desc,
            }
        },
    )
    get_config_cache(ctx).invalidate()
    if not _saved(sub):
        return {"error": "subdomain not created", "validations": sub.get("validations", sub)}
    sub_uuid = str(sub["uuid"])

    handle: dict[str, Any] = {
        "enabled": "1",
        "reverse": domain_uuid,
        "subdomain": sub_uuid,
        "HandleType": "handle",
        "HandlePath": "",
        "HandleDirective": "reverse_proxy",
        "ToDomain": to_host,
        "ToPort": str(to_port),
        "HttpTls": tls_mode,
        "description": desc,
    }
    if insecure_skip_verify:
        handle["HttpTlsInsecureSkipVerify"] = "1"
    hres = await api.post(_endpoint("add", "handle"), {"handle": handle})
    if not _saved(hres):
        await api.post(_endpoint("del", "subdomain"), {}, path_suffix=sub_uuid)
        return {
            "error": "handler not created; the new subdomain was removed again",
            "validations": hres.get("validations", hres),
        }
    return {
        "result": "saved",
        "domain_uuid": domain_uuid,
        "subdomain_uuid": sub_uuid,
        "handler_uuid": hres.get("uuid"),
        "next": "call opn_reconfigure_caddy to apply",
    }
