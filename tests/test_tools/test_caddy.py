"""Tests for Caddy (os-caddy) tools."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from opnsense_mcp.api_client import ENDPOINT_REGISTRY, WriteDisabledError
from opnsense_mcp.tools.caddy import (
    opn_caddy_add,
    opn_caddy_add_service,
    opn_caddy_caddyfile,
    opn_caddy_delete,
    opn_caddy_general,
    opn_caddy_get,
    opn_caddy_search,
    opn_caddy_set_general,
    opn_caddy_status,
    opn_caddy_toggle,
    opn_caddy_update,
    opn_reconfigure_caddy,
)

_KINDS = [
    ("domains", "reverse_proxy", "reverse"),
    ("subdomains", "subdomain", "subdomain"),
    ("handlers", "handle", "handle"),
    ("access_lists", "access_list", "accesslist"),
    ("layer4", "layer4", "layer4"),
]

_GENERAL = {
    "caddy": {
        "general": {
            "enabled": "1",
            "EnableLayer4": "1",
            "HttpPort": "9080",
            "HttpsPort": "9443",
            "TlsEmail": "ops@example.com",
            "TlsDnsApiKey": "CANARY-dns-api-key",
            "DisableSuperuser": [{"value": "No", "selected": 0}, {"value": "Yes", "selected": 1}],
            "TlsDnsProvider": {"cloudflare": {"value": "Cloudflare", "selected": 1}},
        }
    }
}


# --- R1 / R10: service ---------------------------------------------------------


class TestStatus:
    async def test_calls_status(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value={"status": "running"})
        result = await opn_caddy_status(mock_ctx)
        mock_api.get.assert_called_once_with("caddy.service.status")
        assert result == {"status": "running"}

    def test_static_endpoints_registered(self):
        assert ENDPOINT_REGISTRY["caddy.service.status"][1] == "caddy/service/status"
        assert ENDPOINT_REGISTRY["caddy.service.reconfigure"][1] == "caddy/service/reconfigure"
        assert ENDPOINT_REGISTRY["caddy.general.get"][1] == "caddy/general/get"
        assert ENDPOINT_REGISTRY["caddy.general.set"][1] == "caddy/general/set"
        assert ENDPOINT_REGISTRY["caddy.diagnostics.caddyfile"][1] == "caddy/diagnostics/caddyfile"


class TestReconfigure:
    async def test_posts_empty_json_body(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"status": "ok"})
        result = await opn_reconfigure_caddy(mock_ctx_writes)
        mock_api_writes.post.assert_called_once_with("caddy.service.reconfigure", {})
        assert result == {"status": "ok", "service": "caddy"}

    async def test_requires_writes(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock()
        with pytest.raises(WriteDisabledError):
            await opn_reconfigure_caddy(mock_ctx)
        mock_api.post.assert_not_called()


# --- R2 / R6: general settings ---------------------------------------------------


class TestGeneral:
    async def test_returns_only_allowlisted_flattened_fields(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(return_value=_GENERAL)
        result = await opn_caddy_general(mock_ctx)
        mock_api.get.assert_called_once_with("caddy.general.get")
        assert result == {
            "enabled": "1",
            "EnableLayer4": "1",
            "HttpPort": "9080",
            "HttpsPort": "9443",
            "DisableSuperuser": "1",
        }
        assert "CANARY" not in json.dumps(result)

    async def test_dict_option_field_is_flattened(self, mock_api, mock_ctx):
        data = json.loads(json.dumps(_GENERAL))
        data["caddy"]["general"]["DisableSuperuser"] = {
            "0": {"value": "No", "selected": 1},
            "1": {"value": "Yes", "selected": 0},
        }
        mock_api.get = AsyncMock(return_value=data)
        result = await opn_caddy_general(mock_ctx)
        assert result["DisableSuperuser"] == "0"


# --- R3 / R14: search -------------------------------------------------------------


class TestSearch:
    @pytest.mark.parametrize(("rtype", "kind", "_body"), _KINDS)
    async def test_search_each_kind(self, mock_api, mock_ctx, rtype, kind, _body):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        result = await opn_caddy_search(mock_ctx, resource_type=rtype, search="nas", limit=10)
        logical = f"caddy.reverse_proxy.search_{kind}"
        mock_api.post.assert_called_once_with(logical, {"current": 1, "rowCount": 10, "searchPhrase": "nas"})
        assert ENDPOINT_REGISTRY[logical][1] == f"caddy/reverse_proxy/search_{kind}"
        assert result == {"rows": [], "rowCount": 0}

    async def test_limit_capped(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock(return_value={"rows": [], "rowCount": 0})
        await opn_caddy_search(mock_ctx, resource_type="handlers", limit=10_000)
        assert mock_api.post.call_args.args[1]["rowCount"] == 500

    async def test_rows_are_redacted(self, mock_api, mock_ctx):
        rows = [{"uuid": "u1", "FromDomain": "a.example.com", "StaticKey": "CANARY-static"}]
        mock_api.post = AsyncMock(return_value={"rows": rows, "rowCount": 1})
        result = await opn_caddy_search(mock_ctx, resource_type="layer4")
        assert result["rows"][0]["StaticKey"] == "[REDACTED]"
        assert result["rows"][0]["FromDomain"] == "a.example.com"

    async def test_invalid_type(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock()
        result = await opn_caddy_search(mock_ctx, resource_type="headers")
        assert "error" in result
        assert "domains" in result["error"]
        mock_api.post.assert_not_called()


# --- R4 / R6: get -------------------------------------------------------------------


class TestGet:
    @pytest.mark.parametrize(("rtype", "kind", "_body"), _KINDS)
    async def test_get_each_kind(self, mock_api, mock_ctx, rtype, kind, _body):
        mock_api.get = AsyncMock(return_value={"x": {}})
        await opn_caddy_get(mock_ctx, resource_type=rtype, uuid="abc-123")
        logical = f"caddy.reverse_proxy.get_{kind}"
        mock_api.get.assert_called_once_with(logical, path_suffix="abc-123")
        assert ENDPOINT_REGISTRY[logical][1] == f"caddy/reverse_proxy/get_{kind}"

    async def test_nested_secrets_redacted(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock(
            return_value={
                "reverse": {
                    "FromDomain": "*.example.com",
                    "TlsDnsApiKey": "CANARY-nested-key",
                    "LogCredentials": "0",
                    "inner": [{"basicauthpass": "CANARY-pass"}],
                }
            }
        )
        result = await opn_caddy_get(mock_ctx, resource_type="domains", uuid="u1")
        assert "CANARY" not in json.dumps(result)
        assert result["reverse"]["FromDomain"] == "*.example.com"
        assert result["reverse"]["LogCredentials"] == "0"

    async def test_invalid_type(self, mock_api, mock_ctx):
        mock_api.get = AsyncMock()
        result = await opn_caddy_get(mock_ctx, resource_type="basic_auth", uuid="u1")
        assert "error" in result
        mock_api.get.assert_not_called()


# --- R5 / R7: Caddyfile ----------------------------------------------------------------


class TestCaddyfile:
    async def test_returns_redacted_content(self, mock_api, mock_ctx):
        content = (
            "{\n\thttp_port 9080\n\tacme_dns cloudflare CANARY-dns-api-key\n}\n"
            "basic_auth {\n\tbob $2a$14$" + "A" * 53 + "\n}\n"
            "-----BEGIN OpenVPN Static key V1-----\nCANARY-hex\n"
            "-----END OpenVPN Static key V1-----\n"
            "nas.example.com {\n\treverse_proxy 10.0.0.5:5000\n}\n"
        )

        async def fake_get(endpoint, **_kw):
            if endpoint == "caddy.diagnostics.caddyfile":
                return {"status": "success", "content": content}
            return _GENERAL

        mock_api.get = AsyncMock(side_effect=fake_get)
        result = await opn_caddy_caddyfile(mock_ctx)
        text = result["content"]
        assert "CANARY" not in text
        assert "$2a$14$" not in text
        assert "http_port 9080" in text
        assert "reverse_proxy 10.0.0.5:5000" in text
        assert text.count("[REDACTED]") >= 3
        assert result["status"] == "success"


# --- R8 / R12 / R13: CRUD -----------------------------------------------------------------


class TestAdd:
    @pytest.mark.parametrize(("rtype", "kind", "body"), _KINDS)
    async def test_add_each_kind(self, mock_api_writes, mock_ctx_writes, rtype, kind, body):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved", "uuid": "new"})
        result = await opn_caddy_add(mock_ctx_writes, resource_type=rtype, config={"description": "x"})
        logical = f"caddy.reverse_proxy.add_{kind}"
        mock_api_writes.post.assert_called_once_with(logical, {body: {"description": "x"}})
        assert ENDPOINT_REGISTRY[logical][1] == f"caddy/reverse_proxy/add_{kind}"
        assert result["uuid"] == "new"

    async def test_requires_writes(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock()
        with pytest.raises(WriteDisabledError):
            await opn_caddy_add(mock_ctx, resource_type="domains", config={"FromDomain": "x"})
        mock_api.post.assert_not_called()

    async def test_empty_config_rejected(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock()
        result = await opn_caddy_add(mock_ctx_writes, resource_type="domains", config={})
        assert "error" in result
        mock_api_writes.post.assert_not_called()

    async def test_invalid_type(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock()
        result = await opn_caddy_add(mock_ctx_writes, resource_type="nope", config={"a": "1"})
        assert "error" in result
        mock_api_writes.post.assert_not_called()


class TestUpdate:
    async def test_update_handler(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_caddy_update(mock_ctx_writes, resource_type="handlers", uuid="h1", config={"ToPort": "8080"})
        mock_api_writes.post.assert_called_once_with(
            "caddy.reverse_proxy.set_handle", {"handle": {"ToPort": "8080"}}, path_suffix="h1"
        )

    async def test_requires_writes(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_caddy_update(mock_ctx, resource_type="handlers", uuid="h1", config={"a": "1"})


class TestDelete:
    async def test_delete_posts_empty_body(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "deleted"})
        await opn_caddy_delete(mock_ctx_writes, resource_type="subdomains", uuid="s1")
        mock_api_writes.post.assert_called_once_with("caddy.reverse_proxy.del_subdomain", {}, path_suffix="s1")

    async def test_requires_writes(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_caddy_delete(mock_ctx, resource_type="subdomains", uuid="s1")


class TestToggle:
    async def test_toggle_without_value(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "Enabled", "changed": True})
        await opn_caddy_toggle(mock_ctx_writes, resource_type="layer4", uuid="l1")
        mock_api_writes.post.assert_called_once_with("caddy.reverse_proxy.toggle_layer4", {}, path_suffix="l1")

    async def test_requires_writes(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_caddy_toggle(mock_ctx, resource_type="layer4", uuid="l1")


# --- R9: set general ----------------------------------------------------------------------


class TestSetGeneral:
    async def test_sets_general(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock(return_value={"result": "saved"})
        await opn_caddy_set_general(mock_ctx_writes, config={"HttpPort": "80", "HttpsPort": "443"})
        mock_api_writes.post.assert_called_once_with(
            "caddy.general.set", {"caddy": {"general": {"HttpPort": "80", "HttpsPort": "443"}}}
        )

    async def test_refuses_sensitive_key(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock()
        result = await opn_caddy_set_general(mock_ctx_writes, config={"TlsDnsApiKey": "x"})
        assert "error" in result
        mock_api_writes.post.assert_not_called()

    async def test_requires_writes(self, mock_api, mock_ctx):
        with pytest.raises(WriteDisabledError):
            await opn_caddy_set_general(mock_ctx, config={"HttpPort": "80"})


# --- R11: add service ------------------------------------------------------------------------


_DOMAINS = {"rows": [{"uuid": "dom-1", "FromDomain": "*.example.com", "FromPort": ""}], "rowCount": 1}
_ACLS = {"rows": [{"uuid": "acl-1", "accesslistName": "internal"}], "rowCount": 1}


def _service_api(api, *, handler_result=None):
    calls: list[tuple] = []

    async def fake_post(endpoint, data=None, *, path_suffix=""):
        calls.append((endpoint, data, path_suffix))
        if endpoint == "caddy.reverse_proxy.search_reverse_proxy":
            return _DOMAINS
        if endpoint == "caddy.reverse_proxy.search_access_list":
            return _ACLS
        if endpoint == "caddy.reverse_proxy.add_subdomain":
            return {"result": "saved", "uuid": "sub-1"}
        if endpoint == "caddy.reverse_proxy.add_handle":
            return handler_result or {"result": "saved", "uuid": "h-1"}
        if endpoint == "caddy.reverse_proxy.del_subdomain":
            return {"result": "deleted"}
        raise AssertionError(endpoint)

    api.post = AsyncMock(side_effect=fake_post)
    return calls


class TestAddService:
    async def test_creates_subdomain_and_catch_all_handler(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)
        result = await opn_caddy_add_service(
            mock_ctx_writes,
            fqdn="app.example.com",
            to_host="10.0.0.5",
            to_port=8080,
            tls="https",
            insecure_skip_verify=True,
            access_list="internal",
            description="#30 app",
        )
        sub = next(c for c in calls if c[0] == "caddy.reverse_proxy.add_subdomain")
        assert sub[1] == {
            "subdomain": {
                "enabled": "1",
                "reverse": "dom-1",
                "FromDomain": "app.example.com",
                "accesslist": "acl-1",
                "description": "#30 app",
            }
        }
        handle = next(c for c in calls if c[0] == "caddy.reverse_proxy.add_handle")
        assert handle[1] == {
            "handle": {
                "enabled": "1",
                "reverse": "dom-1",
                "subdomain": "sub-1",
                "HandleType": "handle",
                "HandlePath": "",
                "HandleDirective": "reverse_proxy",
                "ToDomain": "10.0.0.5",
                "ToPort": "8080",
                "HttpTls": "1",
                "HttpTlsInsecureSkipVerify": "1",
                "description": "#30 app",
            }
        }
        assert result["subdomain_uuid"] == "sub-1"
        assert result["handler_uuid"] == "h-1"
        assert result["domain_uuid"] == "dom-1"
        assert not any(c[0] == "caddy.service.reconfigure" for c in calls)

    async def test_defaults_http_no_acl(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)
        await opn_caddy_add_service(mock_ctx_writes, fqdn="b.example.com", to_host="h", to_port=80)
        sub = next(c for c in calls if c[0] == "caddy.reverse_proxy.add_subdomain")
        assert sub[1]["subdomain"]["accesslist"] == ""
        handle = next(c for c in calls if c[0] == "caddy.reverse_proxy.add_handle")
        assert handle[1]["handle"]["HttpTls"] == "0"
        assert "HttpTlsInsecureSkipVerify" not in handle[1]["handle"]
        assert not any(c[0] == "caddy.reverse_proxy.search_access_list" for c in calls)

    async def test_h2c(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)
        await opn_caddy_add_service(mock_ctx_writes, fqdn="c.example.com", to_host="h", to_port=1, tls="h2c")
        handle = next(c for c in calls if c[0] == "caddy.reverse_proxy.add_handle")
        assert handle[1]["handle"]["HttpTls"] == "2"

    async def test_explicit_domain_and_acl_uuid(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)
        uuid_d = "11111111-2222-3333-4444-555555555555"
        uuid_a = "66666666-7777-8888-9999-000000000000"
        await opn_caddy_add_service(
            mock_ctx_writes, fqdn="d.other.org", to_host="h", to_port=1, domain=uuid_d, access_list=uuid_a
        )
        sub = next(c for c in calls if c[0] == "caddy.reverse_proxy.add_subdomain")
        assert sub[1]["subdomain"]["reverse"] == uuid_d
        assert sub[1]["subdomain"]["accesslist"] == uuid_a
        assert not any(c[0].startswith("caddy.reverse_proxy.search_") for c in calls)

    async def test_unknown_domain(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)
        result = await opn_caddy_add_service(mock_ctx_writes, fqdn="x.nowhere.net", to_host="h", to_port=1)
        assert "error" in result
        assert not any("add_" in c[0] for c in calls)

    async def test_unknown_access_list(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)
        result = await opn_caddy_add_service(
            mock_ctx_writes, fqdn="x.example.com", to_host="h", to_port=1, access_list="nope"
        )
        assert "error" in result
        assert not any("add_" in c[0] for c in calls)

    async def test_invalid_tls(self, mock_api_writes, mock_ctx_writes):
        mock_api_writes.post = AsyncMock()
        result = await opn_caddy_add_service(mock_ctx_writes, fqdn="x.example.com", to_host="h", to_port=1, tls="ftp")
        assert "error" in result
        mock_api_writes.post.assert_not_called()

    async def test_rolls_back_subdomain_when_handler_fails(self, mock_api_writes, mock_ctx_writes):
        failed = {"result": "failed", "validations": {"handle.ToPort": "bad"}}
        calls = _service_api(mock_api_writes, handler_result=failed)
        result = await opn_caddy_add_service(mock_ctx_writes, fqdn="e.example.com", to_host="h", to_port=1)
        assert ("caddy.reverse_proxy.del_subdomain", {}, "sub-1") in calls
        assert "error" in result
        assert result["validations"] == {"handle.ToPort": "bad"}

    async def test_subdomain_failure_stops(self, mock_api_writes, mock_ctx_writes):
        calls = _service_api(mock_api_writes)

        orig = mock_api_writes.post.side_effect

        async def fail_sub(endpoint, data=None, *, path_suffix=""):
            if endpoint == "caddy.reverse_proxy.add_subdomain":
                calls.append((endpoint, data, path_suffix))
                return {"result": "failed", "validations": {"subdomain.FromDomain": "dup"}}
            return await orig(endpoint, data, path_suffix=path_suffix)

        mock_api_writes.post = AsyncMock(side_effect=fail_sub)
        result = await opn_caddy_add_service(mock_ctx_writes, fqdn="f.example.com", to_host="h", to_port=1)
        assert "error" in result
        assert not any(c[0] == "caddy.reverse_proxy.add_handle" for c in calls)

    async def test_requires_writes(self, mock_api, mock_ctx):
        mock_api.post = AsyncMock()
        with pytest.raises(WriteDisabledError):
            await opn_caddy_add_service(mock_ctx, fqdn="a.example.com", to_host="h", to_port=1)
        mock_api.post.assert_not_called()
