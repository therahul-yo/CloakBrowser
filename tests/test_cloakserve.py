"""Unit tests for cloakserve — parse_connection_params, parse_cli_args, URL rewriting, connection tracking."""

import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

aiohttp = pytest.importorskip("aiohttp", reason="cloakserve requires aiohttp (install with .[serve])")
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# Load cloakserve as a module from bin/ (no .py extension).
_bin_path = str(Path(__file__).resolve().parents[1] / "bin" / "cloakserve")
_loader = importlib.machinery.SourceFileLoader("cloakserve", _bin_path)
_spec = importlib.util.spec_from_file_location("cloakserve", _bin_path, loader=_loader)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["cloakserve"] = _mod
_loader.exec_module(_mod)

parse_connection_params = _mod.parse_connection_params
parse_cli_args = _mod.parse_cli_args
ChromePool = _mod.ChromePool
_default_data_dir = _mod._default_data_dir
SAFE_SEED_RE = _mod.SAFE_SEED_RE
RESERVED_SEEDS = _mod.RESERVED_SEEDS
auth_middleware = _mod.auth_middleware


# ---------------------------------------------------------------------------
# parse_connection_params
# ---------------------------------------------------------------------------


class TestParseConnectionParams:
    def test_empty_query(self):
        result = parse_connection_params("")
        assert result["seed"] is None
        assert result["extra_args"] == []

    def test_fingerprint_seed(self):
        result = parse_connection_params("fingerprint=12345")
        assert result["seed"] == "12345"

    def test_timezone_and_locale(self):
        result = parse_connection_params("fingerprint=1&timezone=Asia/Tokyo&locale=ja-JP")
        assert result["timezone"] == "Asia/Tokyo"
        assert result["locale"] == "ja-JP"

    def test_proxy(self):
        result = parse_connection_params("proxy=http://proxy:8080")
        assert result["proxy"] == "http://proxy:8080"

    def test_geoip_true_variants(self):
        for val in ("true", "1", "yes", "True", "YES"):
            result = parse_connection_params(f"geoip={val}")
            assert result["geoip"] is True, f"geoip={val} should be True"

    def test_geoip_false(self):
        for val in ("false", "0", "no", "anything"):
            result = parse_connection_params(f"geoip={val}")
            assert result["geoip"] is False, f"geoip={val} should be False"

    def test_generic_fingerprint_params(self):
        qs = "fingerprint=1&platform=windows&hardware-concurrency=8&gpu-vendor=NVIDIA"
        result = parse_connection_params(qs)
        assert "--fingerprint-platform=windows" in result["extra_args"]
        assert "--fingerprint-hardware-concurrency=8" in result["extra_args"]
        assert "--fingerprint-gpu-vendor=NVIDIA" in result["extra_args"]

    def test_special_params_not_in_extra_args(self):
        qs = "fingerprint=1&timezone=UTC&locale=en-US&proxy=http://x:1&geoip=true"
        result = parse_connection_params(qs)
        assert result["extra_args"] == []

    def test_multiple_values_takes_first(self):
        result = parse_connection_params("fingerprint=111&fingerprint=222")
        assert result["seed"] == "111"

    def test_token_param_not_forwarded_to_chrome(self):
        """Auth token (?token=) must not leak into Chrome args as --fingerprint-token."""
        result = parse_connection_params("fingerprint=1&token=s3cret")
        assert result["seed"] == "1"
        assert result["extra_args"] == []
        # Defensive: nothing in extra_args should reference the secret
        assert not any("s3cret" in arg for arg in result["extra_args"])
        assert not any(arg.startswith("--fingerprint-token") for arg in result["extra_args"])

    def test_token_param_alone(self):
        result = parse_connection_params("token=s3cret")
        assert result["extra_args"] == []
        assert result["seed"] is None

    def test_token_does_not_displace_other_generic_params(self):
        qs = "fingerprint=1&token=s3cret&platform=windows&hardware-concurrency=8"
        result = parse_connection_params(qs)
        assert "--fingerprint-platform=windows" in result["extra_args"]
        assert "--fingerprint-hardware-concurrency=8" in result["extra_args"]
        assert not any("token" in arg for arg in result["extra_args"])


# ---------------------------------------------------------------------------
# parse_cli_args
# ---------------------------------------------------------------------------


class TestParseCliArgs:
    def test_defaults(self):
        config, passthrough = parse_cli_args([])
        assert config["port"] == 9222
        assert config["headless"] is True
        assert config["data_dir"] is not None
        assert passthrough == []

    def test_custom_port(self):
        config, _ = parse_cli_args(["--port=8080"])
        assert config["port"] == 8080

    def test_headless_false(self):
        config, passthrough = parse_cli_args(["--headless=false"])
        assert config["headless"] is False
        # headless flag still passed through to Chrome
        assert "--headless=false" in passthrough

    def test_strips_remote_debugging_flags(self):
        args = ["--remote-debugging-port=9999", "--remote-debugging-address=0.0.0.0", "--no-sandbox"]
        config, passthrough = parse_cli_args(args)
        assert passthrough == ["--no-sandbox"]

    def test_passthrough_args(self):
        args = ["--no-sandbox", "--disable-gpu", "--fingerprint=999"]
        config, passthrough = parse_cli_args(args)
        # --fingerprint=999 is consumed into config["default_seed"], not passed through
        assert passthrough == ["--no-sandbox", "--disable-gpu"]
        assert config["default_seed"] == "999"

    def test_port_not_in_passthrough(self):
        _, passthrough = parse_cli_args(["--port=9222", "--no-sandbox"])
        assert "--port=9222" not in passthrough
        assert "--no-sandbox" in passthrough

    def test_custom_data_dir(self):
        config, passthrough = parse_cli_args(["--data-dir=/custom/path", "--no-sandbox"])
        assert config["data_dir"] == "/custom/path"
        assert "--data-dir=/custom/path" not in passthrough

    def test_data_dir_not_in_passthrough(self):
        _, passthrough = parse_cli_args(["--data-dir=/tmp/test"])
        assert not any(a.startswith("--data-dir=") for a in passthrough)

    @patch("os.path.exists", return_value=True)
    def test_default_data_dir_docker(self, _mock):
        assert _default_data_dir() == "/tmp/cloakserve"

    @patch("os.path.exists", return_value=False)
    def test_default_data_dir_bare_metal(self, _mock):
        result = _default_data_dir()
        assert result.endswith(".cloakbrowser/cloakserve")

    def test_auth_token_arg(self):
        config, passthrough = parse_cli_args(["--auth-token=s3cret"])
        assert config["auth_token"] == "s3cret"
        assert not any(a.startswith("--auth-token") for a in passthrough)

    def test_auth_token_default_none(self):
        config, _ = parse_cli_args([])
        assert config["auth_token"] is None

    def test_host_arg(self):
        config, passthrough = parse_cli_args(["--host=0.0.0.0"])
        assert config["host"] == "0.0.0.0"
        assert not any(a.startswith("--host=") for a in passthrough)

    def test_host_default_none(self):
        config, _ = parse_cli_args([])
        assert config["host"] is None


# ---------------------------------------------------------------------------
# URL rewriting logic (pure string manipulation, extracted from handlers)
# ---------------------------------------------------------------------------


class TestURLRewriting:
    """Test the URL rewriting logic used by /json/version and /json/list."""

    def _rewrite_version(self, orig_ws: str, host: str, seed: str | None, scheme: str = "ws") -> str:
        """Replicate the URL rewrite logic from handle_json_version."""
        if seed:
            ws_path = f"fingerprint/{seed}/devtools/browser"
        else:
            ws_path = "devtools/browser"
        guid = orig_ws.rsplit("/", 1)[-1] if "/devtools/" in orig_ws else ""
        return f"{scheme}://{host}/{ws_path}/{guid}"

    def _rewrite_list_entry(self, orig_ws: str, host: str, seed: str | None, scheme: str = "ws") -> str:
        """Replicate the URL rewrite logic from handle_json_list."""
        ws_tail = orig_ws.split("/devtools/")[-1]
        if seed:
            return f"{scheme}://{host}/fingerprint/{seed}/devtools/{ws_tail}"
        else:
            return f"{scheme}://{host}/devtools/{ws_tail}"

    def test_version_rewrite_with_seed(self):
        orig = "ws://127.0.0.1:5100/devtools/browser/abc-123"
        result = self._rewrite_version(orig, "container:9222", "12345")
        assert result == "ws://container:9222/fingerprint/12345/devtools/browser/abc-123"

    def test_version_rewrite_no_seed(self):
        orig = "ws://127.0.0.1:5100/devtools/browser/abc-123"
        result = self._rewrite_version(orig, "container:9222", None)
        assert result == "ws://container:9222/devtools/browser/abc-123"

    def test_list_rewrite_page_with_seed(self):
        orig = "ws://127.0.0.1:5100/devtools/page/DEF-456"
        result = self._rewrite_list_entry(orig, "host:9222", "99")
        assert result == "ws://host:9222/fingerprint/99/devtools/page/DEF-456"

    def test_list_rewrite_page_no_seed(self):
        orig = "ws://127.0.0.1:5100/devtools/page/DEF-456"
        result = self._rewrite_list_entry(orig, "host:9222", None)
        assert result == "ws://host:9222/devtools/page/DEF-456"

    def test_list_rewrite_browser(self):
        orig = "ws://127.0.0.1:5100/devtools/browser/XYZ"
        result = self._rewrite_list_entry(orig, "host:9222", "seed1")
        assert result == "ws://host:9222/fingerprint/seed1/devtools/browser/XYZ"

    def test_wss_scheme_version(self):
        orig = "ws://127.0.0.1:5100/devtools/browser/abc-123"
        result = self._rewrite_version(orig, "host:443", "seed1", scheme="wss")
        assert result == "wss://host:443/fingerprint/seed1/devtools/browser/abc-123"

    def test_wss_scheme_list(self):
        orig = "ws://127.0.0.1:5100/devtools/page/DEF-456"
        result = self._rewrite_list_entry(orig, "host:443", "seed1", scheme="wss")
        assert result == "wss://host:443/fingerprint/seed1/devtools/page/DEF-456"


# ---------------------------------------------------------------------------
# Connection refcounting
# ---------------------------------------------------------------------------


class TestConnectionTracking:
    """Test ChromePool.connect() / disconnect() without real Chrome."""

    def _make_pool(self):
        return ChromePool(
            binary="/fake/chrome",
            global_args=[],
            headless=True,
            data_dir="/tmp/test-cloakserve",
        )

    def test_connect_increments(self):
        pool = self._make_pool()
        pool.connect("seed1")
        assert pool._connections["seed1"] == 1
        pool.connect("seed1")
        assert pool._connections["seed1"] == 2

    def test_disconnect_decrements(self):
        pool = self._make_pool()
        pool.connect("seed1")
        pool.connect("seed1")
        pool.disconnect("seed1")
        assert pool._connections["seed1"] == 1

    def test_disconnect_to_zero_removes_key(self):
        pool = self._make_pool()
        pool.connect("seed1")
        pool.disconnect("seed1")
        assert "seed1" not in pool._connections

    def test_disconnect_below_zero_safe(self):
        pool = self._make_pool()
        pool.disconnect("nonexistent")
        assert "nonexistent" not in pool._connections

    def test_multiple_seeds_independent(self):
        pool = self._make_pool()
        pool.connect("a")
        pool.connect("b")
        pool.connect("a")
        pool.disconnect("a")
        assert pool._connections["a"] == 1
        assert pool._connections["b"] == 1


# ---------------------------------------------------------------------------
# Seed validation (CVE fix — path traversal via fingerprint param)
# ---------------------------------------------------------------------------


class TestSeedValidation:
    """Verify SAFE_SEED_RE rejects path traversal and reserved names."""

    @pytest.mark.parametrize("seed", [
        "../foo", "../../etc", "/etc/passwd", "..", ".", "foo/bar",
        "foo\\bar", "\x00evil", "", "a" * 129,
    ])
    def test_malicious_seeds_rejected(self, seed):
        assert not SAFE_SEED_RE.match(seed)

    @pytest.mark.parametrize("seed", [
        "__default__",
    ])
    def test_reserved_seeds_rejected(self, seed):
        assert seed in RESERVED_SEEDS

    @pytest.mark.parametrize("seed", [
        "12345", "my-seed_01", "ABC", "a" * 128, "0", "test-seed",
    ])
    def test_valid_seeds_accepted(self, seed):
        assert SAFE_SEED_RE.match(seed)
        assert seed not in RESERVED_SEEDS


# ---------------------------------------------------------------------------
# Path containment (_safe_rmtree)
# ---------------------------------------------------------------------------


class TestSafeRmtree:
    """Verify _safe_rmtree refuses to delete outside data_dir."""

    def _make_pool(self, data_dir: str):
        return ChromePool(
            binary="/fake/chrome",
            global_args=[],
            headless=True,
            data_dir=data_dir,
        )

    def test_refuses_path_outside_data_dir(self, tmp_path):
        data_dir = tmp_path / "profiles"
        data_dir.mkdir()
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "sentinel").touch()

        pool = self._make_pool(str(data_dir))
        pool._safe_rmtree(str(victim))

        assert victim.exists(), "Directory outside data_dir must not be deleted"

    def test_refuses_data_dir_itself(self, tmp_path):
        data_dir = tmp_path / "profiles"
        data_dir.mkdir()
        (data_dir / "sentinel").touch()

        pool = self._make_pool(str(data_dir))
        pool._safe_rmtree(str(data_dir))

        assert data_dir.exists(), "data_dir itself must not be deleted"

    def test_deletes_valid_subdirectory(self, tmp_path):
        data_dir = tmp_path / "profiles"
        data_dir.mkdir()
        subdir = data_dir / "seed-12345"
        subdir.mkdir()
        (subdir / "data").touch()

        pool = self._make_pool(str(data_dir))
        pool._safe_rmtree(str(subdir))

        assert not subdir.exists(), "Valid subdirectory should be deleted"

    def test_refuses_traversal_path(self, tmp_path):
        data_dir = tmp_path / "profiles"
        data_dir.mkdir()
        victim = tmp_path / "victim"
        victim.mkdir()

        traversal = str(data_dir / ".." / "victim")
        pool = self._make_pool(str(data_dir))
        pool._safe_rmtree(traversal)

        assert victim.exists(), "Traversal path must not be deleted"


# ---------------------------------------------------------------------------
# Auth middleware end-to-end
# ---------------------------------------------------------------------------


def _make_auth_app(token: str | None):
    """Build an aiohttp app with auth_middleware and a handler that exposes
    what parse_connection_params() would forward to Chrome."""
    middlewares = [auth_middleware] if token else []
    app = web.Application(middlewares=middlewares)
    if token:
        app["auth_token"] = token

    async def handler(request: web.Request) -> web.Response:
        parsed = parse_connection_params(request.query_string)
        return web.json_response({
            "ok": True,
            "extra_args": parsed["extra_args"],
            "seed": parsed["seed"],
        })

    app.router.add_get("/json/version", handler)
    return app


class TestAuthMiddleware:
    """End-to-end auth flow: gate routes behind a token without leaking it to Chrome."""

    async def test_no_token_configured_allows_all(self):
        app = _make_auth_app(token=None)
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/json/version")
            assert resp.status == 200

    async def test_missing_token_rejected(self):
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/json/version")
            assert resp.status == 401
            assert resp.headers.get("WWW-Authenticate") == "Bearer"

    async def test_wrong_token_rejected(self):
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            resp = await client.get(
                "/json/version",
                headers={"Authorization": "Bearer wrong"},
            )
            assert resp.status == 401

    async def test_wrong_query_token_rejected(self):
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            resp = await client.get("/json/version?token=wrong")
            assert resp.status == 401

    async def test_bearer_header_accepted(self):
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            resp = await client.get(
                "/json/version?fingerprint=42",
                headers={"Authorization": "Bearer s3cret"},
            )
            assert resp.status == 200
            body = await resp.json()
            assert body["seed"] == "42"
            assert body["extra_args"] == []

    async def test_query_token_accepted_and_not_forwarded(self):
        """Critical: when client auths via ?token=, the token must NOT be
        forwarded to Chrome as --fingerprint-token=<secret>."""
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            resp = await client.get(
                "/json/version?fingerprint=42&token=s3cret&platform=windows"
            )
            assert resp.status == 200
            body = await resp.json()
            assert body["seed"] == "42"
            # platform passes through (legitimate fingerprint param)
            assert "--fingerprint-platform=windows" in body["extra_args"]
            # token must NOT leak through as --fingerprint-token=s3cret
            assert not any("token" in arg for arg in body["extra_args"])
            assert not any("s3cret" in arg for arg in body["extra_args"])

    async def test_malformed_authorization_header_falls_through_to_query(self):
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            # No "Bearer " prefix → ignored, query token used instead
            resp = await client.get(
                "/json/version?token=s3cret",
                headers={"Authorization": "s3cret"},
            )
            assert resp.status == 200

    async def test_empty_token_rejected(self):
        app = _make_auth_app(token="s3cret")
        async with TestClient(TestServer(app)) as client:
            resp = await client.get(
                "/json/version",
                headers={"Authorization": "Bearer "},
            )
            assert resp.status == 401
