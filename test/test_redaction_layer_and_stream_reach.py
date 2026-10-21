"""Redaction reads every decoded layer, holds a catalog match through its filler,
keeps numeric passwords behind a label, and leaves ports, paths and quoted PEM
markers alone."""

from __future__ import annotations

import json

import pytest

from kiro_crew.apps.builtins.design_tweak.backend import preview_files, server
from kiro_crew.log_redaction import SecretRedactionFilter
from kiro_crew.security.redaction import redact_credentials
from kiro_crew.security.text_redaction import StreamRedactor


def _redact(text: str) -> str:
    return redact_credentials(text)[0]


def _stream(text: str, size: int) -> str:
    redactor = StreamRedactor()
    out = "".join(redactor.feed(text[i : i + size]) for i in range(0, len(text), size))
    return out + redactor.flush()


# ── A run of digits behind a secret label is the secret ──


@pytest.mark.parametrize("quoted", [True, False])
def test_a_numeric_password_behind_its_label_is_redacted(quoted: bool) -> None:
    password = "834729105623"  # 12 digits: the shape of an account ID
    text = json.dumps({"password": password}) if quoted else f"password={password}"

    assert password not in _redact(text)
    assert password not in SecretRedactionFilter([]).redact(text)


def test_an_account_id_behind_its_own_label_stays() -> None:
    text = '{"account_id": "123456789012"}'

    assert _redact(text) == text


# ── Every decoded layer is read ──


def test_a_double_encoded_password_with_a_quote_is_redacted_whole() -> None:
    password = 'Xq7"m2pzR9tvB8nc1kd6wf'
    text = json.dumps(json.dumps({"password": password}))

    out = _redact(text)

    assert "Xq7" not in out
    assert "m2pzR9tvB8nc1kd6wf" not in out
    # One value, one tag, and the stream agrees with the batch.
    assert out.count("[REDACTED") == 1
    assert _stream(text, 1) == out
    assert _stream(text, 16) == out


def test_a_triple_encoded_password_with_a_quote_is_redacted_whole() -> None:
    password = 'Xq7"m2pzR9tvB8nc1kd6wf'
    out = _redact(json.dumps(json.dumps(json.dumps({"password": password}))))

    assert "Xq7" not in out
    assert "m2pzR9tvB8nc1kd6wf" not in out


# ── The stream holds a catalog match through the rule's filler ──

#: A made-up UUID, kept apart from its keyword so no literal reads as a key.
_UUID = "12345678-1234-1234-1234-" "123456789abc"

_CATALOG_LINES = [
    f"Your heroku key = {_UUID} ok\n",
    "adafruit key = xq7lm2pz9rt4vb8nc1kd6wf3hj5gs0ty ok\n",
    # The rules' filler is up to 20 characters: " production api key ".
    f"heroku production api key = {_UUID} ok\n",
]


@pytest.mark.parametrize("text", _CATALOG_LINES)
@pytest.mark.parametrize("size", [1, 16])
def test_the_stream_redacts_a_catalog_secret_behind_filler_like_the_batch(
    text: str, size: int
) -> None:
    batch = _redact(text)
    assert "[REDACTED" in batch

    assert _stream(text, size) == batch


# ── A port and a path are not a password ──


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:5173/@vite/client",
        "https://registry.npmjs.org:443/@types/node",
    ],
)
def test_a_url_with_a_port_and_an_at_in_its_path_is_left_intact(url: str) -> None:
    assert _redact(url) == url


@pytest.mark.parametrize(
    ("url", "password", "host"),
    [
        ("postgres://app:ab/cdEF12xy@db.internal:5432/x", "ab/cdEF12xy", "@db.internal:5432/x"),
        # Digit-led passwords: the host after ``@`` is dotted or has a port.
        (
            "postgres://app:2024/SecretPw99xy@db.internal:5432/x",
            "2024/SecretPw99xy",
            "@db.internal",
        ),
        ("redis://default:007/xK9mQ2pL7vR4@cache.example.com:6379", "007/xK9mQ2pL7vR4", "@cache."),
        ("mysql://root:443/pa55wordQQ@db:3306/x", "443/pa55wordQQ", "@db:3306/x"),
    ],
)
def test_a_uri_password_holding_a_slash_is_still_redacted(
    url: str, password: str, host: str
) -> None:
    out = _redact(url)

    assert password not in out
    assert host in out
    assert _stream(url, 1) == out


# ── The preview's PEM marker exemption holds in a decoded view too ──


def test_an_escaped_pem_marker_without_a_body_is_served() -> None:
    data = b'const k = "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----\\n";'

    assert preview_files.contains_credential(server, data) is False


def test_a_double_escaped_pem_marker_without_a_body_is_served() -> None:
    marker = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"
    data = json.dumps(json.dumps(marker)).encode()

    assert preview_files.contains_credential(server, data) is False


def test_an_escaped_pem_block_with_a_body_is_refused() -> None:
    body = "MIIEowIBAAKCAQEA" + "q7Lm2Pz9Rt4Vb8Nc1Kd6Wf3Hj5Gs0Ty" * 3
    data = (
        f'const k = "-----BEGIN RSA PRIVATE KEY-----\\n{body}\\n'
        f'-----END RSA PRIVATE KEY-----\\n";'
    ).encode()

    assert preview_files.contains_credential(server, data) is True
