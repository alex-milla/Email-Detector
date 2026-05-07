from extract_features import (
    extract_urls,
    detect_urgency_keywords,
    get_attachment_risk,
    count_special_chars,
    check_mismatched_urls,
)


class TestURLExtraction:
    def test_extract_urls_from_text(self):
        text = "Visita https://example.com y http://test.org para más info"
        urls = extract_urls(text)
        assert "https://example.com" in urls
        assert "http://test.org" in urls

    def test_extract_urls_no_urls(self):
        assert extract_urls("Esto es un texto sin URLs") == []

    def test_extract_urls_empty(self):
        assert extract_urls("") == []


class TestUrgencyKeywords:
    def test_detect_spanish_urgency(self):
        text = "URGENTE: acción requerida, su cuenta será suspendida"
        assert detect_urgency_keywords(text) >= 3

    def test_detect_english_urgency(self):
        text = "URGENT: action required, your account will be suspended"
        assert detect_urgency_keywords(text) >= 3

    def test_no_urgency(self):
        text = "Hola, ¿cómo estás? Espero que tengas un buen día"
        assert detect_urgency_keywords(text) == 0

    def test_empty_text(self):
        assert detect_urgency_keywords("") == 0


class TestAttachmentRisk:
    def test_exe_is_high_risk(self):
        assert get_attachment_risk("virus.exe") == 10

    def test_jpg_is_low_risk(self):
        assert get_attachment_risk("foto.jpg") == 1

    def test_unknown_extension_is_default(self):
        assert get_attachment_risk("archivo.xyz") == 2

    def test_case_insensitive(self):
        assert get_attachment_risk("malware.EXE") == 10


class TestSpecialChars:
    def test_special_chars_counted(self):
        assert count_special_chars("¡Hola! ¿Cómo estás?") == 3

    def test_no_special_chars(self):
        assert count_special_chars("Hola como estas") == 0

    def test_empty_text(self):
        assert count_special_chars("") == 0


class TestMismatchedUrls:
    def test_no_mismatch(self):
        html = '<a href="https://example.com">https://example.com</a>'
        assert check_mismatched_urls(html) == 0

    def test_mismatch_detected(self):
        html = '<a href="http://evil.tk/verify">http://banco.com/verificar</a>'
        assert check_mismatched_urls(html) == 1

    def test_empty_html(self):
        assert check_mismatched_urls("") == 0
