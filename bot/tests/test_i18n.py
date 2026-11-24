import pytest

from wgoctopus_bot.i18n import EN, RU, lang_from_code, placeholders, t


def test_catalogs_match_and_language_normalization():
    assert EN.keys() == RU.keys()
    assert placeholders(EN) == placeholders(RU)
    assert lang_from_code(None) == "en"
    assert lang_from_code("RU") == "ru"
    assert lang_from_code("ru-RU") == "ru"
    assert lang_from_code("fr") == "en"


def test_unknown_translation_key_raises():
    with pytest.raises(KeyError):
        t("en", "missing")
