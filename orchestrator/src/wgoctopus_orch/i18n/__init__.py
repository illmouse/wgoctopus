"""UI string catalog: t('key', name=value) looks up the current request language (English only for now)."""
from contextvars import ContextVar

from .en import STRINGS as EN

CATALOGS = {"en": EN}
DEFAULT = "en"
_lang = ContextVar("lang", default=DEFAULT)


def pick_language(cookie=None, accept=None):
    """Language from the `lang` cookie, then Accept-Language, else the default."""
    if cookie in CATALOGS:
        return cookie
    for part in (accept or "").split(","):
        code = part.split(";")[0].strip().lower().split("-")[0]
        if code in CATALOGS:
            return code
    return DEFAULT


def set_language(lang):
    _lang.set(lang if lang in CATALOGS else DEFAULT)


def t(key, **values):
    text = CATALOGS[_lang.get()].get(key) or EN.get(key, key)
    return text.format(**values) if values else text
