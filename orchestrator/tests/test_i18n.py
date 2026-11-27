import re
from pathlib import Path

from wgoctopus_orch import i18n
from wgoctopus_orch.i18n import EN, pick_language, set_language, t

SRC = Path(i18n.__file__).parent.parent
KEY = re.compile(r"""\bt\(\s*["']([a-z0-9_]+\.[a-z0-9_.]+)["']""")


def test_pick_language():
    assert pick_language("en") == "en"
    assert pick_language("xx", "de-DE,en;q=0.8") == "en"
    assert pick_language(None, None) == "en"


def test_t_format_and_missing():
    set_language("en")
    EN["test.hello"] = "Hello {name}"
    try:
        assert t("test.hello", name="Bob") == "Hello Bob"
    finally:
        del EN["test.hello"]
    assert t("no.such_key") == "no.such_key"


def test_all_used_keys_exist():
    files = [*(SRC / "templates").glob("*.html"), SRC / "webui.py", SRC / "api.py"]
    used = {(f.name, k) for f in files for k in KEY.findall(f.read_text())}
    missing = sorted(f"{f}: {k}" for f, k in used if k not in EN)
    assert not missing, missing
