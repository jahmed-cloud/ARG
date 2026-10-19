"""
Download one release of Microsoft's Azure Landing Zones library (github.com/Azure/Azure-Landing-Zones-Library, MIT)
into scripts/subscription_analysis/alz_library - the reference the landing-zone view compares the tenant with.

    python -m scripts.update_alz_library                  # the release pinned below
    python -m scripts.update_alz_library platform/alz/2027.01.0

Only the ALZ reference is kept: management-group architecture, archetypes, policy assignments, policy and initiative
definitions, plus the library's LICENSE. Review the diff before committing a new release.
"""

import json
import pathlib
import shutil
import sys
import urllib.parse
import urllib.request

REPO = "Azure/Azure-Landing-Zones-Library"
RELEASE = "platform/alz/2026.10.0"
FOLDERS = ("architecture_definitions", "archetype_definitions", "policy_assignments", "policy_definitions",
           "policy_set_definitions")
TARGET = pathlib.Path(__file__).resolve().parent / "subscription_analysis" / "alz_library"


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "azure-resource-guardian-alz-library"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def download(release: str = RELEASE, target: pathlib.Path = TARGET) -> int:
    raw = f"https://raw.githubusercontent.com/{REPO}/{release}/"
    files = ["LICENSE", "platform/alz/alz_library_metadata.json", "platform/alz/alz_policy_default_values.json"]
    for folder in FOLDERS:
        listing = json.loads(_get(f"https://api.github.com/repos/{REPO}/contents/platform/alz/{folder}"
                                  f"?ref={urllib.parse.quote(release, safe='')}"))
        files += [i["path"] for i in listing if i["type"] == "file" and i["name"].endswith(".json")]
    staging = target.with_name(target.name + ".new")
    shutil.rmtree(staging, ignore_errors=True)
    for path in files:
        data = _get(raw + path)
        if path.endswith(".json"):
            json.loads(data)   # refuse a broken download
        out = staging / path.replace("platform/alz/", "")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    (staging / "SOURCE.md").write_text(
        f"# Azure Landing Zones library\n\nSource: https://github.com/{REPO} (MIT License, see LICENSE), release "
        f"`{release}`.\nDownloaded by `python -m scripts.update_alz_library`; files are unchanged. ARG reads them "
        f"to compare the tenant with the ALZ reference.\n", encoding="utf-8")
    shutil.rmtree(target, ignore_errors=True)
    staging.rename(target)
    return len(files)


if __name__ == "__main__":
    count = download(sys.argv[1] if len(sys.argv) > 1 else RELEASE)
    print(f"{count} files from {REPO}@{sys.argv[1] if len(sys.argv) > 1 else RELEASE} -> {TARGET}")
