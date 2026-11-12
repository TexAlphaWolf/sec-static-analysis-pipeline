"""The documentation says what the measured JSON files say: every Markdown report is rebuilt from its JSON, the demo report is
regenerated, and the numbers in the README and docs/analysis.md are formatted from the JSON here."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from pescan import analysis, report
from pescan import corpus as C
from pescan import scan as S

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
README = (ROOT / "README.md").read_text(encoding="utf-8")
ANALYSIS = (DOCS / "analysis.md").read_text(encoding="utf-8")
LIMITS = (DOCS / "limitations.md").read_text(encoding="utf-8")
DEMO = json.loads((DOCS / "report.json").read_text(encoding="utf-8"))
REAL = json.loads((DOCS / "real.json").read_text(encoding="utf-8"))
BENCH = json.loads((DOCS / "bench.json").read_text(encoding="utf-8"))
VOLATILE = ("elapsed_s", "speed")


def flat(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("**", "").replace("`", ""))


def has(text: str, *needles: str) -> None:
    body = flat(text)
    for n in needles:
        assert flat(n) in body, n


def test_markdown_is_rebuilt_from_the_json() -> None:
    assert (DOCS / "report.md").read_text(encoding="utf-8") == report.render_report(DEMO)
    assert (DOCS / "real.md").read_text(encoding="utf-8") == report.render_report(REAL)
    assert (DOCS / "bench.md").read_text(encoding="utf-8") == report.render_bench(BENCH)
    for png in ("report.png", "real.png", "bench.png"):
        assert (DOCS / png).read_bytes()[:4] == b"\x89PNG"


def test_the_demo_report_is_regenerated(tmp_path: Path) -> None:
    C.write_corpus(tmp_path / "demo", 300, 1, damaged=1)
    recs, sec = S.scan(list(S.walk([tmp_path / "demo"])), S.Options(now=C.NOW, reference=True))
    truth = json.loads((tmp_path / "demo" / "truth.json").read_text(encoding="utf-8"))["files"]
    rep = analysis.build(recs, DEMO["source"], C.NOW, sec, DEMO["options"], truth)
    rep = json.loads(json.dumps(rep))
    assert {k: v for k, v in rep.items() if k not in VOLATILE} == {k: v for k, v in DEMO.items() if k not in VOLATILE}


def test_readme_demo_block() -> None:
    block = README.split("```text\n", 1)[1].split("```", 1)[0].strip().splitlines()
    assert block == analysis.summary_lines(DEMO)
    y, ref = DEMO["yara"], DEMO["reference"]
    has(
        README,
        f"The {DEMO['files']['pe'] - y['same_traits']} YARA disagreements and the {ref['compared'] - ref['identical']} pefile "
        f"differences are all on damaged copies",
    )


def pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%"


def test_the_real_folder_in_the_text() -> None:
    f, p, t, y, ref, ts = REAL["files"], REAL["pe"], REAL["traits"], REAL["yara"], REAL["reference"], REAL["timestamps"]
    n = f["pe"]
    assert (f["total"], n, f["not_pe"], f["malformed"], f["unreadable"]) == (4716, 4405, 311, 0, 0)
    assert ref["identical"] == ref["compared"] == n and ref["refused"] == 0 and y["same_traits"] == y["files"] == n
    per = REAL["indicators_per_file"]
    decades = dict(map(tuple, ts["decades"]))
    after_if_uniform = 1 - REAL["now"] / 2**32
    claims = [
        f"the {f['total']:,} files directly in C:\\Windows\\System32 of a Windows 11 computer",
        f"pefile reads all {n:,} PE files the same as pescan's parser",
        f"the checksum on the {ref['checksum_compared']:,} files up to 4 MiB",
        f"{y['same_traits']:,} of {y['files']:,}. {f['not_pe']} files are not programs",
        f"{pct(t['debugger_check'], n)} of the files import IsDebuggerPresent ({t['debugger_check']:,})",
        f"{pct(t['future_timestamp'], n)} have a link time stamp later than the day of the scan ({t['future_timestamp']:,})",
        f"{pct(t['tls'], n)} have a TLS directory ({t['tls']:,})",
        f"{sum(per[3:])} system files have three indicators or more, none has five",
        f"from the 1970s ({decades[1970]}) to the 2100s ({decades[2100]}), with no decade above {max(decades.values())}",
        f"{100 * after_if_uniform:.1f}% would fall after the scan; {pct(ts['after_now'], n)} do",
        f"{REAL['entropy']['executable_high']} of {REAL['entropy']['executable_sections']:,} executable sections",
        f"The {t['injection_imports']} files that import VirtualAllocEx",
        f"The {t['few_imports']} programs with fewer than 4 imports",
        f"{pct(t['no_embedded_signature'], n)} ({t['no_embedded_signature']:,}) carry no Authenticode signature",
        f"The header checksum is right on {p['checksum_right']:,} files and zero on {p['checksum_zero']}",
        f"{pct(t['no_aslr'], n)} lack ASLR ({t['no_aslr']} files), {pct(t['no_dep'], n)} DEP ({t['no_dep']})",
        f"{pct(t['no_cfg'], n)} Control Flow Guard ({t['no_cfg']})",
        f"took {REAL['elapsed_s']:.0f} s with {REAL['options']['workers']} processes",
    ]
    has(README, *claims)
    for name in ("ClipUp.exe", "GenValObj.exe", "SppExtComObj.Exe", "sppsvc.exe", "d3dcsx_42.dll", "WMVDECOD.DLL"):
        assert name in REAL["examples"]["high_entropy_code"] and name in README
    for name in ("dbgeng.dll", "Faultrep.dll", "kernel32.dll", "ttdinject.exe"):
        assert name in REAL["examples"]["injection_imports"] and name in README
    assert per == [690, 1569, 1500, 642, 4, 0] and t["checksum_mismatch"] == 0
    has(
        ANALYSIS,
        f"{f['total']:,} files, {f['bytes'] / 1e6:,.1f} MB, read in {REAL['elapsed_s']:.0f} s "
        f"({REAL['speed']['files_per_s']:.1f} files and {REAL['speed']['mb_per_s']:.1f} MB a second",
        f"{n:,} are PE files ({f['pe_bytes'] / 1e6:,.1f} MB)",
        f"{p['bits_64']:,} are 64-bit and {n - p['bits_64']} are 32-bit; {p['dll']:,} are DLLs; {p['dotnet']} are .NET",
        "One YARA scan was reported as timed out",
        f"{decades[1970]} in the 1970s, {decades[1980]} in the 1980s, {decades[2020]} in the 2020s (the most), {decades[2100]} in the 2100s",
        f"{per[0]} with none, {per[1]:,} with one, {per[2]:,} with two, {per[3]} with three and {per[4]} with four",
        f"{REAL['imphash']['distinct']:,} distinct import hashes among {n:,} files, the largest group of {REAL['imphash']['largest_groups'][0][1]}",
        f"{REAL['strings']['files_with_urls']:,} files contain a URL, most often www.microsoft.com ({REAL['strings']['top_hosts'][0][1]:,} files)",
        f"crl.microsoft.com ({REAL['strings']['top_hosts'][1][1]:,})",
        f"{t['no_high_entropy_va']} 64-bit files ({pct(t['no_high_entropy_va'], n)}) high-entropy ASLR",
        "3,584 files have one",
    )
    assert y["retried"] == 1 and dict(map(tuple, REAL["top_section_names"]))["fothk"] == 3584
    ex = REAL["entropy"]["executable"]
    has(ANALYSIS, f"mostly between 5.5 and 6.5 bits a byte ({ex[11] + ex[12]:,}), and {ex[0]:,} are below 0.5")


def test_the_published_copy_is_generic() -> None:
    assert REAL["source"] == "C:\\Windows\\System32 (Windows 11)" and "published" in REAL
    assert all(REAL["traits"][k] <= 50 for k in REAL["examples"])
    text = json.dumps(REAL)
    assert (
        "Home" not in text
        and "build 26200" not in text
        and "nv" not in " ".join(n for names in REAL["examples"].values() for n in names)
    )


def step(files: int, name: str) -> dict[str, Any]:
    return next(r for r in BENCH["steps"] if r["files"] == files and r["step"] == name)


def test_the_benchmark_in_the_text() -> None:
    env, w, pairs, v = BENCH["environment"], BENCH["workers"], BENCH["pairs"], BENCH["verification"]
    parse, pef = step(1000, "parse"), step(1000, "pefile (reference)")
    traits, yr, hashes = step(1000, "traits, strings, entropy"), step(1000, "YARA rules"), step(1000, "hashes")
    mbs = {r["step"]: r["mb"] / r["seconds"] for r in BENCH["steps"] if r["files"] == 1000}
    rate = [x["files"] / x["seconds"] for x in w]
    d, st = v["details"], v["details"]["damaged_stats"]
    assert v["ok"] and BENCH["yara_retries"] == [] and [x["workers"] for x in w] == [1, 2, 4, 8]
    has(
        README,
        f"{env['system']}, {env['cpus']} CPUs, Python {env['python']}, medians of {env['repeat']} runs",
        f"On 1,000 generated files ({parse['mb']:.1f} MB) pescan parses {mbs['parse']:.1f} MB a second and pefile "
        f"{mbs['pefile (reference)']:.1f} MB a second ({parse['seconds'] * 1000:.1f} ms against {pef['seconds']:.2f} s)",
        f"the slowest own step ({mbs['traits, strings, entropy']:.1f} MB a second)",
        f"YARA rules run at {mbs['YARA rules']:.1f} MB a second",
        f"from {rate[0]:,.0f} files a second with 1 process to {rate[-1]:,.0f} with 8",
        f"On {d['files']:,} generated files with {d['traits_set']:,} traits set",
        f"On {d['damaged']:,} damaged copies the parser refuses {st['own_refused']} with its own error",
        f"they agree on {st['both_identical']:,} of {st['both_read']:,}, and YARA and Python agree on {st['yara_same']:,} of {st['yara_compared']:,}",
    )
    has(
        ANALYSIS,
        f"| parse (pescan) | {report.duration(parse['seconds'])} | {mbs['parse']:.1f} |",
        f"| hashes (MD5, SHA-1, SHA-256) | {report.duration(hashes['seconds'])} | {mbs['hashes']:.1f} |",
        f"| traits, strings, entropy | {report.duration(traits['seconds'])} | {mbs['traits, strings, entropy']:.1f} |",
        f"| YARA rules | {report.duration(yr['seconds'])} | {mbs['YARA rules']:.1f} |",
        f"| pefile (reference) | {report.duration(pef['seconds'])} | {mbs['pefile (reference)']:.1f} |",
        f"pescan's parser is {pef['seconds'] / parse['seconds']:.0f} times faster than pefile",
        f"takes {report.duration(w[0]['seconds'])} with 1 process, {report.duration(w[1]['seconds'])} with 2, "
        f"{report.duration(w[2]['seconds'])} with 4 and {report.duration(w[3]['seconds'])} with 8",
        ", ".join(f"{r:,.0f}" for r in rate[:3]) + f" and {rate[3]:,.0f} files a second",
        f"{report.duration(pairs[0]['fast_s'])} against {report.duration(pairs[0]['literal_s'])} one byte value at a time "
        f"({pairs[0]['literal_s'] / pairs[0]['fast_s']:.0f} times)",
        f"{report.duration(pairs[1]['fast_s'])} against {report.duration(pairs[1]['literal_s'])} one word at a time "
        f"({pairs[1]['literal_s'] / pairs[1]['fast_s']:.0f} times)",
        f"{d['sections']:,} sections have the same entropy both ways within {d['entropy_max_diff']:.1e} bits",
        f"the parser refuses {st['own_refused']} with its own error and never fails in another way; pefile refuses {st['ref_refused']}",
        f"Both read {st['both_read']:,} and agree on every field of {st['both_identical']:,}; the {st['both_read'] - st['both_identical']} others "
        f"differ in imports ({d['damaged_field_differences']['imports']})",
        f"the largest difference is writable_code ({d['damaged_yara_differences']['writable_code']})",
    )
    has(
        LIMITS,
        f"({st['yara_same']:,} of {st['yara_compared']:,} damaged copies",
        f"({st['both_read'] - st['both_identical']} of {st['both_read']:,} differ)",
    )


def test_the_demo_in_the_analysis() -> None:
    f, t = DEMO["files"], DEMO["traits"]
    ind = {k: t[k] for k in DEMO["groups"]["indicators"]}
    low = min(ind, key=lambda k: ind[k])
    high = max(ind, key=lambda k: ind[k])
    has(
        ANALYSIS,
        f"{f['total']} files, {f['pe']} PE, {f['not_pe']} not PE",
        f"and {f['malformed']} malformed",
        f"YARA agrees with Python on {DEMO['yara']['same_traits']} of the {f['pe']} PE files and pefile reads {DEMO['reference']['identical']} the same",
        f"from {ind[low]} files with {low} to {ind[high]} with {high}",
        f"with {sum(DEMO['indicators_per_file'][3:])} files having three indicators or more",
    )
    assert DEMO["accuracy"]["exact_python"] == DEMO["accuracy"]["exact_yara"] == DEMO["accuracy"]["files"] == 300


@pytest.mark.parametrize(
    "doc", ["README.md", "docs/method.md", "docs/analysis.md", "docs/limitations.md", "docs/architecture.md"]
)
def test_links_point_to_files(doc: str) -> None:
    text = (ROOT / doc).read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#]+?)\)", text):
        if target.startswith("http"):
            continue
        assert (ROOT / doc).parent.joinpath(target).resolve().exists(), (doc, target)
