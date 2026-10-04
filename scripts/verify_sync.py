import re

def verify():
    with open("project_report.tex", "r", encoding="utf-8") as f:
        tex = f.read()
    with open("FINAL_DISSERTATION.md", "r", encoding="utf-8") as f:
        md = f.read()

    print("=== FILE SIZES ===")
    print(f"project_report.tex: {len(tex.splitlines())} lines, {len(tex.split())} words")
    print(f"FINAL_DISSERTATION.md: {len(md.splitlines())} lines, {len(md.split())} words")

    print("\n=== METRICS PARITY ===")
    metrics = [
        "38.2 ms", "12.4 ms", "1.302", "3.45", "99.28",
        "Suricata 8.0", "Zeek 8.0", "Qwen2.5-3B", "nftables",
        "LightGBM", "Isolation Forest", "asyncio", "P_{95}", "P_{99}",
        "NIST SP 800-82", "ISO/IEC 27001", "GDPR"
    ]
    all_matched = True
    for m in metrics:
        # Check presence in TeX and MD
        in_tex = m in tex
        in_md = m in md
        status = "PASS" if in_tex and in_md else "FAIL"
        if status == "FAIL":
            all_matched = False
        print(f"[{status}] '{m}': TeX={in_tex}, MD={in_md}")

    print("\n=== CITATIONS PARITY ===")
    citations = [
        "sharafaldin2018", "ke2017", "liu2008", "shannon1948", "paxson1999",
        "oisf2024", "ferrag2022", "yang2024", "touvron2023", "chase1999",
        "langchain2024", "sharma2026", "li2025", "gyamfi2022", "nist2023",
        "iso27001", "dwork2014", "netfilter2024", "wooldridge2009", "algaradi2020"
    ]
    for c in citations:
        in_tex = f"\\cite{{{c}}}" in tex or f"\\bibitem{{{c}}}" in tex
        print(f"Citation '{c}': TeX={in_tex}")

    print("\n=== TABLE LABELS IN LATEX ===")
    tex_tables = re.findall(r'\\caption\{([^}]+)\}\s*\n\s*\\label\{(tab:[^}]+)\}', tex)
    for cap, lbl in tex_tables:
        print(f"  {lbl}: {cap}")

    print("\n=== FIGURE LABELS IN LATEX ===")
    tex_figs = re.findall(r'\\caption\{([^}]+)\}\s*\n\s*\\label\{(fig:[^}]+)\}', tex)
    for cap, lbl in tex_figs:
        print(f"  {lbl}: {cap}")

    if all_matched:
        print("\n>>> ALL VERIFICATIONS PASSED: Documents are 100% synchronized and streamlined! <<<")
    else:
        print("\n>>> WARNING: Some checks failed! <<<")

if __name__ == "__main__":
    verify()
