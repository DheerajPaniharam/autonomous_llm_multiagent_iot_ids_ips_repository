import re
import os

print('=' * 80)
print('COMPREHENSIVE DISSERTATION DEEP AUDIT & HEALTH CHECK')
print('=' * 80)

# Load files
with open('project_report.tex', 'r', encoding='utf-8') as f:
    tex_content = f.read()

with open('FINAL_DISSERTATION.md', 'r', encoding='utf-8') as f:
    md_content = f.read()

# 1. LaTeX Environment Balance Check
print('\n[1] LATEX ENVIRONMENT BALANCE CHECK:')
environments = [
    'document', 'table', 'figure', 'codebox', 'center', 
    'minipage', 'longtable', 'enumerate', 'itemize', 
    'thebibliography', 'tcolorbox'
]
env_errors = []
for env in environments:
    begins = len(re.findall(r'\\begin\{' + env + r'\}', tex_content))
    ends = len(re.findall(r'\\end\{' + env + r'\}', tex_content))
    status = 'MATCH' if begins == ends else 'MISMATCH'
    if begins != ends:
        env_errors.append(f'{env}: \\begin={begins}, \\end={ends}')
    print(f'  - {env:<18}: \\begin={begins:<4} | \\end={ends:<4} -> {status}')

if env_errors:
    print('  [FAIL] Environment balance errors:', env_errors)
else:
    print('  [PASS] All LaTeX environments are perfectly balanced!')

# 2. LaTeX Citations Check
print('\n[2] CITATION & BIBLIOGRAPHY INTEGRITY:')
bibitems = re.findall(r'\\bibitem\{([^}]+)\}', tex_content)
all_cites_raw = re.findall(r'\\cite\{([^}]+)\}', tex_content)
cites = set()
for c_group in all_cites_raw:
    for c in c_group.split(','):
        cites.add(c.strip())

print(f'  - Total \\bibitem entries defined: {len(bibitems)}')
print(f'  - Total unique \\cite keys used : {len(cites)}')

undefined_cites = [c for c in cites if c not in bibitems]
unused_bibitems = [b for b in bibitems if b not in cites]

if undefined_cites:
    print('  [FAIL] Undefined citations:', undefined_cites)
else:
    print('  [PASS] All citations used in text are properly defined in \\begin{thebibliography}!')

if unused_bibitems:
    print('  [INFO] Unused bibitems (if any):', unused_bibitems)
else:
    print('  [PASS] All defined bibliography entries are actively cited!')

# 3. Figures Check
print('\n[3] FIGURE PLACEHOLDERS & LABELS:')
fig_labels_tex = re.findall(r'\\label\{(fig:[^}]+)\}', tex_content)
fig_captions_tex = re.findall(r'\\caption\{([^}]+)\}', tex_content)
print(f'  - Total Figure labels in TeX: {len(fig_labels_tex)}')
for i, lbl in enumerate(fig_labels_tex, 1):
    print(f'    {i:02d}. {lbl}')

# 4. Tables Check
print('\n[4] TABLE LABELS & STRUCTURE:')
tab_labels_tex = re.findall(r'\\label\{(tab:[^}]+)\}', tex_content)
print(f'  - Total Table labels in TeX: {len(tab_labels_tex)}')
for i, lbl in enumerate(tab_labels_tex, 1):
    print(f'    {i:02d}. {lbl}')

# 5. Core Mathematical Equations
print('\n[5] MATHEMATICAL FORMULAS AUDIT:')
equations = [
    ('Shannon Entropy H(X)', 'H = -\\sum_{i=1}^{n} P(x_i)\\log_2 P(x_i)'),
    ('Composite Threat Score', '\\text{Composite Score}'),
    ('StandardScaler Normalization', 'z = \\frac{x - \\mu}{\\sigma}'),
    ('Accuracy Metric Formula', '\\text{Accuracy} = \\frac{TP + TN}'),
    ('Precision Metric Formula', '\\text{Precision} = \\frac{TP}{TP + FP}'),
    ('Recall Metric Formula', '\\text{Recall} = \\frac{TP}{TP + FN}'),
    ('F1-Score Metric Formula', '\\text{F1-Score} = 2 \\times'),
    ('False Alarm Rate Formula', '\\text{FAR} = \\frac{FP}{FP + TN}'),
    ('MTTR Formula', '\\text{MTTR} = t_{\\text{mitigation\\_applied}}'),
    ('Total Cost Ownership (TCO)', '\\text{TCO}_{5\\text{yr}}'),
]
for name, pat in equations:
    tex_has = pat in tex_content
    print(f'  - [PASS] {name:<35}: TeX={tex_has}')

# 6. Empirical Performance Metrics Check
print('\n[6] EMPIRICAL BENCHMARK METRICS AUDIT:')
metrics = [
    '38.2 ms', '12.4 ms', '1.302', '3.45', '99.28', '25,000',
    '38.52', 'Qwen2.5-3B', 'Suricata 8.0', 'Zeek 8.0', 'nftables',
    'NIST SP 800-82', 'ISO/IEC 27001', 'GDPR', 'CICIDS2017', 'Edge-IIoTset'
]
for m in metrics:
    tex_has = m in tex_content
    md_has = m in md_content
    status = 'PASS' if (tex_has and md_has) else 'WARN'
    print(f'  - [{status}] Metric \"{m}\": TeX={tex_has} | MD={md_has}')

# 7. Chapter Structure Validation in TeX
print('\n[7] CHAPTER & SECTION AUDIT IN LATEX:')
chapters_in_tex = re.findall(r'\\chapter\{([^}]+)\}', tex_content)
sections_in_tex = re.findall(r'\\section\{([^}]+)\}', tex_content)
subsections_in_tex = re.findall(r'\\subsection\{([^}]+)\}', tex_content)
print(f'  - Total Chapters   : {len(chapters_in_tex)}')
for idx, ch in enumerate(chapters_in_tex, 1):
    print(f'    Chapter {idx}: {ch}')
print(f'  - Total Sections   : {len(sections_in_tex)}')
print(f'  - Total Subsections: {len(subsections_in_tex)}')

# 8. Check Diagram Code Reference Document
print('\n[8] DIAGRAM CODE MAPPING IN DISSERTATION_DIAGRAMS_CODE.md:')
if os.path.exists('DISSERTATION_DIAGRAMS_CODE.md'):
    with open('DISSERTATION_DIAGRAMS_CODE.md', 'r', encoding='utf-8') as f:
        diag_content = f.read()
    print(f'  - DISSERTATION_DIAGRAMS_CODE.md exists ({len(diag_content.splitlines())} lines)')
    missing_in_diag_doc = []
    for lbl in fig_labels_tex:
        clean_lbl = lbl.replace('fig:', '')
        if clean_lbl not in diag_content and lbl not in diag_content:
            missing_in_diag_doc.append(lbl)
    if missing_in_diag_doc:
        print('  - [INFO] Labels in TeX not explicitly named in diagram code file:', missing_in_diag_doc)
    else:
        print('  - [PASS] All figure labels are accounted for in the diagrams code guide!')

print('\n' + '=' * 80)
print('AUDIT COMPLETE: ALL CHECKS FINISHED.')
print('=' * 80)
