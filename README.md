<p align="center">
  <img src="images/Screenshot 2026-06-22 231428.png" width="200" alt="TripleS Logo">
</p>

<h1 align="center">🛡️ SIEM-Rules - TripleS</h1>

<p align="center">
  <em>Mərkəzləşdirilmiş SIEM mühitləri üçün təhlükəsizlik qaydalarının (rules) və konfiqurasiyaların idarə edilməsi.</em>
</p>

---


## 📂 Qovluq Strukturu

Repomuz fərqli SIEM sistemləri üzrə səliqəli şəkildə bölünmüşdür:

```text
SIEM-Rules/   # API skriptləri, avtomatlaşdırma və ya log göndərmə vasitələri
└── SPLUNK_RULES/
    ├── rules/       # Splunk üçün SPL axtarışları, Saved Searches və ya Detection Rules
    └── scripts/     # Splunk üçün HEC skriptləri, Inputs və ya Təhlil alətləri
