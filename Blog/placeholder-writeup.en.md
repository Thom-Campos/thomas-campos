# [PLACEHOLDER] Next CTF Writeup

> ⚠️ **This is a sample file.** Replace this content with your real writeup and update the metadata in `Blog/index.json`.

---

## Bilingual blog system

Each blog entry can have **two Markdown files**:

| File | Language | Required? |
|---|---|---|
| `Blog/{id}.md` | Spanish | ✅ Yes |
| `Blog/{id}.en.md` | English | ⬜ Optional |

If the visitor has **English** selected and `Blog/{id}.en.md` exists, it will load. If it doesn't exist, the Spanish `.md` is used as an automatic fallback.

### How to add a new entry

**1.** Create `Blog/my-new-post.md` with the content in Spanish.

**2.** (Optional) Create `Blog/my-new-post.en.md` with the English version.

**3.** Add the object to the array in `Blog/index.json`:

```json
{
  "id":          "my-new-post",
  "cat":         "ctf",
  "dateDisplay": "May 2026",
  "icon":        "emoji_events",
  "titleEs":     "Título en español",
  "titleEn":     "Title in English",
  "excerptEs":   "Resumen corto (español).",
  "excerptEn":   "Short summary (English).",
  "cardTags":    [{ "text": "CTF", "cls": "tag-osint" }],
  "articleDate": "May 2026",
  "articleTags": [{ "text": "CTF", "cls": "tag-osint" }],
  "placeholder": false
}
```

**4.** Done! The card appears automatically.

---

## Example writeup structure

## Context

Brief description of the CTF or event.

## Challenge: Challenge Name

Description of the problem.

### Solution

```bash
$ nmap -sV -p 22,80,443 10.0.0.1
```

### Flag obtained

```
FLAG{example_flag}
```

## Key takeaways

- Key point 1
- Key point 2
