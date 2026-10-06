# Custom content

Everything the team writes **from the dashboard** lands here, apart from the shipped content:

| Folder | Written by | Format |
|--------|-----------|--------|
| `custom/rules/<id>.yml` | Rules page → **＋ New rule** (or *Clone as custom* on a shipped rule) | one rule per file, same YAML as `rules/` (see `docs/RULES.md`) |
| `custom/playbooks/<name>.md` | Playbooks page → **＋ New playbook** | Markdown, triage queries in ```` ```kql ```` blocks |

* The shipped rules (`rules/`, 95 rules with scenarios and tests) and playbooks (`playbooks/`) are
  read-only in the UI; a custom rule can never take a shipped id. Use ids like `KB-CUS-001`.
* A rule is validated before it is saved (fields, condition, modifiers, regexes, playbook link) and
  the detection engine reloads at once - no restart.
* The files are plain text: edit them by hand and press **reload from disk** on the Rules page, or
  commit them with the rest of the repository.
* The folder is configured with `custom_dir` in `config/server.yml`.

API: `POST /api/rules`, `PUT|DELETE /api/rules/{id}`, `GET /api/rules/template`,
`POST /api/playbooks`, `PUT|DELETE /api/playbooks/{name}`.
