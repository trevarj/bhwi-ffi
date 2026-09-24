# PR Description

Write plain, short facts for someone reviewing the diff, normally one screen.

- Lead with `> **Blocked on #N**: reason.` only when blocked; use `Closes #N`
  only when the PR actually closes that issue.
- Use bullets naming the surface and what changed. Group by surface only when it
  helps. No issue restatement, implementation diary or discarded approaches.
- Call out behavior, public FFI API, host lifecycle/threading/errors, generated
  types, package coordinates/ABIs/platform requirements, dependencies or security
  impacts **only when relevant**. Do not fill empty sections with boilerplate.
- Tables are for real contracts, support matrices or measurements, not file lists.
  At most one extra explanatory sentence for a root cause the bullets cannot carry.
- End with an actual `Checks:` line: commands/results and explicit skips/blockers.
  Distinguish APK assembly, emulator startup, instrumentation, consumer replay and
  physical signing when applicable. No unchecked checklist or historical passes.
- Omit unused parts below and replace placeholders; do not add attribution trailers.

```markdown
> **Blocked on #N**: reason.

Closes #N.

- `surface/path`: what it now does
- `surface/path`: another reviewer-relevant change

Behavior changes:
- Relevant API, host, package, dependency or security impact

Checks: `actual command`: passed; `other command`: skipped/blocked: concrete reason.
```

For docs-only work, name the documentation checks actually performed and include:
`Checks: Links, paths and command/source references checked. Skipped code validation because only docs changed.`
Use that wording only if those documentation checks were performed.
