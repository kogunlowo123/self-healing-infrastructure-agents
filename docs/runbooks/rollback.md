# Rolling back the service

```bash
helm history heal -n self-healing
helm rollback heal <revision> -n self-healing
```

- The database schema is created idempotently and versioned in
  `schema_version`; 0.1.0 has schema version 1, so rollback within 0.1.x
  needs no data migration.
- Plans in `executing` when a pod restarts remain in that state; check them
  with `GET /v1/remediations?status=executing` and resolve them following
  [remediation-failure.md](remediation-failure.md).
- Images are pinned by digest in production values; roll back to the
  previous digest recorded in the release notes.
- Policy and playbook files ship in the image; a policy regression is
  rolled back the same way.
