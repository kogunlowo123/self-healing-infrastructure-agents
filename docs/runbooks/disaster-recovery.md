# Disaster recovery

| Component | Recovery |
|---|---|
| PostgreSQL | Managed backups with point-in-time recovery (14-day retention in the Terraform modules); restore to a new instance and update the database URL secret |
| Audit chains | WORM object storage copies; per-pod volumes are re-created empty and new chains start from genesis with the same key ID |
| Audit signing key | Secret manager; rotating it changes the key ID recorded in new events, old chains verify with the old public key |
| Terraform stacks volume | Rebuilt by the delivery pipeline |
| Configuration | Helm values in version control; policies and playbooks in the image |

## Procedure

1. Put the service in dry-run mode while recovering.
2. Restore the database; verify `/readyz`.
3. Review plans that were `approved` or `executing` at the time of the
   failure; re-validate them before any live execution (policy is
   re-evaluated on execution regardless).
4. Verify the latest audit chains from WORM storage.
5. Return to live mode through the normal change process.

The service holds no state outside the database, the audit chains and the
stacks volume, so recovery does not require replaying alerts; active alerts
re-fire from their sources.
