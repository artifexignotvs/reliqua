# Using runtime evidence during PHP2Shell response

This workflow supports an administrator's remediation review. It does not apply
patches, deploy network controls or investigate compromise automatically.

1. Establish the PHP services, workers, containers, origins and backend replicas
   you actually operate. Include dependencies embedded in other products.
2. Follow your distribution or product vendor's current update instructions.
   Upstream fixed releases for this incident are 8.2.35, 8.3.36, 8.4.27 and 8.5.12;
   distribution backports use different complete package versions. Verify those
   against the vendor advisory. [PHP](https://www.php.net/archive/2026.php),
   [Ubuntu](https://ubuntu.com/security/notices/USN-8948-1).
3. If patching cannot happen promptly, evaluate exposure isolation with the service
   owner. Configuration workarounds are partial; do not convert them into a
   remediation claim. [CERT-EU](https://cert.europa.eu/publications/security-advisories/2026-018/).
4. Capture a private `before` snapshot when doing so will not delay remediation.
   Update and drain/restart services through your existing operational procedure.
   RELIQUA deliberately has no automatic restart or configuration editing mode.
5. Recollect inside each relevant namespace and inspect the result. A deleted or
   replaced executable/module needs restart or rollout review. A package-file
   mismatch needs investigation. Unsupported builds need vendor-specific evidence.
6. Run the declared-node gate with one fresh report per alias. Fix missing inventory,
   clock problems and collection gaps. Keep the distinction between observed
   process correspondence and successful request-route/service checks.
7. Separately assess possible earlier compromise. Updating now cannot establish
   that no attacker acted before the update. AWS reported pre-disclosure attempts
   from October 17; use incident response evidence appropriate to your environment.
   [AWS threat intelligence](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/).

## Finding reference

| Finding | Next review |
|---|---|
| `RESTART_REVIEW` | Check old masters/workers, drain procedure and mapped modules; recollect after completion. |
| `PACKAGE_FILE_CHANGED` | Check local modifications, package provenance and incident-response evidence. |
| `FIX_UNVERIFIED` | Read the vendor notice and bundled policy; unfamiliar does not necessarily mean vulnerable. |
| `COLLECTION_GAP` / `PROCESS_GAP` | Review permissions, visibility, namespaces and process churn. |
| `CLI_NOT_WEB_EVIDENCE` | Determine whether CLI-named PHP serves HTTP or long-lived work; its role is unresolved. |
| `NO_WEB_RUNTIME` | Reconcile inventory, stopped services, container scope and discovery naming. |

Raw reports belong in restricted operational storage, outside a public repository.
The fleet summary removes runtime paths and process/boot IDs but retains aliases.
Review even a summary before external publication.
