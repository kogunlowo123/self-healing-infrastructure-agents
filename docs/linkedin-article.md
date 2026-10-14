# Self-healing infrastructure that asks before it acts

At 3 a.m. the fix is usually known: undo the release, add replicas, cordon the node. What takes time is waking a person to type it. What takes courage is letting software type it.

**The problem.** Teams want agents that remediate, but a wrong terraform apply or a scale-to-zero turns an incident into an outage. Change windows, approvals and audit still apply.

**Why it matters.** Most pages repeat known failure modes. The gap is safe automation with evidence a change board and an auditor accept.

**Architecture.** Telemetry (Alertmanager, signed CloudWatch alarms via SNS) → Terraform Analysis (destroys, stateful resources, disabled safety settings, blast radius) → Policy Validation (ABAC rules, change windows, approvals) → Remediation (restart, scale, rollout undo, cordon, apply of the reviewed plan) → Rollback (snapshot restore, or a non-destructive last-known-good plan). Around it: identity-fabric authorization, MCP tools and an A2A card for other agents, a signed audit chain, Prometheus and OpenTelemetry.

**How we built it.** Versioned playbooks diagnose from read-only cluster evidence. Approvals bind to a plan digest, re-checked before apply. Dry run is the default and uses server-side dry runs.

**Practices.** Security: verify every notification, scope every caller. Governance: invariants in code that a policy edit cannot remove. Observability: alert on failed rollbacks. Reliability: missing evidence means escalate, never guess.

**Tradeoffs.** Approvals add latency. Post-checks add minutes. Rollback plans cannot always be automatic. Compliance needs human gates. Using Terraform and the Kubernetes API directly limits vendor lock-in but adds code to own.

**Value.** Faster mitigation for repeat incidents and change records that write themselves.

**What next.** Agents will act on infrastructure; the debate is how much autonomy we grant.

Where would you draw the line: should an agent ever apply a production Terraform change with one human approval, or always two?

Code: https://github.com/kogunlowo123/self-healing-infrastructure-agents

#AI #ArtificialIntelligence #GenerativeAI #AgenticAI #LLMOps #EnterpriseAI #AISecurity #RAG #MachineLearning #DataScience #CloudComputing #Kubernetes #MLOps #DigitalTransformation #Innovation #SRE #Terraform #SelfHealing #PlatformEngineering
