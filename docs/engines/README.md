# Engine reference

[Read the scanner purpose, SWOT and version guide](../scanner-guide.md) · [Download standard sample reports](../samples/v0.4.0/README.md)

[繁體中文](README.zh-TW.md) · [Documentation](../README.md)

One page per scanner and per shared launcher. Each page records how the product runs that engine, what the adapter keeps from its output, how to update it, and what real runs taught. Read the page before changing an engine, and add a line to its **Lessons from real runs** when a real run teaches something new.

The v0.4.0 stable release integrates 25 runnable engines, including optional ZAP passive website checks, Agentic Radar offline workflow inventory and bounded Garak model checks.

[Engine maintenance procedure](../engine-maintenance.md) is the policy. Start a rebuild or upstream update with the [image build and update notebook](image-build-index.md): it covers all 25 engines, their build contexts, rules/data preparation, coupled edits and known pitfalls, plus the gateway. Each engine page links back to that entry point.

`engines/catalog.json` and each `engines/images/<engine>/plan.json` record exact pins and intended build facts. Compare them with the publication source commit and evidence before saying what a pinned image runs: current source can differ from the published artifact. Historical Semgrep records illustrated this distinction; the current combined pack has a [verified publication record](semgrep-publication-2026-10-03.md). Resolve a disagreement from the actual artifact and acquisition evidence, then correct the affected records and documentation.

## Engines

| Assets | Engines | Entrypoint | Publish workflow |
| --- | --- | --- | --- |
| AWS account; Prowler also an Azure subscription or GCP project | [Prowler](prowler.md), [ScoutSuite](scoutsuite.md), [Cloudsplaining](cloudsplaining.md), [Steampipe](steampipe.md) and [CloudQuery](cloudquery.md) (both inventory) | [Cloud launcher](cloud-launcher.md) | `engine-images-cloud.yml` |
| Microsoft 365 tenant | [ScubaGear](scubagear.md), [Maester](maester.md) | [Microsoft 365 launcher](m365-launcher.md) | `engine-images-m365.yml` |
| Website, domain, IP address | [naabu](naabu.md), [httpx](httpx.md), [Nuclei](nuclei.md) | [External launcher](external-launcher.md) | `engine-images-external.yml` |
| | [ZAP](zap.md) (optional passive website checks) | Upstream image | None |
| Internal host or service | [Greenbone](greenbone.md) | [Greenbone launcher](greenbone-launcher.md) | `engine-image-greenbone.yml` |
| Repository, IaC project, container image | [Semgrep](semgrep.md), [TruffleHog](trufflehog.md), [Trivy](trivy.md), [Grype](grype.md) | [Local launcher](local-launcher.md) | `engine-images-local-k8s.yml` |
| | [Gitleaks](gitleaks.md) | Its own entrypoint | `engine-image-gitleaks.yml` |
| | [Checkov](checkov.md), [Syft](syft.md) | Upstream entrypoint | `engine-image-checkov.yml`, `engine-image-syft.yml` |
| | [KICS](kics.md) | Upstream image | None |
| Kubernetes cluster, Kubernetes node | [Kubescape](kubescape.md), [kube-bench](kube-bench.md) | [Local launcher](local-launcher.md) | `engine-images-local-k8s.yml` |
| MCP configuration in a repository | [MCP Armor](mcp-armor.md) | Its own entrypoint | `engine-image-mcp-armor.yml` |
| Agent repository snapshot | [Agentic Radar](agentic-radar.md) (optional offline inventory) | Dedicated static launcher | `engine-image-agentic-radar.yml` |
| AI model endpoint | [Garak](garak.md) (optional fixed native probes) | Dedicated bounded REST launcher | `engine-image-garak.yml` |

Engines that reach a network target or a provider leave their container only through the [egress gateway](egress-gateway.md).

## What a page holds

- The pins: upstream release and revision, image tag, build inputs, launcher, wrapper, adapter and tests.
- A local-build entry: Dockerfile, actual build context, host preparation, known build limitations and a link to the update notebook.
- How the product invokes it: the fixed profile, what goes in and what comes out.
- What the adapter turns into findings, inventory and warnings, and what it leaves as raw evidence.
- Every product-owned difference from upstream, with its reason and the condition for removing it.
- Lessons from real runs, one line each: date, symptom, cause, fix commit.
- Updating: the files that must move together, and how to compare normalized output with the raw upstream output.

## Shipping an engine image change

Publishing an image is the product owner's decision. Once it is approved:

1. **Fix.** Change the launcher, wrapper, Dockerfile or lock, and run the tests named on the engine's page. A change that alters normalized output for unchanged upstream output also follows the adapter-version rule in [§8 of the maintenance procedure](../engine-maintenance.md#8-shared-adapter-contract-version).
2. **Publish commit.** Give each owner-approved image rebuild a new tag in the workflow matrix and Dockerfile version label. A shared launcher edit updates source records for every consumer; the owner's selected publication scope determines which images are rebuilt. Record any difference between current source and a sibling's historical artifact. Tags are immutable, and the publication guard refuses to reuse one for changed recorded inputs. The local/Kubernetes workflow automatically selects explicitly new tags and requires native Semgrep validation for both architectures; manual Semgrep verification publishes nothing.
3. **Push to `main`.** The family's workflow builds both architectures, runs its smoke checks, attests the image and uploads `<engine>-image-evidence-<run>-<attempt>` with `<engine>-image-manifest.json`. Until the pin commit, `npm run validate:engines` and the CI job **Engine admission contracts** fail because the inputs run ahead of the plans.
4. **Check the evidence.** The manifest's digest and platform digests, `sourceRevision` equal to the publish commit, an anonymous pull, and `gh attestation verify oci://<image>@<digest> -R <source-repository> --signer-workflow <source-repository>/.github/workflows/<workflow> --source-ref refs/heads/main --source-digest <publish commit>`.
5. **Pin commit.** Catalog `image.tag`, `image.digest` and `provenance.engine.artifact_source_revision`; the plan's `final_artifact`, `publication` and any recorded hash that changed; then every other current file naming the old tag (`git grep -nF '<old tag>'`). Leave historical records alone. `npm run validate:engines` passes again.
6. **Verify product execution.** Test the updated catalog in the product with a bounded fixture or an already-approved target, and compare normalized output with native output using the engine page's recipe. Add the actual scope, commands, outcomes and limits to the page. For someone asking to install or run a scan, use the released desktop app and the scanner skill as AGENTS.md requires.

New images publish to `ghcr.io/ted-h-com` with source repository `TED-H-com/ai-security-scanner`. Existing pins remain at `ghcr.io/teddashh` with source repository `teddashh/ai-security-scanner`. Use the source repository paired with the image namespace for verification; mixed origins are rejected.
