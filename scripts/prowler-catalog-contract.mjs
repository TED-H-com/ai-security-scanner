import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export const PROWLER_PROVIDER_EXECUTION_CONTRACTS = [
  {
    provider: "aws",
    asset_kind: "cloud_account",
    profile: "aws_iam_service_exact_account",
    network_destinations: [
      "iam.amazonaws.com:443",
      "sts.us-east-1.amazonaws.com:443",
      "ec2.us-east-1.amazonaws.com:443",
      "organizations.us-east-1.amazonaws.com:443",
    ],
  },
  {
    provider: "azure",
    asset_kind: "subscription",
    profile: "azure_iam_service_static_token_exact_subscription",
    network_destinations: ["management.azure.com:443"],
  },
  {
    provider: "gcp",
    asset_kind: "project",
    profile: "gcp_iam_four_checks_exact_project",
    network_destinations: ["cloudresourcemanager.googleapis.com:443"],
  },
];

export const PROWLER_NETWORK_DESTINATIONS =
  PROWLER_PROVIDER_EXECUTION_CONTRACTS.flatMap((contract) => contract.network_destinations);

export const PROWLER_KNOWLEDGE_INPUT = {
  kind: "runtime_live",
  identifier: "Exact-scope AWS, Azure, or GCP IAM configuration",
  version: null,
  acquisition_source: "Provider APIs authorized by one case-scoped ephemeral AWS session, Azure ARM access token, or GCP OAuth access token",
  pin_state: "runtime_live",
};

export const PROWLER_PROVENANCE_DATA = {
  mode: "runtime_live",
  identifier: PROWLER_KNOWLEDGE_INPUT.identifier,
  revision: null,
  acquisition_source: PROWLER_KNOWLEDGE_INPUT.acquisition_source,
};

export const PROWLER_DATA_ACQUISITION = {
  mode: "runtime_live",
  scope_cardinality: "exactly_one_asset",
  credential_lifetime: "launcher_enforced_ephemeral_five_to_sixty_minutes",
  providers: [
    {
      provider: "aws",
      asset_kind: "cloud_account",
      native_identifier: "aws_account_id",
      credential_keys: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
      identity_check: "STS GetCallerIdentity account equals the exact scoped account",
      profile: "aws_iam_service_exact_account",
    },
    {
      provider: "azure",
      asset_kind: "subscription",
      native_identifier: "azure_subscription_id",
      credential_keys: ["AZURE_ACCESS_TOKEN"],
      identity_check: "ARM subscription GET returns the exact scoped subscription in Enabled state",
      profile: "azure_iam_service_static_token_exact_subscription",
    },
    {
      provider: "gcp",
      asset_kind: "project",
      native_identifier: "gcp_project_id",
      credential_keys: ["GOOGLE_OAUTH_ACCESS_TOKEN"],
      identity_check: "projects.testIamPermissions on the exact project proves required reads and denies pinned mutations; project GET returns the exact scoped project in ACTIVE state and getIamPolicy succeeds",
      profile: "gcp_iam_four_checks_exact_project",
    },
  ],
};

export const PROWLER_DOWNSTREAM_RUNTIME_PATCHES = {
  origin: "ai_security_scanner_downstream",
  base_revision: "499fd637f3393b485833b08cdaf4172917c5698e",
  application_phase: "image_build",
  test_hunks_installed: false,
  applier: {
    path: "engines/images/prowler/apply-runtime-patches.py",
    sha256: "sha256:8f698134a7d8bc2b6cab79f2b322f8fe68ecc1b6b8034caf648638503d794383",
  },
  series: {
    path: "engines/images/prowler/patches/series",
    sha256: "sha256:a8cf6ca3d9de3328454cc91c36abda9e71d0df7ba9b35b5420ec93a8c1931c8e",
  },
  patches: [
    {
      path: "engines/images/prowler/patches/0001-azure-static-access-token-iam-only.patch",
      sha256: "sha256:053ef441588b6bff99aef8a568f2617d8933a46449d2f9c2804b796c7a39566a",
      runtime_files: [
        "prowler/providers/azure/azure_provider.py",
        "prowler/providers/azure/lib/arguments/arguments.py",
        "prowler/providers/common/provider.py",
      ],
      purpose: "Adds non-refreshing Azure ARM static-token authentication, exact subscription resolution, and IAM-only service enforcement.",
    },
    {
      path: "engines/images/prowler/patches/0002-gcp-exact-project-lookups.patch",
      sha256: "sha256:7a22e58b3c700813e3b7e814dd04254dd90ddbdbdfbccd917c3b477e487c2fcb",
      runtime_files: ["prowler/providers/gcp/gcp_provider.py"],
      purpose: "Replaces ambient GCP project listing and default discovery with all-or-nothing exact requested-project lookups.",
    },
    {
      path: "engines/images/prowler/patches/0003-gcp-disable-ambient-organization-search.patch",
      sha256: "sha256:136335c3b7defd5a167aa6d07633bcb8f5c99c6f98b398eff01fc15d11a417d1",
      runtime_files: ["prowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py"],
      purpose: "Disables ambient GCP organization search so the four-check profile uses only exact project get and getIamPolicy calls.",
    },
    {
      path: "engines/images/prowler/patches/0004-gcp-disable-provider-organization-lookup.patch",
      sha256: "sha256:ffef7b02808bbb85f1f7d28ab3c453237b33cde45729daa51feb37633e1fd79a",
      runtime_files: ["prowler/providers/gcp/gcp_provider.py"],
      purpose: "Skips provider-level parent organization enrichment whenever an exact GCP project ID is supplied.",
    },
    {
      path: "engines/images/prowler/patches/0005-azure-disable-tenant-enumeration.patch",
      sha256: "sha256:00f40971d80137612b5327a8b7e31de6b05b08dd8239f1bd635339ae6325f80b",
      runtime_files: [
        "prowler/lib/outputs/finding.py",
        "prowler/providers/azure/azure_provider.py",
      ],
      purpose: "Replaces Azure tenant enumeration with exact subscription tenant attribution and preserves attributable findings without fabricating an organization ID.",
    },
    {
      path: "engines/images/prowler/patches/0006-azure-require-enabled-subscription.patch",
      sha256: "sha256:47b4202cdfe545b699fbe0b0dfc3e5d249d94e9d00cf7d61388405071e5aaeba",
      runtime_files: ["prowler/providers/azure/azure_provider.py"],
      purpose: "Rejects an exact Azure subscription unless ARM reports the case-sensitive Enabled state before Prowler can run.",
    },
  ],
  runtime_files: [
    {
      path: "prowler/lib/outputs/finding.py",
      pre_sha256: "sha256:00ed79bee5e32239d3cce4943c70df33dbfe3f85056deb750ad11f2073613cce",
      post_sha256: "sha256:71d5665f11c27a3dc69660ac61b747264066c6791ba65014c50ba80105902749",
    },
    {
      path: "prowler/providers/azure/azure_provider.py",
      pre_sha256: "sha256:8e54390485d31feeb5e114db2c24933f3c73a4f22f2532b5c18583f9520c9cbb",
      post_sha256: "sha256:51cef0e3e7ed819144959f62389d3eb169b97aa37baf37aab66d4c290d21bf14",
    },
    {
      path: "prowler/providers/azure/lib/arguments/arguments.py",
      pre_sha256: "sha256:fc48fdd229d5760f5675f06032e05df8e54ee8777dd04a60aecc093615474068",
      post_sha256: "sha256:afb7c9b47f1b9b2354774579121db4f1c26d6b03112a3d0407fb4f14ad8625af",
    },
    {
      path: "prowler/providers/common/provider.py",
      pre_sha256: "sha256:1080b11456deb6426307167067a3066ec79c87c7af07bb85dd3c507d6c76a1da",
      post_sha256: "sha256:bd65d893c106cf47389cd17071f96002e7302706b07ebb17cdca6c10f95f3f27",
    },
    {
      path: "prowler/providers/gcp/gcp_provider.py",
      pre_sha256: "sha256:9ae2691559660ca902ab3b282fb1a5611bb47ca11f3118d34500dac847770c77",
      post_sha256: "sha256:c30756aaaa1ce3739c6bf2a023b4ab633656c767f1e6fa1e84ba4ff9fff1c34f",
    },
    {
      path: "prowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py",
      pre_sha256: "sha256:029725c008bf0ed0d6c8cdb8ba1a378d40e584dc49ee40e021c4955e4e5688f3",
      post_sha256: "sha256:379876877311fe2f4aa17bb9d5b132c85baaf2081210aebf6da59472cc11c9fe",
    },
  ],
};

const prowlerWrapperStrategy = "Validate exactly one AWS account, Azure subscription, or GCP project against one complete ephemeral provider credential profile, enforce provider-specific identity and read-only permission preflights, then invoke only the matching narrow IAM profile without a shell.";
const downstreamNotice = "Azure static-token and GCP exact-project behavior comes from six ai-security-scanner downstream patches, bound to the applier and runtime-source pre/post SHA-256 values in the packaging plan; it is not native Prowler 5.39.1 behavior.";

function exact(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function artifactDigest(readArtifact, relative) {
  return `sha256:${createHash("sha256").update(readArtifact(relative)).digest("hex")}`;
}

export function validateProwlerCatalogContract({ engine, plan, projectRoot, readArtifact }) {
  const errors = [];
  const read = readArtifact ?? ((relative) => readFileSync(resolve(projectRoot, relative)));
  const requireExact = (actual, expected, label) => {
    if (!exact(actual, expected)) errors.push(`${label} must match the exact released Prowler contract`);
  };

  requireExact(engine?.supported_providers, ["aws", "azure", "gcp"], "catalog:prowler.supported_providers");
  requireExact(engine?.supported_asset_kinds, ["cloud_account", "subscription", "project"], "catalog:prowler.supported_asset_kinds");
  requireExact(engine?.provider_execution_contracts, PROWLER_PROVIDER_EXECUTION_CONTRACTS, "catalog:prowler.provider_execution_contracts");
  requireExact(engine?.network_destinations, PROWLER_NETWORK_DESTINATIONS, "catalog:prowler.network_destinations");
  requireExact(engine?.execution?.network?.destinations, PROWLER_NETWORK_DESTINATIONS, "catalog:prowler.execution.network.destinations");
  requireExact(engine?.provenance?.data, PROWLER_PROVENANCE_DATA, "catalog:prowler.provenance.data");
  requireExact(engine?.compatibility?.knowledge_input, PROWLER_KNOWLEDGE_INPUT, "catalog:prowler.compatibility.knowledge_input");
  if (engine?.compatibility?.wrapper?.strategy !== prowlerWrapperStrategy) {
    errors.push("catalog:prowler.compatibility.wrapper.strategy must describe the exact three-provider narrow-IAM dispatch");
  }
  if (!engine?.notices?.includes(downstreamNotice)) {
    errors.push("catalog:prowler.notices must disclose the downstream Azure/GCP runtime patches");
  }

  requireExact(plan?.provider_execution_contracts, PROWLER_PROVIDER_EXECUTION_CONTRACTS, "engines/images/prowler/plan.json.provider_execution_contracts");
  requireExact(plan?.knowledge_input, PROWLER_KNOWLEDGE_INPUT, "engines/images/prowler/plan.json.knowledge_input");
  requireExact(plan?.data_acquisition, PROWLER_DATA_ACQUISITION, "engines/images/prowler/plan.json.data_acquisition");
  requireExact(plan?.downstream_runtime_patches, PROWLER_DOWNSTREAM_RUNTIME_PATCHES, "engines/images/prowler/plan.json.downstream_runtime_patches");
  requireExact(plan?.managed_runtime?.network_destinations, PROWLER_NETWORK_DESTINATIONS, "engines/images/prowler/plan.json.managed_runtime.network_destinations");
  if (plan?.managed_runtime?.updates !== false || plan?.managed_runtime?.telemetry !== false) {
    errors.push("engines/images/prowler/plan.json: managed runtime must disable updates and telemetry");
  }
  if (plan?.wrapper?.strategy !== prowlerWrapperStrategy) {
    errors.push("engines/images/prowler/plan.json.wrapper.strategy must describe the exact three-provider narrow-IAM dispatch");
  }

  const artifacts = [
    PROWLER_DOWNSTREAM_RUNTIME_PATCHES.applier,
    PROWLER_DOWNSTREAM_RUNTIME_PATCHES.series,
    ...PROWLER_DOWNSTREAM_RUNTIME_PATCHES.patches,
  ];
  for (const artifact of artifacts) {
    try {
      const actual = artifactDigest(read, artifact.path);
      if (actual !== artifact.sha256) {
        errors.push(`${artifact.path}: actual SHA-256 differs from the exact Prowler runtime-patch contract`);
      }
    } catch (error) {
      errors.push(`${artifact.path}: cannot read exact Prowler runtime-patch input (${error.message})`);
    }
  }

  try {
    const series = read(PROWLER_DOWNSTREAM_RUNTIME_PATCHES.series.path).toString("utf8");
    const expectedSeries = `${PROWLER_DOWNSTREAM_RUNTIME_PATCHES.patches.map(({ path }) => path.split("/").at(-1)).join("\n")}\n`;
    if (series !== expectedSeries) {
      errors.push("engines/images/prowler/patches/series: patch names and order must be exact");
    }
  } catch {
    // The unreadable-artifact error above is already specific enough.
  }

  try {
    const dockerfile = read("engines/images/prowler/Dockerfile").toString("utf8");
    for (const required of [
      "COPY --chmod=0555 engines/images/prowler/apply-runtime-patches.py /tmp/ai-security-scanner-prowler/apply-runtime-patches.py",
      "COPY --chmod=0444 engines/images/prowler/patches /tmp/ai-security-scanner-prowler/patches",
      "RUN /home/prowler/.venv/bin/python /tmp/ai-security-scanner-prowler/apply-runtime-patches.py",
      "--root /home/prowler",
      "--patch-dir /tmp/ai-security-scanner-prowler/patches",
    ]) {
      if (!dockerfile.includes(required)) {
        errors.push(`engines/images/prowler/Dockerfile: exact runtime-patch application lacks ${required}`);
      }
    }
  } catch (error) {
    errors.push(`engines/images/prowler/Dockerfile: cannot verify exact runtime-patch application (${error.message})`);
  }

  return errors;
}
