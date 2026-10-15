export const LOCAL_IMAGE_DIGEST = "${{ steps.guard.outputs.digest || steps.build.outputs.digest || steps.semgrep_image.outputs.digest }}";
export const LOCAL_BUILD_GUARD = "steps.guard.outputs.should_build == 'true' && matrix.engine != 'semgrep'";
export const SEMGREP_HANDOFF_GUARD = "matrix.engine == 'semgrep' && steps.guard.outputs.should_build == 'true'";

export function validateSemgrepNativePublication(workflow) {
  const errors = [];
  const require = (condition, message) => {
    if (!condition) errors.push(`Semgrep native image handoff: ${message}`);
  };
  const native = workflow?.jobs?.["semgrep-native-verify"]?.steps ?? [];
  const steps = workflow?.jobs?.publish?.steps ?? [];
  const reviewIndex = native.findIndex((step) => step.name === "Verify complete result union, source attachment and runtime boundaries");
  const exportIndex = native.findIndex((step) => step.name === "Export the exact tested native image");
  const uploadIndex = native.findIndex((step) => step.name === "Transfer the tested native image to publication");
  require(reviewIndex >= 0 && exportIndex > reviewIndex && uploadIndex > exportIndex,
    "only successfully tested images may be exported and transferred");
  for (const index of [exportIndex, uploadIndex]) {
    require(native[index]?.if === "success() && inputs.mode != 'verify'",
      "image export and upload must be absent in verification-only or failed runs");
  }
  require(native[uploadIndex]?.with?.name === "semgrep-native-image-${{ matrix.arch }}-${{ github.run_id }}-${{ github.run_attempt }}",
    "native image upload must be bound to its architecture, run and attempt");
  require(native[uploadIndex]?.with?.path === "${{ runner.temp }}/semgrep-native-image" &&
    native[uploadIndex]?.with?.["if-no-files-found"] === "error",
    "native image upload must contain only its required transfer directory");

  const build = steps.find((step) => step.id === "build");
  const handoffIndex = steps.findIndex((step) => step.id === "semgrep_image");
  const handoff = steps[handoffIndex];
  const guardIndex = steps.findIndex((step) => step.uses === "./.github/actions/engine-image-evidence/publication-guard");
  require(build?.if === LOCAL_BUILD_GUARD, "the ordinary build must exclude Semgrep and retain the immutable-tag guard");
  require(guardIndex >= 0 && handoffIndex > guardIndex && handoff?.if === SEMGREP_HANDOFF_GUARD,
    "native publication must follow the immutable-tag guard and select only Semgrep");
  require(handoff?.env?.CANDIDATE_TAG === "${{ steps.guard.outputs.candidate_tag }}" &&
    handoff?.env?.REVISION === "${{ github.sha }}",
    "native publication must use the guarded candidate tag and exact source revision");
  for (const arch of ["amd64", "arm64"]) {
    const index = steps.findIndex((step) => step.name === `Download the tested ${arch} image`);
    const download = steps[index];
    require(index >= 0 && index < handoffIndex && download?.if === SEMGREP_HANDOFF_GUARD &&
      download?.uses?.startsWith("actions/download-artifact@") &&
      download?.with?.name === `semgrep-native-image-${arch}-\${{ github.run_id }}-\${{ github.run_attempt }}` &&
      download?.with?.path === `\${{ runner.temp }}/semgrep-native-image-${arch}`,
      `${arch} must use its image from the same run and attempt`);
  }
  const script = handoff?.run ?? "";
  for (const required of [
    'sha256sum "${transfer}/image.tar.gz"', '.source_revision == $revision',
    '.expected_version == $version', '"linux/${arch}"',
    'docker load --input "${transfer}/image.tar.gz"',
    'python3 engines/images/semgrep/verify_image_payload.py',
    '--image "${image_id}" --expected "${expected_payload}"',
    'platform_refs+=("${IMAGE}@${platform_digest}")',
    'docker buildx imagetools create --tag "${IMAGE}:${CANDIDATE_TAG}" "${platform_refs[@]}"',
    'echo "digest=${digest}" >> "${GITHUB_OUTPUT}"',
  ]) require(script.includes(required), `native publication is missing ${required}`);
  require(!/docker (?:build|buildx build)\b/u.test(script), "publication must not rebuild the tested images");

  const verifyIndex = steps.findIndex((step) => step.id === "verify");
  require(verifyIndex > handoffIndex && steps[verifyIndex]?.env?.DIGEST === LOCAL_IMAGE_DIGEST &&
    steps[verifyIndex]?.run?.includes("verify_image_payload.py"),
    "anonymous verification must consume the exact selected digest and recheck the native filesystem");
  for (const action of ["./.github/actions/engine-image-evidence", "./.github/actions/engine-image-evidence/promote"]) {
    const index = steps.findIndex((step) => step.uses === action);
    require(index > verifyIndex && steps[index]?.with?.digest === LOCAL_IMAGE_DIGEST,
      `${action} must consume the same verified digest after anonymous checks`);
  }
  require(steps.find((step) => step.name === "Record the published index and platform digests")?.env?.DIGEST === LOCAL_IMAGE_DIGEST,
    "the publication manifest must record the same selected digest");
  return errors;
}
