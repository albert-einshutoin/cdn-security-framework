# Release candidate binding (pre-publication gate)

This gate is for the eventual #571 publication after #895 GO. It is not release approval, and it must not be run to publish the current 1.4.0-versioned schema 2 candidate. H01 and the final human GO remain pending.

The release job uses the `npm-release` GitHub environment. A repository administrator must configure at least one **required reviewer** and **prevent self-review**. The verifier reads the environment configuration; missing protection or unavailable API access stops before publication. This task does not change repository settings, move secrets, or expand token permissions. **Known administrative HOLD:** the current workflow token grants only `contents: read` and `id-token: write`; its new Actions run/jobs, environment read and cross-run artifact reads need `actions: read`, while its #895 comment read needs `issues: read`. Those permissions are deliberately not added in this PR. A separately authorized settings/permission review and safe non-public run are required before #571. Do not bypass this failure by repacking or using a dispatch input as approval.

After H01 is completed and the final versioned candidate is produced and fully validated on `main`, the repository owner may append a machine-readable decision to #895. The latest owner-authored record for the tag is authoritative. A later `NO_GO` record revokes an earlier GO. The record begins with `CSF_RELEASE_APPROVAL_V1` on its own line, followed by JSON with:

- `version: 1`, `decision: "GO"` or `"NO_GO"`;
- `rc` and `final`: exact `source`, `tree`, `run`, `attempt`, tgz `sha256`, and common `lockSha256`;
- `tag`, `packageVersion`, and `distTag` (`latest` for stable, `next` for prerelease);
- `h01Evidence`: the real #890 result comment URL;
- `changedPaths`: the exact sorted set of paths changed between reviewed RC and final commit, including #571 version/Changelog edits and any other explicitly assessed change.

The verifier compares that record with the tag checkout, `main` ancestry, both actual main CI runs, all mandatory final jobs, and the downloaded **RC and final** single-pack tarballs' bytes and locks. A new final candidate needs its own main run and an updated owner decision. Approval of the RC does **not** grant an unchanged hash to the versioned final candidate. Before approving the protected environment, its reviewer must inspect the #895 owner record and its cited H01/final-candidate evidence; GitHub pauses the job **before** these verification steps, so the reviewer cannot rely on their output at approval time. After approval, the workflow performs the machine checks and fails closed on a mismatch. A dispatch value, commit author text, or local review ALLOW is not that approval.

The eventual publish command targets the verified `candidate.tgz` path with `--ignore-scripts`, `--provenance`, and the approved dist-tag. It does not invoke a second pack. The registry verification step compares the fetched registry tarball SHA-256 to the approved candidate, including the already-published-version path, then checks provenance. No tag, npm publish, GitHub Release, or release workflow dispatch is part of this PR's validation.
