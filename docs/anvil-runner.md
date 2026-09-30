# Anvil runner registration gate

NockLock is public. A fork PR can change any `pull_request` workflow or add a
new one that requests matching self-hosted runner labels. The Anvil job's
`pull_request_target` trigger protects its own workflow definition, but job
conditions and labels alone cannot protect a runner from other workflows.

Before registering a credentialed Anvil runner, an organization admin must:

1. Create the `nocklock-anvil` runner group. Limit repository access to
   `nocktechnologies/nocklock`, allow this public repository, and restrict
   workflow access to **only**
   `nocktechnologies/nocklock/.github/workflows/anvil.yml@refs/heads/main`.
   Put the Anvil runner only in this group. Do not expose another runner with
   access to its credentials through repo-wide labels or a broader group.
2. Check the repo and organization policy under Settings > Actions > General >
   Approval for running fork pull request workflows from contributors. Require
   approval for all outside collaborators. This is an additional review gate;
   it does not replace the workflow-scoped runner group.
3. Verify the runner user's home cannot read other runner users' credentials or
   review files. The Anvil account should hold only its dedicated Codex auth.
4. Verify the group has `restricted_to_workflows: true`, the single selected
   workflow above, and only the intended repository. Then register the runner.

The Anvil workflow checks out the event's base SHA. It fetches
`refs/pull/<number>/head` only as diff data and refuses a different SHA. No
fork-controlled repository code is checked out or executed by its Actions steps.
