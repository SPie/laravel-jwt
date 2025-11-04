# Branch Protection Rules

## Master Branch Protection

To ensure all tests pass before merging PRs, configure the following branch protection rules for the `master` branch in GitHub:

### Required Settings

1. Go to **Settings** → **Branches** in your GitHub repository
2. Add a branch protection rule for `master`
3. Enable the following settings:

#### Required status checks
- ✅ **Require status checks to pass before merging**
- ✅ **Require branches to be up to date before merging**

#### Required status checks to pass:
Select all of these jobs from the "Tests" workflow:
- `test (7.4)`
- `test (8.0)`
- `test (8.1)`
- `test (8.2)`
- `test (8.3)`
- `test (8.4)`

#### Additional recommended settings:
- ✅ **Require pull request reviews before merging** (optional but recommended)
- ✅ **Dismiss stale pull request approvals when new commits are pushed**
- ✅ **Require review from CODEOWNERS** (if you have a CODEOWNERS file)
- ✅ **Include administrators** (enforce rules for admins too)

### Notes
- All PHP version tests must pass before a PR can be merged
- The GitHub Action will automatically run on all pull requests targeting `master`
- Coverage reports are only uploaded once (from PHP 8.2) to avoid duplication