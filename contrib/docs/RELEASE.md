# Release process

## Creating a new minor release

Minor releases are used to release new features or more generally occur as part of the
standard release cycle. A new minor release increments the minor release version number, and
reverts the patch level number to `1`. As an example, the next minor release from `0.1.1` is
`0.2.1`, and from `0.3.5` is `0.4.1`.

New minor releases are created from `master`.

### Tag release

Tag the new minor version from an up to date local `master` branch and push the tag.

```bash
git tag 0.2.1
git push origin 0.2.1
```

### Create release branch

Create the new minor release branch from existing `master` and push it.

The release branch should **not** include the patch level component of the version tag.

```bash
git checkout -b release-0.2
git push --set-upstream origin release-0.2
```

## Creating a new patch release

Patch releases are used to fix a bug identified in a released minor version. These fixes
are applied in a minor release branch.

### Commit fix in new branch

Create a new branch based on the minor release branch the fix should be applied in. For example,
if the fix is needed in `0.2`:

```bash
git fetch origin
git checkout -b fix --no-track origin/release-0.2
...
git commit
git push --set-upstream origin fix
```

### PR fix against minor branch

Create a new PR against the minor release branch the fix should be applied in, and merge after
review.

### Tag patch release

Once merged into the minor release branch, create a new tag incrementing the patch level.

```bash
git fetch origin
git checkout -b release-0.2 origin/release-0.2
git tag 0.2.2
git push origin 0.2.2
```

### Update master if required

If required, another PR should be created to apply the fix to mainline.
