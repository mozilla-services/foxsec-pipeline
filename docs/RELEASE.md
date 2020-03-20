# Release process

## Versioning

__Note__: Creating a release will always involve the addition of a tag. Before hand ensure that
the version number that will be used to tag is accurately represented in `pom.xml` and in
`Version.java`. If not, ensure an update is committed to update the version number to the
correct value before tagging.

The minor version should be incremented whenever a release contains new features or configurations.
As an example if the current release is `0.5.4`, the next minor release is `0.6.1`. If the current
version is `0.5.1`, the next minor release is `0.6.1`.

The patch version can be incremented if a new release has minor fixes, for example to resolve a bug
that was identified during testing in stage. As an example, `0.5.1` would become `0.5.2`. A patch
release should __only__ be used if the new release does not modify configuration options or anything
else that deployment infrastructure may need to be aware of.

## Creating a new release

Releases are always created from `master`.

### Regenerate documentation

Regenerate javadoc documentation and merge the new documentation into `master`.

```bash
git rm -r docs/secops-beam/*
bin/m javadoc:javadoc
git add docs/secops-beam
```

### Tag release

Tag the new minor version from an up to date local `master` branch that includes the documentation
updates, and push the tag.

```bash
git tag 0.2.1
git push origin 0.2.1
```
