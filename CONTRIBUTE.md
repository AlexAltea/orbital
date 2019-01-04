# Contribution Guidelines

**Orbital welcomes all contributions.** Please take a moment to read about our internal organization and requirements for contributors.


## Organization

We define the following lists of people involved in Orbital:

* _Author_: Original developer of this project.
* _Maintainers_: Current lead developers and responsible of reviews and maintenance.
* _Developers_: Current and former regular developers.
* _Contributors_: People who have occasionally contributed to this project.
* _Supporters_: People who provided economical support.

These lists must be stored in [CREDITS.md](CREDITS.md) and may also be available through Orbital's GUI/CLI. Three pieces of information about a person may be provided:

- _Name_: Legal given name(s) and/or legal family name(s).
- _Alias_: Nickname chosen by the person.
- _Email_: Valid email address owned by the person.

These shall be formatted as follows `$name (@$alias) <$email>`. If *Name* is not provided, *Alias* shall not be wrapped in parenthesis. If neither *Name* nor *Alias* are provided, *Email* shall not be wrapped in angle brackets. Members of the lists: *Maintainers* and *Developers* must provide a valid email address, to allow contacting them if required.

These lists might be managed following these rules:

1. Only *Author* and *Maintainers* shall modify the lists: {*Maintainers*, *Developers*, *Affiliated*, *Supporters*}.
2. Any listed person may remove or modify their own data.
3. The lists will be sorted by "joining date", i.e. the date the name was added to the list, by keeping older entries first.


## Licensing

All files and patches contributed to Orbital shall be licensed under *MIT License*, described at root-level file: [LICENSE](LICENSE), unless this license gets overriden in any of the following circumstances:

- The file header specifies a different license.
- Any parent folders contain a different *LICENSE* file.

To ensure licensing criteria are met, we require contributors to follow the [Developer Certificate of Origin](https://developercertificate.org/). The DCO is an attestation attached to every contribution made by every developer. In the commit message of the contribution (described more fully later in this document), the developer simply adds a `Signed-off-by` statement and thereby agrees to the DCO.

Below you'll find an excerpt from the original document linked above listing all major points of the DCO:

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

To comply with the DCO, we require a sign-off message, in the following format, to be included on each commit in the pull request:

```
Signed-off-by: $name <$email>
```

This footer can be added by specifying the `-s` or `--signoff` flag to the `git commit` command. Contributors must do this with every commit they want to upstream to Orbital. Optionally, contributors should digitally sign the commits by adding the `-S` flag, and uploading their GPG public key to GitHub.
