# Security policy

## Reporting a vulnerability

Do not report security vulnerabilities in public issues or pull requests. Contact the repository maintainers privately through GitHub's **Report a vulnerability** feature on the repository's Security tab.

Include the affected version or commit, the relevant command or component, steps to reproduce, and the impact. Do not include real passwords, app-specific passwords, tokens, cookies, or private iCloud data. Use a test account and redact sensitive values from any proof of concept.

The maintainers will acknowledge the report and work with the reporter to assess and address it before public disclosure.

## Supported versions

Security fixes target the latest published release. Update to the latest release before reporting an issue when possible.

## Credential handling

iCLI uses Apple app-specific passwords. It stores saved passwords in the operating system credential store and does not write them to its regular configuration file. Avoid passing passwords as command-line arguments, where shell history or process listings may expose them.
