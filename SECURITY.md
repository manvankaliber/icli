# Security policy

## Reporting a vulnerability

Do not report security vulnerabilities in public issues or pull requests. Contact the repository maintainers privately through GitHub's **Report a vulnerability** feature on the repository's Security tab.

Include the affected version or commit, the relevant command or component, steps to reproduce, and the impact. Do not include real passwords, app-specific passwords, tokens, cookies, or private iCloud data. Use a test account and redact sensitive values from any proof of concept.

The maintainers will acknowledge the report and work with the reporter to assess and address it before public disclosure.

## Supported versions

Security fixes target the latest published release. Update to the latest release before reporting an issue when possible.

## Credential handling

iCLI stores app-specific passwords, pending Apple sign-in challenges, session tokens, and cookies in the operating system credential store. It never saves the Apple Account password, and stores only account addresses and settings in its regular configuration file. Passwords and verification codes can be read from private stdin or hidden terminal prompts. Avoid passing passwords as command-line arguments, where shell history or process listings may expose them.
