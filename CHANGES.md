# CHANGES

## Version 1.0.3 - 2022-04-19
- Minor fix to prepare for an upcoming change that allows for more than one item to be linked to a Message item

## Version 1.0.2 - 2022-02-30
- Includes a fix where the public copy of a key did not receive the claims from the source key
- Updates org.json dependency to version 20220320

## Version 1.0.1 - 2022-02-22
- Allows for systemName to be set when issuing a new identity. If none is provided, then the systemName from the issuing identity is used
- Adds an option to exclude the trust chain from an issued identity, allows for more flexible usage and trust verification
- Method Identity:isTrusted() and Identity:isTrusted(Identity) is added for more fine-grained verification of trust chains
- Method Identity:verifyTrust() is deprecated and will be removed in future versions
- Additional unit tests added (from C#/.NET reference implementation)
- Updates org.json dependency to version 20211205
- Official acknowledgements added, credits where credits are due, thank you!

**NOTE:** *Version 1.0.1 includes changes that will break 1.0.0. These are only code-breaking changes, so all previously issued identities and other created Di:ME items will continue to work.*

## Version 1.0.0 - 2022-01-24
- Official version 1.0.0 (**Hurray!**)

**Copyright © 2022 Shift Everywhere AB. All rights reserved.**