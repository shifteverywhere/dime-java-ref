# CHANGES: Di:ME JAVA REFERENCE

## Version 1.0.1 - 2022-xx-xx
- Adds an option to exclude the trust chain from an issued identity, allows for more flexible usage and trust verification
- Method Identity:isTrusted() and Identity:isTrusted(Identity) is added for more fine-grained verification of trust chains
- Method Identity:verifyTrust() is deprecated and will be removed in future versions
- Additional unit tests added (from C#/.NET reference implementation)
- Updates org.json dependency to version 20211205
- Official acknowledgements added, credits where credits due, thank you!

**NOTE:** *Version 1.0.1 includes changes that will break 1.0.0. These are only code breaking changes, so all previously issued identities and other created Di:ME items will continue to work.*

## Version 1.0.0 - 2022-01-24
- Official version 1.0.0 (**Hurray!**)

**Copyright © 2022 Shift Everywhere AB. All rights reserved.**