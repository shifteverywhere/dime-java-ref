# CHANGES

## Version 1.2.2 - 2022-10-25
- Conforms to DiME data format version 1.001
- Refactored verify methods to match C# interface
- Cryptographic suite changed to 'DSC'
  - Key encoded changes to Base64 (from Base58), massive performance gain
  - 'STN' cryptographic suite still supported, need to set Crypto#setDefaultSuiteName(string) to use it as default
  - Item links created using 'DSC' will not work in versions before 1.2.2
  - Keys, Identities, IIRs (and Messages using 'pub') created using 'DSC' will not work in versions before 1.2.2
- Instance method Item#thumbprint changes name to Item#generateThumbprint (code-breaking change)

## Version 1.2.1 - 2022-10-19
- Minor clean up and fixes
- Adds alien (cross platform) unit tests
- First publish to Maven Central (updated build.gradle)

## Version 1.2.0 - 2022-10-11
- Full implementation of DiME data format specification (1.000)
- Grace period added to Dime as a global setting (this means breaking changes from 1.1.0 in verify methods)
- Many methods marked as deprecated in version 1.1.1 and earlier removed
- Introduces KeyRing to hold multiple keys and identities as trusted
  - Removes trusted Identity in Dime and Identity
  - Verify has been reworked to support key ring
  - isTrusted has been replaced with verify in Identity
- IntegrityState introduced to hold result of a verification
- Introduced getClaim/putClaim/removeClaim to allow for more flexible claim handling
  - Removes many claim convenience methods, simplifies usage and code
- Removes Claim.USE and replaces it with Claim.CAP (KeyCapability/IdentityCapability)
- Cleaned up, removed and renamed package specific exceptions

**NOTE** *Version 1.2.0 includes changes that will break 1.1.1 and earlier. These are only code-breaking changes, so all previously created DiME items will continue to work.*

## Version 1.1.1 - 2022-09-25
- Refactored KeyUse to Key.Use
- Minor improvements and fixes

## Version 1.1.0 - 2022-08-18
- Adds possibility for multiple signatures for items
- Adds feature to strip an item of any signatures, so it can be modified and then resigned
- Refactors item linking and allows linking to multiple items
- Adds plugin model for other cryptographic suites
- Introduces JSON canonicalization to guarantee some order of JSON data, avoiding breaking of signatures
- Implements Tag item
- Implements Data item
- Adds the possibility to override the current time, intended for troubleshooting
- Numerous minor improvements and fixes
- Breaking changes in Envelope (sign/verify) removes return item

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

**NOTE** *Version 1.0.1 includes changes that will break 1.0.0. These are only code-breaking changes, so all previously issued identities and other created DiME items will continue to work.*

## Version 1.0.0 - 2022-01-24
- Official version 1.0.0 (**Hurray!**)

**Copyright (c) 2022 Shift Everywhere AB. All rights reserved.**