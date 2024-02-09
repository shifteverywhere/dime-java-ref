# CHANGES

## Version 1.2.9 - 2024-02-07
- Updates dependencies
- Specifies sourceCompatibility/targetCompatibility to JAVA 11 (55)

## Version 1.2.8 - 2024-02-07
- Restrictions to only generate thumbprints of signed Message/Data items removed
- Minor updates unit tests
- Minor corrections to documentation
- Fixes an issue with Common Name claim
- Adds a method to get all attached signatures of an Item as a list of Signature instances
- Adds a method to get the unique name of a key
- Adds a method to get all claims and values for an Item
- Exposes a Map with all set claims in an item
- Updates dependencies

## Version 1.2.7 - 2023-03-09
- Updates dependencies, particularly org.json:json due to CVE-2022-45688

## Version 1.2.6 - 2023-03-08
- Allows fetching of items from envelopes based on any claim, not just context ("ctx")
- Deprecated Envelope#getItem(String), fetching from context
- Introduced NaCl crypto suite with large performance gains when signing
- Implements the claim Common Name ("cnm")
- Support for legacy format (before official DiME specification) has been marked deprecated and will be removed in version 1.3
- Conforms to DiME data format version 1.004

## Version 1.2.5 - 2023-02-02
- Adds support to verify identities using an arbitrary identity from the trust chain
- Removes verification of identity issuing requests when issuing new identity, if required, verify manually first
- Removes verification of issuer when issuing new identity, if required, issuers need to be verified manually first
- Fixes an issue with issuing an identity with the same key as the issuing identity
- Fixes an issue when requesting SELF capability for an identity that is not self-issued

## Version 1.2.4 - 2022-11-14
- Fixes an issue with the used crypto suite was not attached to an item link
- Fixes an issue with legacy keys and creating a public copy

## Version 1.2.3 - 2022-11-10
- Conforms to DiME data format version 1.002
- Improves working with encrypted message payloads and allows encryption with symmetric key
- Internal verification order changed according to Dime 1.002
- Adds Issuer URL claim ("isu")
- Adds identity capabilities SEAL and TIMESTAMP
- Fixes an issue with converting items containing item links to legacy
- Fixes an issue where KID was not set correctly when encrypting message payloads

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
- Removes "Claim.USE" and replaces it with "Claim.CAP" (KeyCapability/IdentityCapability)
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

**Copyright (c) 2024 Shift Everywhere AB. All rights reserved.**