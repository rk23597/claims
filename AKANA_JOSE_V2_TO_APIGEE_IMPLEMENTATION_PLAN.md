# Akana JOSE Security Policy v2 to Apigee
## JWS and JWE Implementation Plan

| Item | Value |
|---|---|
| Status | Draft |
| Owner | Customer Digital and Data |
| Migration source | Akana JOSE Security Policy v2 |
| Target platform | Apigee |
| Last updated | 30 October 2026 |
| Related Akana case | `01676299` |
| Scope | JWS, JWE, protected-header validation, `crit`, and UK Open Banking 3.1 compatibility |

## 1. Purpose

This document defines the implementation plan for migrating Akana JOSE Security Policy v2 behavior to Apigee.

The implementation will:

- retain the existing KVM-driven proxy execution model;
- support JWS request verification and response/fault generation;
- support JWE request decryption and response/fault encryption;
- validate JOSE protected-header parameters configured as key/value pairs;
- validate and generate the JWS `crit` protected-header parameter;
- apply UK Open Banking 3.1 header rules automatically when enabled;
- support `IN`, `OUT`, and `FAULT` protection scopes;
- centralize all reusable logic in shared flows;
- avoid per-proxy JavaScript or cryptographic code;
- support direct Apigee creation and Akana migration through the same KVM schema; and
- map both creation paths to one internal effective mode.

This is an implementation plan. It does not change the confirmed Akana behavior without an explicit migration decision.

## 2. Scope and terminology

### 2.1 In scope

- JWS Compact Serialization.
- Attached compact JWS.
- Detached compact JWS using the normal Base64URL payload representation.
- Detached compact JWS using the RFC 7797 unencoded payload option.
- JWS protected-header parameter validation.
- JWS critical-header validation and generation.
- UK Open Banking 3.1 `iat`, `iss`, and `tan` protected headers.
- Environment-specific Open Banking `tan` resolution.
- JWE protected-header validation and configured cryptographic algorithms.
- Request, response, and fault integration.
- Proxy, shared-flow, UI, onboarding, and CI/CD checks.
- Akana-to-Apigee configuration conversion.

### 2.2 Out of scope until separately confirmed

- JWS JSON Serialization.
- Open Banking versions other than 3.1.
- Current UK Open Banking profiles that differ from the migrated Akana behavior.
- JWT payload-claim validation such as JWT `aud`, `exp`, `nbf`, or `scope`.
- A new key-management platform.
- A new participant directory.
- JWE features not present in the current Akana policies, such as compression or external Additional Authenticated Data.

### 2.3 Meaning of “claim” in this document

Akana describes `iat`, `iss`, `tan`, `typ`, and similar values as claims. In this implementation they are **JOSE protected-header parameters**. They are not claims in a JWT payload.

All validation described in this document applies to the decoded protected JOSE header unless a section explicitly states otherwise.

## 3. Standards baseline

The implementation is based on:

- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html);
- [RFC 7515 Appendix F: Detached Content](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-F);
- [RFC 7797: JWS Unencoded Payload Option](https://www.rfc-editor.org/rfc/rfc7797.html);
- [RFC 7516: JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html);
- [Akana JOSE Security Policy v2](https://help.akana.com/content/current/ag/policies/policy_op_jose_security_v2.htm);
- [Akana UK Open Banking use case](https://help.akana.com/content/current/ag/policies/uc_ukopenbanking.htm);
- [Apigee VerifyJWS policy](https://cloud.google.com/apigee/docs/api-platform/reference/policies/verify-jws-policy);
- [Apigee GenerateJWS policy](https://cloud.google.com/apigee/docs/api-platform/reference/policies/generate-jws-policy); and
- [Apigee VerifyJWT policy, including encrypted JWT](https://cloud.google.com/apigee/docs/api-platform/reference/policies/verify-jwt-policy).

## 4. Confirmed design decisions

1. Two configuration creation paths are retained for stakeholder comparison: direct Apigee creation and Akana migration. Both emit the same KVM schema.
2. Both approaches use the same `jws.profile` values: `COMPACT`, `COMPACT_DETACHED`, and `COMPACT_DETACHED_UNENCODED`.
3. Original Akana `Unencoded Detached Payload` and `Enforce Appendix F` values are migration inputs only; they are not stored in the runtime KVM.
4. `jws.profile` directly selects one of the three internal JWS effective modes:
   - `COMPACT`;
   - `COMPACT_DETACHED`; and
   - `COMPACT_DETACHED_UNENCODED`.
5. `COMPACT_DETACHED` represents RFC 7515 Appendix F behavior.
6. `COMPACT_DETACHED_UNENCODED` represents RFC 7797 behavior with `b64:false`.
7. Open Banking message signing always uses a detached JWS.
8. A detached HTTP message always carries the original payload separately in the HTTP body.
9. “Encoded” versus “unencoded” describes the payload representation in the **JWS signing input**. It does not change the transmitted HTTP body.
10. `headerValidation` is a strict typed key/value map for static protected-header validation.
11. `criticalHeaders` contains only additional user-configured critical headers. Runtime-mode entries are derived automatically.
12. `alg`, `kid`, `b64`, `crit`, and JWE `enc` are runtime-managed fields and must not be duplicated in `headerValidation`.
13. Enabling Open Banking automatically enables the required Open Banking `crit` validation. There is no separate switch for disabling it.
14. Open Banking `tan` comes from trusted environment configuration, not from each proxy and not from the incoming JWS.
15. Open Banking `iat` permits a maximum future difference of 120 seconds and has no maximum-age rule, matching the current Akana response.
16. Final Open Banking `iss` validation remains blocked on Akana case `01676299`.
17. Configuration flags must be JSON booleans, not strings such as `"true"`.
18. Private keys and private-key material must never be stored in the proxy configuration JSON.

## 5. Internal JWS effective modes

### 5.1 `COMPACT`

Wire representation:

```text
BASE64URL(protected-header).BASE64URL(payload).BASE64URL(signature)
```

Signing input:

```text
BASE64URL(protected-header) + "." + BASE64URL(payload-bytes)
```

Behavior:

- the payload is contained inside the JWS;
- no detached-signature HTTP header is required;
- `b64` is absent;
- `b64` must not appear in `crit`; and
- for inbound processing, the verified payload is restored as the message content before target invocation.

### 5.2 `COMPACT_DETACHED`

Wire representation:

```text
BASE64URL(protected-header)..BASE64URL(signature)
```

Signing input:

```text
BASE64URL(protected-header) + "." + BASE64URL(exact-body-bytes)
```

Behavior:

- this is the RFC 7515 Appendix F effective behavior;
- the HTTP body remains the original body;
- the serialized JWS is read from or written to `jws.source`;
- `b64` is absent;
- `b64` must not appear in `crit`; and
- verification and generation must use the exact body bytes without JSON reserialization.

### 5.3 `COMPACT_DETACHED_UNENCODED`

Wire representation:

```text
BASE64URL(protected-header)..BASE64URL(signature)
```

Signing input:

```text
BASE64URL(protected-header) + "." + exact-body-bytes
```

Behavior:

- this is the RFC 7797 unencoded payload option;
- the HTTP body remains the original body;
- the serialized JWS is read from or written to `jws.source`;
- the protected header must contain `"b64": false`;
- `crit` must contain `"b64"`; and
- verification and generation must use the exact body bytes without JSON reserialization.

### 5.4 Open Banking detached requirement

Open Banking does not use the attached `COMPACT` public profile in this migration.

Open Banking can operate over either detached effective mode supported by the migrated Akana policy:

- `COMPACT_DETACHED`: the signature input uses `BASE64URL(body)` and `b64` is absent;
- `COMPACT_DETACHED_UNENCODED`: the signature input uses raw body bytes and `b64:false` is required.

The documented Akana UK Open Banking use-case preset selects unencoded detached payload and enables Appendix F. Its resulting `effectiveMode` is `COMPACT_DETACHED`.

When a user enables Open Banking, default `jws.profile` to `COMPACT_DETACHED` in both approaches. An imported Akana policy with Appendix F disabled maps to `COMPACT_DETACHED_UNENCODED`.

### 5.5 JWS source

Use one structured `source` field. It identifies where the serialized JWS is read for `IN` processing and where it is written for `OUT` or `FAULT` processing.

HTTP-header source:

```json
{
  "source": {
    "location": "HEADER",
    "name": "x-jws-signature"
  }
}
```

Message-body source:

```json
{
  "source": {
    "location": "MESSAGE_BODY",
    "name": "message.content"
  }
}
```

Rules:

- `source` is required whenever JWS verification or generation is enabled.
- `source.location` must be `HEADER` or `MESSAGE_BODY`.
- `HEADER` requires a non-empty, syntactically valid HTTP header `name`.
- `MESSAGE_BODY` requires `name` to be exactly `message.content`.
- The UI must not allow a custom name for `MESSAGE_BODY`; it sets `message.content` automatically.
- `COMPACT` may use either source because the payload is attached inside the serialized JWS.
- `COMPACT_DETACHED` and `COMPACT_DETACHED_UNENCODED` require `HEADER` in the current message model because the HTTP body carries the detached payload.
- Open Banking requires `HEADER` with `name` equal to `x-jws-signature`.
- HTTP header lookup is case-insensitive, but generation uses the configured canonical spelling.
- The source is trusted configuration. A request cannot override it.

The name `source` is retained for the public KVM model even though it acts as an output location during `OUT` and `FAULT` generation.

## 6. Common profile model and two adoption approaches

Both approaches use the same KVM fields and the same three `jws.profile` values:

```text
COMPACT
COMPACT_DETACHED
COMPACT_DETACHED_UNENCODED
```

Neither approach stores `unencodedDetachedPayload` or `enforceAppendixF`. Those are original Akana policy controls used only by the migration converter to select the final profile.

### 6.1 Compact Detached versus Appendix F

The following table supports the stakeholder walkthrough.

| Effective behavior | JWS sent on the wire | Payload used in signing input | `b64` behavior | Common KVM profile | Original Akana policy controls |
|---|---|---|---|---|---|
| Attached compact | `header.payload.signature` | `BASE64URL(payload)` | `b64` absent | `profile=COMPACT` | Compact; Unencoded Detached Payload unchecked; Appendix F unchecked |
| Compact detached / Appendix F | `header..signature` | `BASE64URL(exact-body-bytes)` | `b64` absent and not in `crit` | `profile=COMPACT_DETACHED` | Compact; Unencoded Detached Payload checked; Appendix F checked |
| Compact detached unencoded | `header..signature` | Exact raw body bytes | `b64=false`; `crit` contains `b64` | `profile=COMPACT_DETACHED_UNENCODED` | Compact; Unencoded Detached Payload checked; Appendix F unchecked |

> **Key point:** `COMPACT_DETACHED` and Appendix F are the same effective wire/signing behavior. `COMPACT_DETACHED` is the common KVM profile. “Enforce Appendix F” is only the original Akana checkbox used to map into that profile.

The HTTP body remains unchanged in both detached rows. Only the payload representation used to calculate the signature changes.

### 6.2 Approach A: Apigee-created configuration

This approach is created directly in the new UI or configuration API.

```json
{
  "configVersion": 2,
  "configurationModel": "APIGEE_NATIVE",
  "flags": {
    "jwsVerify": true,
    "jwsGenerate": true,
    "jwsFault": true,
    "requestDecryption": true,
    "responseEncryption": true,
    "faultEncryption": true
  },
  "privateKeyIdentifier": "space",
  "jws": {
    "algorithm": "PS256",
    "profile": "COMPACT_DETACHED",
    "source": {
      "location": "HEADER",
      "name": "x-jws-signature"
    },
    "headerValidation": {
      "cty": "application/json"
    },
    "criticalHeaders": [],
    "openBanking": {
      "enabled": true,
      "version": "3.1"
    }
  },
  "jwe": {
    "key": "RSA-OAEP-256",
    "content": "A256GCM",
    "headerValidation": {},
    "criticalHeaders": []
  }
}
```

Characteristics:

- the KVM directly states the effective behavior;
- `COMPACT_DETACHED` already represents Appendix F;
- there is no `enforceAppendixF` field;
- there is no `unencodedDetachedPayload` field;
- fewer contradictory configurations are possible; and
- the UI presents the three actual runtime behaviors.

### 6.3 Approach B: Akana-migrated configuration

This approach is produced by converting an exported Akana JOSEv2 policy. The resulting KVM uses the same profile values and field names as Approach A.

```json
{
  "configVersion": 2,
  "configurationModel": "AKANA_COMPATIBLE",
  "flags": {
    "jwsVerify": true,
    "jwsGenerate": true,
    "jwsFault": true,
    "requestDecryption": true,
    "responseEncryption": true,
    "faultEncryption": true
  },
  "privateKeyIdentifier": "space",
  "jws": {
    "algorithm": "PS256",
    "profile": "COMPACT_DETACHED",
    "source": {
      "location": "HEADER",
      "name": "x-jws-signature"
    },
    "headerValidation": {
      "cty": "application/json"
    },
    "criticalHeaders": [],
    "openBanking": {
      "enabled": true,
      "version": "3.1"
    }
  },
  "jwe": {
    "key": "RSA-OAEP-256",
    "content": "A256GCM",
    "headerValidation": {},
    "criticalHeaders": []
  }
}
```

Characteristics:

- the KVM directly states the effective behavior;
- `COMPACT_DETACHED` already represents Appendix F;
- there is no `enforceAppendixF` field;
- there is no `unencodedDetachedPayload` field;
- fewer contradictory configurations are possible;
- the UI presents the same three actual runtime behaviors; and
- the migration report retains the original Akana checkbox values as evidence instead of carrying them into runtime configuration.

### 6.4 Akana conversion logic

The migration converter maps the source Akana controls once:

```text
Compact + Unencoded Detached Payload unchecked
    → profile = COMPACT

Compact + Unencoded Detached Payload checked + Enforce Appendix F checked
    → profile = COMPACT_DETACHED

Compact + Unencoded Detached Payload checked + Enforce Appendix F unchecked
    → profile = COMPACT_DETACHED_UNENCODED
```

After conversion, the shared flow consumes only `jws.profile`. It does not need to know the original checkbox combination.

### 6.5 Open Banking comparison

Open Banking is an overlay on a detached JWS profile.

| Open Banking behavior | Common KVM settings | Original Akana policy controls | Effective `crit` |
|---|---|---|---|
| Encoded detached, documented Akana default | `profile=COMPACT_DETACHED`, `openBanking.enabled=true` | Unencoded Detached Payload checked; Enforce Appendix F checked; Open Banking checked | `iat`, `iss`, `tan`; no `b64` |
| Raw detached, only when explicitly required by a source Akana policy | `profile=COMPACT_DETACHED_UNENCODED`, `openBanking.enabled=true` | Unencoded Detached Payload checked; Enforce Appendix F unchecked; Open Banking checked | `b64`, `iat`, `iss`, `tan` |

Both rows require:

```text
source.location = HEADER
source.name = x-jws-signature
algorithm = PS256
openBanking.version = 3.1
```

For a new Open Banking configuration, default to `COMPACT_DETACHED`.

### 6.6 Decision comparison

| Decision factor | Approach A: Apigee-created | Approach B: Akana-migrated |
|---|---|---|
| KVM schema | Common three-profile schema | Same common three-profile schema |
| Creation path | User/UI selects the effective profile | Converter derives the profile from Akana checkboxes |
| Runtime behavior | Read directly from `jws.profile` | Read directly from `jws.profile` |
| Appendix F representation | `profile=COMPACT_DETACHED` | `profile=COMPACT_DETACHED` after conversion |
| Invalid-state risk | Low | Low after converter validation |
| Migration audit | Configuration history | Source checkbox values retained in migration evidence |
| Shared-flow implementation | Common | Common |

`configurationModel` records configuration provenance. It must not change cryptographic behavior. At runtime, the shared flow uses `jws.profile` directly and does not maintain a separate normalized KVM.

## 7. Protected-header validation model

### 7.1 Static key/value validation

`headerValidation` is a JSON object:

```json
{
  "typ": "JOSE",
  "cty": "application/json",
  "x-message-profile": "payments-v1"
}
```

For inbound verification or decryption, each configured entry means:

1. the parameter must be in the protected JOSE header;
2. its JSON type must match the configured type; and
3. its value must strictly equal the configured value, compared case-sensitively.

For outbound or fault generation, the shared flow adds the same configured entries to the protected header.

The first implementation supports string, number, and boolean values. Arrays and objects are rejected in configuration unless a later requirement defines unambiguous comparison semantics.

### 7.2 Runtime-managed parameters

The following names must not be accepted in `headerValidation`:

- `alg`;
- `kid`;
- `crit`;
- `b64`; and
- `enc`.

They are derived as follows:

| Parameter | Runtime source |
|---|---|
| JWS `alg` | `jws.algorithm` |
| JWE `alg` | `jwe.key` |
| JWE `enc` | `jwe.content` |
| `kid` | trusted key resolver or configured signing-key identifier |
| `b64` | effective JWS mode |
| `crit` | profile rules plus configured custom critical headers |

This restriction prevents contradictory configuration such as `profile=COMPACT_DETACHED_UNENCODED` with `headerValidation.b64=true`.

### 7.3 Direction behavior

The initial schema applies the same static map in all enabled directions:

- `IN`: values are validated;
- `OUT`: values are generated; and
- `FAULT`: values are generated.

Before migration, inventory Akana policies for different IN and OUT private-header values. If such policies exist, extend the schema explicitly with `in`, `out`, and `fault` maps rather than introducing hidden direction-specific behavior.

## 8. Critical-header (`crit`) design

Configure only custom critical headers. The shared flow adds the profile-required ones.

```json
{
  "headerValidation": {
    "x-message-profile": "payments-v1"
  },
  "criticalHeaders": [
    "x-message-profile"
  ]
}
```

The effective `crit` is built as:

```text
effectiveCrit = configured criticalHeaders
    + b64                         (only for COMPACT_DETACHED_UNENCODED)
    + http://openbanking.org.uk/iat, iss, tan   (only when Open Banking 3.1 is enabled)
```

Configuration rules:

- every name in `criticalHeaders` must also exist in `headerValidation`;
- `criticalHeaders` must not contain `b64` or the Open Banking URI names; and
- do not derive critical-header names from an untrusted inbound `tan`.

Inbound validation after signature verification:

- `crit` must be present when `effectiveCrit` is non-empty;
- `crit` must be a JSON array of unique, non-empty strings;
- every `crit` member must also appear as a protected header;
- every expected member must be present, and every incoming member must be in `effectiveCrit`;
- `b64` must be `false` and present in `crit` only for `COMPACT_DETACHED_UNENCODED`;
- `b64` must be absent from the header and `crit` for the other two modes; and
- `crit` comparison is order-independent.

Outbound and fault generation:

- generate `crit` from `effectiveCrit`, or omit it when empty;
- add every referenced protected header before signing; and
- never accept a caller-provided `crit` value.

## 9. UK Open Banking 3.1 defaults

### 9.1 Activation

```json
{
  "openBanking": {
    "enabled": true,
    "version": "3.1"
  }
}
```

Enabling Open Banking automatically activates all rules in this section. There is no separate `validateCrit`, `validateIat`, `validateIss`, or `validateTan` switch.

### 9.2 Profile checks

When Open Banking is enabled:

- the effective JWS mode must be detached;
- `COMPACT` must fail configuration validation;
- the default effective mode is `COMPACT_DETACHED` or `COMPACT_DETACHED_UNENCODED`;
- the algorithm must be `PS256`;
- the default JWS source is `HEADER` with name `x-jws-signature`, and any configured source must match it for the strict Akana Open Banking profile;
- the version must be `3.1`;
- `iat`, `iss`, and `tan` are mandatory protected headers;
- `iat`, `iss`, and `tan` are mandatory members of `crit`; and
- unknown critical headers are rejected unless explicitly configured and understood.

For inbound `typ`:

- it is optional according to the Akana Open Banking 3.1 documentation;
- if present, it must equal `JOSE`.

For generation, add:

```json
{
  "typ": "JOSE"
}
```

For inbound `cty`:

- profile handling accepts the Akana-supported JSON media values when it is present;
- an explicit `headerValidation.cty` entry makes that exact value mandatory; and
- generated `cty` should use the actual response media type, normally `application/json`.

### 9.3 Open Banking with encoded detached content

Effective mode:

```text
COMPACT_DETACHED
```

Required behavior:

```text
transported JWS = protected..signature
signing payload representation = BASE64URL(exact-body-bytes)
b64 = absent
crit = configured custom entries + iat + iss + tan
```

### 9.4 Open Banking with raw detached content

Effective mode:

```text
COMPACT_DETACHED_UNENCODED
```

Required behavior:

```text
transported JWS = protected..signature
signing payload representation = exact-body-bytes
b64 = false
crit = b64 + configured custom entries + iat + iss + tan
```

This mode is used only when an imported Akana policy explicitly has unencoded detached payload enabled and Appendix F disabled. The UI default for a new Open Banking configuration remains encoded detached/Appendix F.

### 9.5 `iat` validation and generation

Akana case `01676299` currently confirms:

- `iat` is a UTC NumericDate expressed as seconds since the Unix epoch;
- it must be represented as a JSON number;
- Akana applies a 120-second clock-skew allowance; and
- Akana has not identified a maximum-age or staleness check.

Inbound validation:

```text
reject if iat > floor(currentTimeMillis / 1000) + 120
```

No lower-age boundary is added:

```text
maximumIatAgeSeconds = null
```

Outbound/fault generation:

```text
iat = floor(currentTimeMillis / 1000)
```

Do not use milliseconds and do not generate a JSON string.

The lack of a maximum-age check is an Akana-parity decision. Replay and idempotency controls must be handled separately rather than changing `iat` behavior silently.

### 9.6 `tan` source and validation

`tan` is environment configuration. It must be stored once in a centrally managed, environment-scoped KVM and must not be repeated in every proxy KVM.

Recommended environment KVM name:

```text
jose-environment-config
```

Recommended structure for the PROD Live deployment environment:

```json
{
  "openBanking": {
    "3.1": {
      "tan": "openbanking.org.uk",
      "allowedFutureIatSeconds": 120,
      "maximumIatAgeSeconds": null
    }
  }
}
```

Recommended structure for every sandbox or non-production deployment environment:

```json
{
  "openBanking": {
    "3.1": {
      "tan": "openbankingtest.org.uk",
      "allowedFutureIatSeconds": 120,
      "maximumIatAgeSeconds": null
    }
  }
}
```

Required values:

| Deployment environment | `tan` |
|---|---|
| PROD Live | `openbanking.org.uk` |
| PROD Sandbox | `openbankingtest.org.uk` |
| SIT Live | `openbankingtest.org.uk` |
| SIT Sandbox | `openbankingtest.org.uk` |
| NFT Live | `openbankingtest.org.uk` |
| NFT Sandbox | `openbankingtest.org.uk` |

This design assumes each listed deployment environment has an independent environment-scoped KVM value or deployment-specific KVM alias. If two listed deployments share one physical Apigee environment, provisioning must still give each deployment an unambiguous KVM binding because there is no proxy-level selector.

Runtime behavior:

1. Read `openBanking.3.1.tan` from the current environment-scoped KVM.
2. Resolve exactly one expected `tan`.
3. Fail as a configuration error if the value is missing or empty.
4. On IN, compare the protected `tan` value exactly.
5. On OUT/FAULT, generate the protected `tan` value from the same trusted configuration.

Do not:

- accept both production and test values in one deployment;
- take the expected value from the incoming JWS;
- use inbound `tan` alone to construct or select a JWKS URL; or
- silently fall back to `openbanking.org.uk` when the environment KVM is missing.

The values are not secrets, but their integrity and promotion must be controlled through CI/CD or infrastructure-as-code.

### 9.7 `iss` validation

Confirmed behavior so far:

- `iss` is mandatory for the Open Banking profile;
- it must be a string;
- it must be present in `crit`; and
- Akana OBSeal uses information associated with the JWKS URI context path as part of validation.

Still awaiting confirmation:

- the exact JWKS context-path extraction;
- whether and how Organisation ID is included;
- whether and how Software Statement ID is included;
- delimiters and normalization;
- certificate-subject fallback behavior; and
- differences between IN and OUT/FAULT generation.

Implementation requirement:

- create a dedicated issuer-validation component with a strategy interface;
- require the header and `crit` entry immediately;
- do not implement Organisation ID-only matching as the final rule;
- do not accept arbitrary `iss` values in production; and
- block Open Banking production acceptance until case `01676299` resolves the exact rule and parity tests pass.

A critical header is not fully processed by checking presence alone. The implementation cannot claim full Open Banking parity until `iss` semantics are enforced.

## 10. JWE configuration and header validation

### 10.1 Common configuration

```json
{
  "jwe": {
    "key": "RSA-OAEP-256",
    "content": "A256GCM",
    "headerValidation": {
      "cty": "application/json"
    },
    "criticalHeaders": []
  }
}
```

### 10.2 JWE checks

For inbound JWE processing:

- protected `alg` must equal `jwe.key`;
- protected `enc` must equal `jwe.content`;
- `kid`, when required by the selected key strategy, must resolve to a trusted decryption key;
- every configured `headerValidation` entry must exist and match exactly;
- every JWE `crit` member must be understood and processed;
- unsupported `zip`, external AAD, or serialization options must fail closed; and
- plaintext must not be used until authenticated decryption succeeds.

For outbound/fault JWE processing:

- set `alg` and `enc` from trusted configuration;
- select the recipient key through trusted metadata;
- add configured protected headers;
- derive `crit` from configured JWE critical headers;
- encrypt only the finalized message body; and
- replace or wrap content exactly as defined by the confirmed Akana parity behavior.

## 11. Configuration checks

### 11.1 Common runtime KVM checks

These checks apply to both `APIGEE_NATIVE` and `AKANA_COMPATIBLE` because both use the same final schema.

```text
jws.profile must be one of:
    COMPACT
    COMPACT_DETACHED
    COMPACT_DETACHED_UNENCODED

unencodedDetachedPayload must be absent
enforceAppendixF must be absent
source is required when any JWS scope is enabled

if source.location is HEADER:
    source.name is required

if source.location is MESSAGE_BODY:
    source.name must be message.content

if jws.profile is COMPACT_DETACHED or COMPACT_DETACHED_UNENCODED:
    source.location must be HEADER

if openBanking.enabled is true:
    jws.profile must be COMPACT_DETACHED or COMPACT_DETACHED_UNENCODED
    algorithm must be PS256
    source.location must be HEADER
    source.name must be x-jws-signature for the strict migrated profile
    version must be 3.1
    environment TAN resolution must succeed
```

### 11.2 Akana migration-converter checks

The following checks apply to the source Akana policy before the converter emits the common KVM:

```text
source serialization must be Compact
source Unencoded Detached Payload must be checked or unchecked
source Enforce Appendix F must be checked or unchecked

if Unencoded Detached Payload is unchecked:
    Enforce Appendix F must be unchecked
    output profile is COMPACT

if Unencoded Detached Payload is checked and Enforce Appendix F is checked:
    output profile is COMPACT_DETACHED

if Unencoded Detached Payload is checked and Enforce Appendix F is unchecked:
    output profile is COMPACT_DETACHED_UNENCODED
```

Runtime KVM configuration must be explicit. Defaults must be materialized when the UI or converter saves configuration so runtime behavior is reviewable.

For new Open Banking configurations, both approaches default to `COMPACT_DETACHED`. An imported Akana source policy with Appendix F disabled maps to `COMPACT_DETACHED_UNENCODED` and applies the RFC 7797 Open Banking rules.

## 12. Observability and audit

Record:

- proxy name and revision;
- environment;
- `configurationModel`;
- effective JWS mode;
- Open Banking enabled/version;
- protection scope;
- algorithm identifiers;
- `kid` or a non-sensitive key fingerprint;
- validation result and internal fault category;
- JWKS cache hit, refresh, or miss;
- elapsed time; and
- correlation/request ID.

Never log:

- private keys;
- private-key passwords;
- full JWS/JWE values in production;
- decrypted sensitive payloads;
- complete customer request/response bodies; or
- access tokens.

Recommended metrics:

```text
jose_jws_verify_total{profile,result}
jose_jws_generate_total{profile,result}
jose_jwe_decrypt_total{result}
jose_jwe_encrypt_total{result}
jose_header_validation_failure_total{header}
jose_crit_validation_failure_total{reason}
jose_ob_validation_failure_total{claim,reason}
jose_jwks_refresh_total{result}
jose_operation_duration_ms{operation,profile}
```

Ensure metric labels do not contain unbounded client values.

## 13. UI implementation plan

### 13.1 Common UI behavior

- Store booleans as booleans.
- For `MESSAGE_BODY`, set `source.name` to `message.content` and do not expose an editable name.
- For `HEADER`, require an editable or profile-defaulted HTTP header name.
- Display the resulting effective mode and signing-input behavior.
- Display derived headers as read-only values.
- Validate before save.
- Send configuration to a backend validation endpoint.
- Show environment-derived `tan` as read-only.
- Warn that `iss` remains pending until the Akana rule is confirmed.
- Prevent users from entering private key material.

### 13.2 Header editor

Use a table with:

| Field | Behavior |
|---|---|
| Header name | Text input |
| Type | String, number, or boolean |
| Expected/generated value | Typed input |
| Critical | Checkbox |

Save ordinary rows into `headerValidation`. Save checked names into `criticalHeaders`.

Reserved names must be blocked in the editor:

```text
alg, kid, crit, b64, enc
```

Show profile-managed Open Banking headers separately:

```text
http://openbanking.org.uk/iat
http://openbanking.org.uk/iss
http://openbanking.org.uk/tan
```

They must not be editable as ordinary static rows.

### 13.3 Profile selection and Open Banking defaults

Present one profile selector:

```text
COMPACT
COMPACT_DETACHED
COMPACT_DETACHED_UNENCODED
```

Selecting Open Banking:

- enables version 3.1;
- defaults profile to `COMPACT_DETACHED`;
- defaults algorithm to `PS256`;
- defaults `source.location` to `HEADER` and `source.name` to `x-jws-signature`;
- enables automatic `crit` validation;
- displays the resolved environment `tan`; and
- explains the 120-second future `iat` allowance and absence of a maximum age.

Allow `COMPACT_DETACHED_UNENCODED` only when the migration/product decision permits the Akana raw Open Banking behavior. Make the signing-input difference visible.

For an imported Akana policy, the converter preselects the effective profile and shows the original source controls as read-only migration evidence. The original detached and Appendix F checkboxes are not stored in the runtime KVM.

## 14. Migration mapping

### 14.1 Akana source controls to common profile

```text
Akana Compact + detached unchecked
    → profile = COMPACT

Akana Compact + unencoded detached checked + Appendix F checked
    → profile = COMPACT_DETACHED

Akana Compact + unencoded detached checked + Appendix F unchecked
    → profile = COMPACT_DETACHED_UNENCODED

Akana UK Open Banking 3.1
    → openBanking.enabled = true
    → openBanking.version = 3.1
    → profile = COMPACT_DETACHED by default when Appendix F was checked
    → tan resolved from the target environment KVM
```

### 14.2 Other source-field mapping

```text
Akana detached Header Parameter Name
    → source.location = HEADER
    → source.name = configured Akana header name

Akana attached compact message
    → source.location = MESSAGE_BODY
    → source.name = message.content

Akana Signature Algorithm
    → jws.algorithm

Akana Private Headers
    → jws.headerValidation and jws.criticalHeaders as applicable

Akana Protection Scope
    → flags.jwsVerify, flags.jwsGenerate and flags.jwsFault
```

The converter validates the source controls, emits only the common profile schema, and stores the original checkbox values in migration evidence rather than in the runtime KVM.

### 14.3 Migration evidence

For each proxy, retain:

- source Akana policy identifier and export;
- source option values;
- generated KVM configuration;
- normalized effective mode;
- key/JWKS mapping reference;
- environment KVM mapping;
- test-vector results;
- exceptions; and
- reviewer/sign-off details.

## 15. Acceptance criteria

The implementation is complete when:

1. Both configuration creation paths use the same schema and profile values.
2. `configurationModel` records provenance only and does not change runtime behavior.
3. All three JWS profiles work for enabled scopes.
4. Detached Open Banking is enforced.
5. Encoded and raw detached signing inputs are not confused.
6. Static protected headers are validated with strict JSON types and values.
7. `crit` is derived, validated, and generated correctly.
8. Open Banking `iat` follows the confirmed 120-second future allowance with no maximum age.
9. Open Banking `tan` resolves from controlled environment configuration and passes the full matrix.
10. Open Banking `iss` parity is confirmed and implemented.
11. JWS is read from and written to the configured `source`; `MESSAGE_BODY` always resolves to `message.content`.

## 16. Final recommendation

Implement one common KVM schema and one JOSE runtime with two configuration creation paths:

- let users create the three effective profiles directly for new Apigee proxies;
- convert original Akana detached and Appendix F checkboxes into the same three profiles during migration;
- retain original Akana option values only in migration evidence;
- treat `configurationModel` as provenance, not a runtime behavior switch;
- keep protected-header key/value validation common;
- derive all mandatory `crit`, `b64`, and Open Banking behavior from `jws.profile`;
- use an environment KVM for `tan` and profile constants; and
- keep `iss` as a production blocker until Akana confirms the full rule.

This structure gives stakeholders a direct Akana-to-profile comparison while keeping one unambiguous runtime configuration.

---

Content from external references was rephrased for compliance with licensing restrictions.
