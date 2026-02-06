import json
import os

from decouple import config

MAX_REPO = 3
SOURCE_REPO = "stacks-sbtc/wsts"
run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    # Convert to cyclic index (1-100)
    run_index = get_cyclic_index(run_number, MAX_REPO)
    # Format the URL with leading zeros
    repo_number = f"{run_index:03d}"
    BASE_URL = f"https://deepwiki.com/grass-dev-pa/wsts-{repo_number}"


scope_files = [
    'src/common.rs',
    'src/compute.rs',
    'src/errors.rs',
    'src/lib.rs',
    'src/main.rs',
    'src/net.rs',
    'src/schnorr.rs',
    'src/state_machine/coordinator/fire.rs',
    'src/state_machine/coordinator/frost.rs',
    'src/state_machine/coordinator/mod.rs',
    'src/state_machine/mod.rs',
    'src/state_machine/signer/mod.rs',
    'src/taproot.rs',
    'src/traits.rs',
    'src/util.rs',
    'src/v1.rs',
    'src/v2.rs',
    'src/vss.rs',
]





def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific WSTS file.

    Args:
        target_file: The specific file path to focus question generation on
            (e.g., "src/v2.rs" or "src/state_machine/coordinator/mod.rs")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""
# Generate 150+ Targeted Security Audit Questions for WSTS

## Context

The target project is WSTS, a Rust implementation of Weighted Schnorr Threshold Signatures.
WSTS extends FROST to support weighted signers, where each signer controls multiple key IDs.
The protocol provides distributed key generation (DKG), signature share generation, and
signature aggregation, with optional BIP-340/341 taproot-compatible Schnorr proofs.

WSTS includes:
- FROST-style DKG with polynomial commitments and Schnorr ID proofs.
- Weighted signing with Lagrange interpolation over key IDs.
- Aggregation of signature shares into group signatures.
- Networked state machines (coordinator and signer) with message signing and timeouts.
- Taproot/Schnorr proof support and key tweaks.
- Diffie-Hellman + AES-GCM encryption for private share exchange.

## Scope

CRITICAL TARGET FILE: Focus question generation EXCLUSIVELY on `{target_file}`

Note: The questions must be generated from `{target_file}` only. If you cannot generate
enough questions from this single file, provide as many quality questions as you can
extract from the file's logic and interactions. DO NOT return empty results.

If a file is more than a thousand lines you can generate as many as 300+ questions, but
always generate as many as you can - do not give other responses.

## Full Context - Critical WSTS Components (for reference only)

core_components = [
    "src/common.rs",
    "src/compute.rs",
    "src/errors.rs",
    "src/net.rs",
    "src/schnorr.rs",
    "src/taproot.rs",
    "src/traits.rs",
    "src/util.rs",
    "src/v1.rs",
    "src/v2.rs",
    "src/vss.rs",
    "src/state_machine/mod.rs",
    "src/state_machine/coordinator/mod.rs",
    "src/state_machine/coordinator/fire.rs",
    "src/state_machine/coordinator/frost.rs",
    "src/state_machine/signer/mod.rs",
]

## WSTS Architecture and Critical Security Layers

1) DKG and Polynomial Commitments
   - Polynomial commitments with Schnorr ID proofs bound to context
   - Private share distribution and verification against public commitments
   - Threshold and key ID validation (weighted threshold in keys, not signers)

2) Weighted Signing and Aggregation
   - Nonce generation and binding values
   - Lagrange interpolation over key IDs
   - Signature share validation and aggregation
   - Handling duplicate or missing key IDs and signer IDs

3) State Machine and Network Protocol
   - Coordinator and signer state transitions
   - Message signing and verification
   - Timeouts, retries, and malicious signer detection
   - DKG and signing round IDs and iteration IDs

4) Taproot and Schnorr Compatibility
   - BIP-340 challenge computation and parity rules
   - BIP-341 key tweaks, taproot merkle root binding
   - Consistency between tweaked keys and signature shares

5) Cryptographic Primitives and Serialization
   - Scalar reduction and point validation
   - Diffie-Hellman shared secrets and AES-GCM encryption
   - Hash domain separation and transcript binding

## Critical Security Invariants

DKG Invariants
- Public polynomial commitments must verify and match the claimed polynomial degree.
- Schnorr ID proofs must bind party ID and polynomial constant to the context.
- All required private shares must exist and verify against commitments.
- Threshold and key ID ranges must be validated (no duplicates, no out of range IDs).
- Aggregated group public key must match sum of valid polynomial constants.

Signing Invariants
- Nonces must be non-zero and never reused across rounds or messages.
- Binding values must be derived from all public nonces and the exact message.
- Lagrange interpolation must use the correct key ID set with no duplicates.
- Signature shares must correspond to the correct party IDs and nonces.
- Aggregated signature must verify for the correct group public key or tweaked key.

Taproot/Schnorr Invariants
- Even-Y parity rules must be applied consistently for R and public keys.
- Tweaks must be added with correct sign adjustments for BIP-340/341.
- Schnorr proof verification must reject invalid points or x-coordinates.

State Machine Invariants
- State transitions must enforce ordering (no skipping DKG steps).
- Round IDs (dkg_id, sign_id, sign_iter_id) must match expected values.
- Malicious signer detection should not be bypassable by message ordering.
- Timeouts must not allow accepting partial or inconsistent sets.

## In-Scope Vulnerability Categories (WSTS)

Critical Severity
- Signature forgery (invalid shares accepted, aggregation bypass)
- Threshold bypass (fewer keys or signers produce a valid signature)
- Key compromise via nonce reuse or incorrect binding
- Taproot/Schnorr proof bypass leading to unauthorized signatures
- DKG poisoning that results in attacker-controlled group key

High Severity
- DKG share validation bypass (bad shares accepted as valid)
- Malicious signer can cause honest signers to compute wrong secrets
- Coordinator or signer state machine desync allowing invalid steps
- Message signature verification bypass for network packets
- Cryptographic point validation failures enabling rogue keys

Medium Severity
- DoS via malformed messages, oversized inputs, or expensive verification paths
- Incorrect handling of duplicate IDs or edge-case key sets
- Non-deterministic or inconsistent transcript binding
- Panic or unwrap on untrusted network data

## Question Format Template

Each question MUST follow this Python list format:

questions = [
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact with severity category?",
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",
]

## Output Requirements

Generate security audit questions focusing EXCLUSIVELY on `{target_file}` that:

- Target ONLY `{target_file}` - all questions must reference this file
- Reference specific functions, methods, structs, or logic sections within `{target_file}`
- Describe concrete attack vectors (not vague "could there be a bug?")
- Tie to impact categories (forgery, threshold bypass, key leak, DoS)
- Include severity classification (Critical/High/Medium/Low)
- Respect WSTS protocol rules and weighted threshold semantics
- Cover math logic, protocol business logic, valid scenarios, and invariants
- Focus on realistic vulnerabilities, avoid out-of-scope questions
- Consider Rust-specific issues (panic on untrusted data, integer conversion, unsafe code)

## Target Question Count

- Large critical files (>1000 lines): aim for 150-300 questions
- Medium files (500-1000 lines): aim for 80-150 questions
- Small files (<500 lines): aim for 30-80 questions
- Provide as many quality questions as the file's complexity allows

Begin generating questions for `{target_file}` now.
"""
    return prompt


def question_format(security_question: str) -> str:
    """
    Generate a comprehensive security audit prompt for WSTS.

    Args:
        security_question: The specific security concern to investigate

    Returns:
        A detailed audit prompt with validation requirements
    """
    prompt = f"""# WSTS SECURITY AUDIT PROMPT

## Security Question to Investigate:
{security_question}

## Codebase Context

You are auditing WSTS, a Rust implementation of Weighted Schnorr Threshold Signatures.
WSTS extends FROST so each signer can control multiple key IDs (weighted threshold).
The protocol builds a distributed key generation (DKG) flow, generates signature shares,
and aggregates them into a group signature. It also supports BIP-340/341 style Schnorr
proofs and taproot key tweaks.

Core protocol flow (high level):
1) DKG: parties create polynomial commitments and exchange private shares.
2) Secret derivation: parties validate shares and derive private keys + group public key.
3) Signing: parties create nonces, compute binding values, sign message shares.
4) Aggregation: coordinator aggregates shares and verifies group signature or proof.

## Critical Components (reference only)

- DKG, polynomials, commitments: src/v1.rs, src/v2.rs, src/vss.rs, src/common.rs
- Signing math and binding: src/compute.rs, src/schnorr.rs, src/taproot.rs
- Aggregation and validation: src/v1.rs, src/v2.rs, src/traits.rs
- State machines and network protocol: src/state_machine/*, src/net.rs
- Encryption and DH key exchange: src/util.rs

## Critical Security Invariants

DKG invariants:
- Public polynomial commitments must verify and match declared degrees.
- Schnorr ID proofs must bind the party ID and polynomial constant to context.
- All expected private shares must be present and verify against commitments.
- Group public key must equal the sum of valid polynomial constants.
- Threshold and key ID bounds must be enforced; no duplicates or out-of-range IDs.

Signing invariants:
- Nonces must be non-zero and never reused across messages or rounds.
- Binding values must commit to all public nonces and the exact message.
- Lagrange interpolation must use the correct key set with no duplicates.
- Signature shares must be consistent with party IDs, nonces, and key ownership.
- Aggregated signatures must verify under the correct group or tweaked public key.

Taproot/Schnorr invariants:
- Even-Y parity rules must be applied consistently to R and public keys.
- BIP-341 tweak must be applied with correct sign adjustments.
- Schnorr proof verification must reject invalid points and x-coordinates.

State machine invariants:
- State transitions must be ordered and unskippable for DKG and signing.
- Round IDs (dkg_id, sign_id, sign_iter_id) must match expected values.
- Malicious signer detection and timeouts must not be bypassable.
- Message authentication must be enforced where configured.

## Protocol Scope (Severity / Impact Definitions)

Critical:
- Any network to shut down or otherwise not confirm new valid transactions for multiple blocks
- Any triggering of a deep fork of 10 or more blocks without spending the requisite Bitcoin
- Any causing the direct loss of funds other than through any form of freezing
- Any chain split caused by different nodes processing the same block or transaction and yielding different results
- Any confirmation of an invalid transaction, such as with an incorrect nonce

High:
- Any unintended chain split or network partition
- Any remotely-exploitable memory access, disk access, or persistent code execution
  (attacks restricted to the Stacks blockchain RPC/P2P ports)

Medium:
- Any transient consensus failures

Low:
- Any remotely-exploitable denial of service in a node
- Any network denial of service impacting more than 10 percent of miners that does not shut down the network

You must map WSTS vulnerabilities to these impact definitions. If the issue cannot be
reasonably connected to an in-scope impact above, it is out of scope.

## Attack Surfaces to Inspect for This Question

1) DKG share validation and commitment checks
2) Nonce generation, binding, and signature share computation
3) Aggregation, signature verification, and tweak handling
4) Coordinator/signer state machines, timeouts, and message authenticity
5) Network message formats, serialization, and signature verification
6) Cryptographic primitives: scalar math, point validation, hash binding
7) Encryption/DH key exchange for private shares

## Vulnerability Validation Requirements

A finding is ONLY valid if it passes ALL checks below.

Impact assessment (must be concrete):
- Tie impact to the protocol scope above.
- Identify what breaks: invalid signatures accepted, key control lost, or
  chain-level impact in dependent systems.
- Quantify impact with realistic parameters.

Likelihood assessment (must be practical):
- Provide exact prerequisites (attacker position, access, required secrets).
- Show a realistic path that does not assume cryptographic breaks.
- Demonstrate feasibility with reasonable resources and timing.

Validation checklist:
1) Exact code location (file path, function, line numbers if possible)
2) Root cause analysis (why the bug exists)
3) Exploitation path (step-by-step)
4) Realistic parameters (no theoretical-only attacks)
5) Proof of concept or concrete exploit algorithm
6) Clear impact mapping to the scope above
7) No dependency on breaking secp256k1, SHA-256, or other primitives
8) Existing mitigations reviewed and shown ineffective

## Audit Report Format

If a valid vulnerability is found, return ONLY this format:

### Title
[Concise, descriptive title of the vulnerability]

### Summary
[2-3 sentence executive summary of the vulnerability and its impact]

### Finding Description
[Detailed technical description including:
- Exact code location (file path, function, line numbers)
- Root cause explanation
- Why existing mitigations fail
- Relevant code context]

### Impact Explanation
[Concrete impact assessment:
- What specific harm occurs?
- Quantify the impact (funds lost, invalid signatures, chain impact)
- Who is affected?
- Severity justification aligned to scope]

### Likelihood Explanation
[Realistic exploitation analysis:
- Required attacker capabilities
- Attack complexity
- Economic feasibility
- Detection risk
- Estimated probability of success]

### Recommendation
[Specific, actionable fix:
- Proposed code changes
- Alternative mitigations if needed
- Testing recommendations
- Deployment considerations]

### Proof of Concept
[Working exploit code or detailed algorithm:
- Exploitation steps
- Parameter values
- Expected vs actual behavior
- Reproduction instructions]

## Strict Output Requirement

If no valid vulnerability exists (theoretical only, missing prerequisites, mitigations work):
Output exactly:
"#NoVulnerability found for this question."

Do not output anything else, no preface or explanation.

Begin your investigation of: {security_question}
"""
    return prompt



def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for WSTS security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for strict technical scrutiny
    """
    prompt = f"""
You are an **Elite WSTS Security Judge** with deep expertise in FROST, weighted threshold
signatures, distributed key generation (DKG), Schnorr signatures, and protocol state
machines. Your ONLY task is **ruthless technical validation** of security claims against
the WSTS codebase.

Note: WSTS is a cryptographic library. Do not assume compromised developers, compromised
operators, or broken cryptography. Malicious signers are allowed only within the protocol
threat model (e.g., up to threshold-1), and claims must not require defeating secp256k1,
SHA-256, or other primitives.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **WSTS VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if ANY apply:

Note before a vulnerability can be considered valid it must have a valid impact and also
a valid likelihood that can be triggered or trigger validly on its own. If a vulnerability
cannot be triggered then it is invalid, except there is a logic vulnerability. This is
very important.

And your return must either be the report or `#NoVulnerability` because this is automated
and that's the only way I can understand.

Note this is the most important: any vuln with no valid impact to the protocol is invalid.
Any vuln that requires a user to self-harm or misuse the protocol outside expected inputs
is invalid.

#### **A. Scope Violations**
- ❌ Affects files not in WSTS production codebase (only `src/` is in scope)
- ❌ Targets test-only code (`#[cfg(test)]` blocks) or files in `tests/`, `benches/`, `target/`
- ❌ Claims about documentation, comments, code style, or logging only
- ❌ Focuses on external tooling, build scripts, or dev utilities

**In-Scope Components (examples):**
- Core protocol: `src/v1.rs`, `src/v2.rs`, `src/vss.rs`, `src/common.rs`
- Math/crypto: `src/compute.rs`, `src/schnorr.rs`, `src/taproot.rs`
- Protocol orchestration: `src/state_machine/*`, `src/net.rs`
- Utilities: `src/util.rs`, `src/traits.rs`, `src/errors.rs`

#### **B. Threat Model Violations**
- ❌ Requires compromised WSTS developers or signers outside the threat model
- ❌ Assumes coordinator private key or network keys are compromised without evidence
- ❌ Assumes underlying crypto primitives are broken (secp256k1, SHA-256, AES-GCM)
- ❌ Relies on social engineering, phishing, or key theft
- ❌ Depends on network-level attacks outside RPC/P2P ports

#### **C. Known Issues / Exclusions**
- ❌ Already known and fixed issues
- ❌ Issues in external dependencies without direct WSTS impact
- ❌ Pure performance claims without security impact
- ❌ Debug or test code paths only

#### **D. Non-Security Issues**
- ❌ Code style, naming, refactoring, or missing logs/events
- ❌ Minor precision errors with negligible impact
- ❌ "Best practices" suggestions with no concrete exploit

#### **E. Invalid Exploit Scenarios**
- ❌ Requires impossible inputs or invalid message formats
- ❌ Cannot be triggered through any realistic protocol usage
- ❌ Relies on calling internal functions not reachable in protocol flow
- ❌ Depends on breaking protocol assumptions (e.g., unlimited malicious signers)

### **PHASE 2: WSTS-SPECIFIC DEEP CODE VALIDATION**
#### **Step 1: Trace Complete Execution Path Through WSTS**
WSTS flow patterns:
1. DKG: commitments -> share distribution -> share verification -> group key derivation
2. Signing: nonce generation -> binding value -> share computation -> aggregation
3. Taproot/Schnorr: tweak derivation -> parity handling -> proof verification
4. State machines: coordinator/signer message flow with timeouts and IDs

For each claim, reconstruct the entire execution path:
1. Identify entry point (message handler, state transition, API call)
2. Follow internal calls and data transformations
3. Document state before exploit (keys, shares, nonces, IDs)
4. Enumerate checks and validations in order
5. Show exactly how the exploit bypasses or subverts protections
6. Show final state and security invariant violation

#### **Step 2: Validate Every Claim with Code Evidence**
For each assertion in the report, require:
- Exact file path and function names (line numbers if available)
- Direct code quotes of the vulnerable logic
- Call traces with concrete parameter values
- Proof that relevant invariant is broken (DKG, signing, state machine, or taproot)

**Red Flags (invalid unless proven):**
1) "Missing validation" claims:
- ❌ Invalid unless the claim shows no checks in `check_public_shares`,
     `PolyCommitment.verify`, or state machine validation.
2) "Nonce reuse" claims:
- ❌ Invalid unless report shows reuse across messages/rounds with same signer state.
3) "Threshold bypass" claims:
- ❌ Invalid unless report demonstrates incorrect Lagrange interpolation or key set handling.
4) "Aggregation bypass" claims:
- ❌ Invalid unless report shows `Signature::verify` or `SchnorrProof::verify` accepts invalid data.
5) "State machine desync" claims:
- ❌ Invalid unless report shows a reachable path that violates ordered transitions.

#### **Step 3: Known Issues and Fixes**
If the issue is already known, fixed, or a duplicate of documented behavior, reject.
If the report cannot prove the issue exists in current code, reject.

### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION (SCOPE ALIGNMENT)**
Impact must be concrete and align with the scope below. If not, reject.

Critical:
- Any network to shut down or otherwise not confirm new valid transactions for multiple blocks
- Any triggering of a deep fork of 10 or more blocks without spending the requisite Bitcoin
- Any causing the direct loss of funds other than through any form of freezing
- Any chain split caused by different nodes processing the same block or transaction
  and yielding different results
- Any confirmation of an invalid transaction, such as with an incorrect nonce

High:
- Any unintended chain split or network partition
- Any remotely-exploitable memory access, disk access, or persistent code execution
  (attacks restricted to the Stacks blockchain RPC/P2P ports)

Medium:
- Any transient consensus failures

Low:
- Any remotely-exploitable denial of service in a node
- Any network denial of service impacting more than 10 percent of miners
  that does not shut down the network

If the claim does not map to one of these impacts with a realistic integration
path, it is out of scope and must be rejected.

#### **Likelihood Reality Check**
- Attacker capabilities must be realistic and within the protocol threat model.
- Exploit must be triggered through normal protocol usage or message flow.
- No reliance on breaking cryptography or trusted roles.
- Economic feasibility must be plausible.

### **PHASE 4: FINAL VALIDATION CHECKLIST**
Before accepting any vulnerability, verify:
1. Scope compliance (production code, not tests)
2. Threat model alignment
3. Concrete impact aligned to scope
4. Technical feasibility with reproducible steps
5. Proof of concept or concrete exploit algorithm
6. Clear invariant break with code evidence
7. No out-of-scope assumptions

Remember: False positives harm credibility. Assume claims are invalid until
overwhelming evidence proves otherwise.

---

**AUDIT REPORT FORMAT** (if vulnerability found):

Audit Report

## Title
The Title Of the Report

## Summary
A short summary of the issue, keep it brief.

## Finding Description
A more detailed explanation of the issue. Poorly written or incorrect findings may result
in rejection and a decrease of reputation score.

Describe which security guarantees it breaks and how it breaks them. If this bug does not
automatically happen, showcase how a malicious input would propagate through the system to
the part of the code where the issue occurs.

## Impact Explanation
Elaborate on why you've chosen a particular impact assessment.

## Likelihood Explanation
Explain how likely this is to occur and why.

## Recommendation
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed
code here.

## Proof of Concept
Note very important the PoC must have a valid test that runs just one function that proves
the vuln.

**Now perform STRICT validation of the claim above.**

**Output ONLY:**
- A full audit report (if genuinely valid after passing all checks above) following the
  specified format
- `#NoVulnerability found for this question.` (if any check fails)
- Note if you cannot validate the claim or do not understand just send
  `#NoVulnerability found for this question.`
- Only show full report when you know this is actually and truly a valid vulnerability
"""
    return prompt

