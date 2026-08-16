//! DNSSEC negative-trust-anchor policy.
//!
//! systemd-resolved keeps positive and negative trust anchors in one ancestry
//! walk.  The walk starts at the queried owner name and proceeds toward the
//! root.  A negative anchor at the first matching name makes that name and all
//! descendants an insecure delegation island.  A positive DS or DNSKEY anchor
//! stops an inherited negative anchor, as required by RFC 7646, section 1.1.
//!
//! This module owns the policy decision only.  DNSKEY/DS chain construction,
//! signature verification, and NSEC/NSEC3 closest-encloser proofs remain in
//! the resolver's packet-validation pipeline.  Keeping those responsibilities
//! separate prevents an NTA from being mistaken for cryptographic proof and
//! ensures that an NTA can never authorize the AD bit.

use std::collections::BTreeSet;

/// DNSSEC validation mode exposed by resolved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnssecMode {
    /// Do not perform DNSSEC validation.
    No,
    /// Validate when possible, but permit an unsigned delegation when the
    /// upstream does not provide DNSSEC data.
    #[default]
    AllowDowngrade,
    /// Require DNSSEC validation and report validation failures as bogus.
    Yes,
}

impl DnssecMode {
    /// Whether this mode asks the resolver to perform DNSSEC validation.
    pub const fn validates(self) -> bool {
        !matches!(self, Self::No)
    }
}

/// A positive trust anchor owner.
///
/// The historical field is named `key` for source compatibility with the
/// initial scaffold.  It contains the owner name of a configured DS or
/// DNSKEY anchor; the actual RR material is consumed by the DNSSEC chain
/// validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    pub key: String,
}

impl TrustAnchor {
    /// Construct a positive trust anchor for `domain`.
    pub fn new(domain: impl Into<String>) -> Self {
        Self { key: domain.into() }
    }

    /// Return the configured owner name.
    pub fn domain(&self) -> &str {
        &self.key
    }
}

/// A DNSSEC negative trust anchor (NTA).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeTrustAnchor {
    pub domain: String,
}

impl NegativeTrustAnchor {
    /// Construct an NTA for `domain`.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
        }
    }
}

/// Input used to build an [`NtaValidator`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidatorConfig {
    pub mode: DnssecMode,
    pub trust_anchors: Vec<TrustAnchor>,
    pub ntas: Vec<NegativeTrustAnchor>,
}

/// A malformed DNS owner in an anchor list or query.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidatorError {
    #[error("invalid DNS name: {0}")]
    InvalidName(String),
}

/// Result of the positive/negative ancestry walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorMatch {
    /// The name is covered by an NTA and must not be DNSSEC validated.
    NegativeTrustAnchor,
    /// A positive DS/DNSKEY anchor applies at the nearest matching ancestor.
    PositiveTrustAnchor,
    /// No configured positive or negative anchor applies.
    None,
}

/// DNSSEC evidence/result used by [`NtaValidator::classify`].
///
/// This is deliberately the result of the chain validator, not an assertion
/// that an upstream AD bit is trustworthy.  In particular, `Secure` is only
/// produced by the packet validator after it has checked signatures and
/// denial proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationState {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
    NotValidated,
}

/// Canonical DNSSEC policy for global positive anchors and NTAs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtaValidator {
    mode: DnssecMode,
    positive: BTreeSet<CanonicalName>,
    negative: BTreeSet<CanonicalName>,
}

impl NtaValidator {
    /// Build a validator, rejecting malformed anchor names instead of
    /// silently creating an anchor with surprising scope.
    pub fn new(config: ValidatorConfig) -> Result<Self, ValidatorError> {
        let positive = config
            .trust_anchors
            .iter()
            .map(|anchor| CanonicalName::parse(anchor.domain()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let negative = config
            .ntas
            .iter()
            .map(|anchor| CanonicalName::parse(&anchor.domain))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            mode: config.mode,
            positive,
            negative,
        })
    }

    /// Construct a validator with no anchors and the default
    /// `allow-downgrade` mode.
    pub fn empty() -> Self {
        Self {
            mode: DnssecMode::default(),
            positive: BTreeSet::new(),
            negative: BTreeSet::new(),
        }
    }

    /// Return the configured validation mode.
    pub const fn mode(&self) -> DnssecMode {
        self.mode
    }

    /// Perform systemd-resolved's exact-name-to-root anchor lookup.
    pub fn lookup(&self, name: &str) -> Result<AnchorMatch, ValidatorError> {
        let mut candidate = Some(CanonicalName::parse(name)?);
        while let Some(current) = candidate {
            // systemd checks the NTA set before the positive set at each
            // owner.  This matters if an administrator deliberately places
            // both kinds of anchor at the same name.
            if self.negative.contains(&current) {
                return Ok(AnchorMatch::NegativeTrustAnchor);
            }
            if self.positive.contains(&current) {
                return Ok(AnchorMatch::PositiveTrustAnchor);
            }
            candidate = current.parent();
        }
        Ok(AnchorMatch::None)
    }

    /// Whether `name` is inside an insecure delegation island.
    pub fn is_insecure(&self, name: &str) -> Result<bool, ValidatorError> {
        Ok(matches!(
            self.lookup(name)?,
            AnchorMatch::NegativeTrustAnchor
        ))
    }

    /// Whether the chain validator should attempt DNSSEC for `name`.
    pub fn should_validate(&self, name: &str) -> Result<bool, ValidatorError> {
        Ok(self.mode.validates() && !self.is_insecure(name)?)
    }

    /// Apply NTA and mode policy to a chain-validation result.
    ///
    /// A name covered by an NTA is intentionally reported as
    /// `NotValidated`, not `Secure`: an NTA permits unsigned data but never
    /// creates cryptographic authentication.  Likewise, `DNSSEC=no` cannot
    /// preserve a `Secure` result received from an untrusted upstream.
    pub fn classify(
        &self,
        name: &str,
        state: ValidationState,
    ) -> Result<ValidationState, ValidatorError> {
        if !self.should_validate(name)? {
            return Ok(ValidationState::NotValidated);
        }
        Ok(state)
    }

    /// Whether the authenticated-data bit may be set for a response.
    ///
    /// The packet validator supplies `state`; this method enforces the policy
    /// side of AD legality.  AD is never legal for an NTA, for
    /// `DNSSEC=no`, or for a state other than `Secure`.
    pub fn ad_legal(&self, name: &str, state: ValidationState) -> Result<bool, ValidatorError> {
        Ok(self.classify(name, state)? == ValidationState::Secure)
    }

    /// Classify a cryptographically invalid signature.
    ///
    /// resolved treats a failed signature as bogus.  Allow-downgrade only
    /// relaxes missing DNSSEC data; it must not turn an invalid signature into
    /// an insecure answer.  NTAs and `DNSSEC=no` bypass validation entirely.
    pub fn failed_signature(&self, name: &str) -> Result<ValidationState, ValidatorError> {
        self.classify(name, ValidationState::Bogus)
    }

    /// Classify a response for which the chain validator found no signature.
    ///
    /// Strict mode rejects this as bogus.  In allow-downgrade mode it is
    /// insecure unless the name is covered by an NTA, in which case no
    /// validation was requested in the first place.
    pub fn missing_signature(&self, name: &str) -> Result<ValidationState, ValidatorError> {
        if !self.should_validate(name)? {
            return Ok(ValidationState::NotValidated);
        }
        Ok(match self.mode {
            DnssecMode::Yes => ValidationState::Bogus,
            DnssecMode::AllowDowngrade => ValidationState::Insecure,
            DnssecMode::No => ValidationState::NotValidated,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CanonicalName(Vec<u8>);

impl CanonicalName {
    fn parse(name: &str) -> Result<Self, ValidatorError> {
        // systemd's empty presentation name denotes the root.  The wire
        // encoder intentionally rejects an empty string, so normalize only
        // this one representation before parsing.
        let presentation = if name.is_empty() { "." } else { name };
        let mut wire = crate::wire::encode_name(presentation)
            .map_err(|_| ValidatorError::InvalidName(name.to_owned()))?;
        // DNS comparisons are ASCII case-insensitive.  Lowercasing the wire
        // labels also makes escaped octets and ordinary presentation forms
        // compare identically after parsing.
        wire.iter_mut()
            .for_each(|byte| *byte = byte.to_ascii_lowercase());
        Ok(Self(wire))
    }

    fn parent(&self) -> Option<Self> {
        let first_length = usize::from(*self.0.first()?);
        if first_length == 0 {
            return None;
        }
        Some(Self(self.0.get(first_length + 1..)?.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(mode: DnssecMode, positive: &[&str], negative: &[&str]) -> NtaValidator {
        NtaValidator::new(ValidatorConfig {
            mode,
            trust_anchors: positive.iter().copied().map(TrustAnchor::new).collect(),
            ntas: negative
                .iter()
                .copied()
                .map(NegativeTrustAnchor::new)
                .collect(),
        })
        .expect("valid anchor configuration")
    }

    #[test]
    fn nta_covers_exact_name_and_all_descendants() {
        let validator = make_validator(DnssecMode::Yes, &["."], &["corp"]);
        assert_eq!(
            validator.lookup("corp").unwrap(),
            AnchorMatch::NegativeTrustAnchor
        );
        assert!(validator.is_insecure("host.CORP.").unwrap());
        assert!(validator.should_validate("signed.example.").unwrap());
    }

    #[test]
    fn positive_anchor_stops_inherited_nta_but_not_a_nearer_nta() {
        let validator = make_validator(
            DnssecMode::Yes,
            &["signed.corp"],
            &["corp", "host.signed.corp"],
        );
        // The first matching owner is the exact NTA, even though it has a
        // positive anchor too in the ancestry below.
        assert_eq!(
            validator.lookup("host.signed.corp").unwrap(),
            AnchorMatch::NegativeTrustAnchor
        );
        // A positive anchor at signed.corp prevents corp from covering names
        // in the signed subtree when no nearer NTA is present.
        let validator = make_validator(DnssecMode::Yes, &["signed.corp"], &["corp"]);
        assert_eq!(
            validator.lookup("host.signed.corp").unwrap(),
            AnchorMatch::PositiveTrustAnchor
        );
        assert_eq!(
            validator.lookup("host.unsigned.corp").unwrap(),
            AnchorMatch::NegativeTrustAnchor
        );
    }

    #[test]
    fn exact_anchor_precedence_matches_systemd() {
        let validator = make_validator(DnssecMode::Yes, &["corp"], &["corp"]);
        assert_eq!(
            validator.lookup("corp").unwrap(),
            AnchorMatch::NegativeTrustAnchor
        );
        let validator = make_validator(DnssecMode::Yes, &["."], &["corp"]);
        assert_eq!(
            validator.lookup("other.example").unwrap(),
            AnchorMatch::PositiveTrustAnchor
        );
    }

    #[test]
    fn canonical_name_matching_handles_case_trailing_dot_and_escapes() {
        let validator = make_validator(DnssecMode::Yes, &["."], &[r"ExAmPle"]);
        assert!(validator.is_insecure("host.example.").unwrap());

        let escaped = make_validator(DnssecMode::Yes, &["."], &[r"foo\.bar"]);
        assert!(escaped.is_insecure(r"host.foo\.bar.").unwrap());
        assert!(!escaped.is_insecure("host.foo.bar.").unwrap());
    }

    #[test]
    fn malformed_anchor_and_query_names_fail_closed() {
        let result = NtaValidator::new(ValidatorConfig {
            mode: DnssecMode::Yes,
            trust_anchors: vec![TrustAnchor::new("bad..name")],
            ntas: Vec::new(),
        });
        assert!(matches!(
            result,
            Err(ValidatorError::InvalidName(name)) if name == "bad..name"
        ));

        let validator = make_validator(DnssecMode::Yes, &[], &["example"]);
        assert!(matches!(
            validator.lookup("bad..name"),
            Err(ValidatorError::InvalidName(name)) if name == "bad..name"
        ));
    }

    #[test]
    fn nta_and_mode_policy_never_authorize_ad() {
        let validator = make_validator(DnssecMode::Yes, &["."], &["example"]);
        assert_eq!(
            validator
                .classify("insecure.example", ValidationState::Secure)
                .unwrap(),
            ValidationState::NotValidated
        );
        assert!(!validator
            .ad_legal("insecure.example", ValidationState::Secure)
            .unwrap());

        let disabled = make_validator(DnssecMode::No, &["."], &[]);
        assert!(!disabled
            .ad_legal("secure.example", ValidationState::Secure)
            .unwrap());
        let enabled = make_validator(DnssecMode::Yes, &["."], &[]);
        assert!(enabled
            .ad_legal("secure.example", ValidationState::Secure)
            .unwrap());
        assert!(!enabled
            .ad_legal("secure.example", ValidationState::Insecure)
            .unwrap());
    }

    #[test]
    fn failed_signature_is_bogus_but_missing_data_can_downgrade() {
        let strict = make_validator(DnssecMode::Yes, &["."], &[]);
        assert_eq!(
            strict.failed_signature("signed.example").unwrap(),
            ValidationState::Bogus
        );
        assert_eq!(
            strict.missing_signature("signed.example").unwrap(),
            ValidationState::Bogus
        );

        let downgrade = make_validator(DnssecMode::AllowDowngrade, &["."], &[]);
        assert_eq!(
            downgrade.failed_signature("signed.example").unwrap(),
            ValidationState::Bogus
        );
        assert_eq!(
            downgrade.missing_signature("signed.example").unwrap(),
            ValidationState::Insecure
        );

        let nta = make_validator(DnssecMode::Yes, &["."], &["example"]);
        assert_eq!(
            nta.failed_signature("private.example").unwrap(),
            ValidationState::NotValidated
        );
    }
}
