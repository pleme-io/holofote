use std::collections::BTreeMap;

use crate::client::SplunkClient;
use crate::outcome::Refusal;
use crate::transport::Transport;

pub struct Targets<T: Transport> {
    by_label: BTreeMap<String, SplunkClient<T>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetsError {
    #[error("no target was configured; pass --host and --label, or at least one --target")]
    Empty,
    #[error("target label {label:?} is configured twice; every target needs its own label")]
    Duplicate { label: String },
}

impl<T: Transport> Targets<T> {
    pub fn new(clients: impl IntoIterator<Item = SplunkClient<T>>) -> Result<Self, TargetsError> {
        let mut by_label = BTreeMap::new();
        for client in clients {
            let label = client.identity().label.clone();
            if by_label.contains_key(&label) {
                return Err(TargetsError::Duplicate { label });
            }
            by_label.insert(label, client);
        }
        if by_label.is_empty() {
            return Err(TargetsError::Empty);
        }
        Ok(Self { by_label })
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.by_label.keys().map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_label.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_label.is_empty()
    }

    pub fn clients(&self) -> impl Iterator<Item = &SplunkClient<T>> {
        self.by_label.values()
    }

    pub fn resolve(&self, target: Option<&str>) -> Result<&SplunkClient<T>, Refusal> {
        match target {
            Some(label) => self
                .by_label
                .get(label)
                .ok_or_else(|| Refusal::UnknownTarget {
                    got: label.to_owned(),
                    known: self.known(),
                }),
            None => match self.by_label.values().next() {
                Some(only) if self.by_label.len() == 1 => Ok(only),
                _ => Err(Refusal::TargetRequired {
                    known: self.known(),
                }),
            },
        }
    }

    fn known(&self) -> Vec<String> {
        self.by_label.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Identity;
    use crate::config::HolofoteConfig;
    use crate::outcome::{Failure, Outcome};
    use crate::tls::TlsPosture;
    use crate::{Credential, MockTransport};
    use shikumi::TieredConfig as _;

    fn client(label: &str, host: &str) -> SplunkClient<MockTransport> {
        SplunkClient::new(
            MockTransport::new(),
            Credential::None,
            HolofoteConfig::prescribed_default(),
            Identity {
                label: label.into(),
                host: host.into(),
                tls_posture: TlsPosture::System,
            },
        )
    }

    fn pair() -> Targets<MockTransport> {
        Targets::new([
            client("beta", "https://splunk-b.example.com:8089"),
            client("alpha", "https://splunk-a.example.com:8089"),
        ])
        .expect("two distinct labels")
    }

    #[test]
    fn labels_are_served_in_one_deterministic_order() {
        let t = pair();
        assert_eq!(t.labels().collect::<Vec<_>>(), ["alpha", "beta"]);
        assert_eq!(t.len(), 2);
        assert!(!t.is_empty());
    }

    #[test]
    fn each_target_keeps_its_own_host() {
        let t = pair();
        let a = t.resolve(Some("alpha")).expect("alpha");
        let b = t.resolve(Some("beta")).expect("beta");
        assert_eq!(a.identity().host, "https://splunk-a.example.com:8089");
        assert_eq!(b.identity().host, "https://splunk-b.example.com:8089");
    }

    #[test]
    fn an_unknown_target_is_refused_naming_every_legal_label() {
        let t = pair();
        let refusal = t.resolve(Some("gamma")).err().expect("refused");
        assert_eq!(refusal.legal(), ["alpha", "beta"]);
        let msg = refusal.to_string();
        assert!(
            msg.contains("gamma") && msg.contains("alpha") && msg.contains("beta"),
            "{msg}"
        );
        let outcome: Outcome<()> = Failure::from(refusal).into();
        assert_eq!(outcome.kind(), "refused");
    }

    #[test]
    fn a_missing_target_is_refused_when_more_than_one_is_served() {
        let refusal = pair().resolve(None).err().expect("refused");
        assert_eq!(refusal.legal(), ["alpha", "beta"]);
        assert!(refusal.to_string().contains("target"), "{refusal}");
    }

    #[test]
    fn a_missing_target_resolves_to_the_only_one() {
        let one =
            Targets::new([client("alpha", "https://splunk-a.example.com:8089")]).expect("one");
        assert_eq!(one.resolve(None).expect("sole").identity().label, "alpha");
        assert_eq!(
            one.resolve(Some("alpha")).expect("named").identity().label,
            "alpha"
        );
        assert_eq!(
            one.resolve(Some("beta")).err().expect("refused").legal(),
            ["alpha"]
        );
    }

    #[test]
    fn duplicate_and_empty_target_sets_are_refused_at_construction() {
        let dup = Targets::new([
            client("alpha", "https://splunk-a.example.com:8089"),
            client("alpha", "https://splunk-b.example.com:8089"),
        ]);
        assert_eq!(
            dup.err(),
            Some(TargetsError::Duplicate {
                label: "alpha".into()
            })
        );
        let none = Targets::<MockTransport>::new([]);
        assert_eq!(none.err(), Some(TargetsError::Empty));
    }
}
