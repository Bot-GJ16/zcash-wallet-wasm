use super::constants::{PROD_STATIC_CONFIG_DIGEST, PROD_STATIC_CONFIG_SOURCE, STAGE_STATIC_CONFIG_DIGEST, STAGE_STATIC_CONFIG_SOURCE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VotingNetwork {
    Testnet,
    Mainnet,
}

impl VotingNetwork {
    pub(crate) fn for_wallet(network: crate::Network) -> Self {
        match network {
            crate::Network::TestNetwork => Self::Testnet,
            crate::Network::MainNetwork => Self::Mainnet,
        }
    }

    pub(crate) fn network(self) -> zcash_voting::Network {
        match self {
            Self::Testnet => zcash_voting::Network::Testnet,
            Self::Mainnet => zcash_voting::Network::Mainnet,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    pub(crate) fn environment(self) -> &'static str {
        match self {
            Self::Testnet => "stage",
            Self::Mainnet => "prod",
        }
    }

    pub(crate) fn static_source(self) -> &'static str {
        match self {
            Self::Testnet => STAGE_STATIC_CONFIG_SOURCE,
            Self::Mainnet => PROD_STATIC_CONFIG_SOURCE,
        }
    }

    pub(crate) fn static_digest(self) -> &'static str {
        match self {
            Self::Testnet => STAGE_STATIC_CONFIG_DIGEST,
            Self::Mainnet => PROD_STATIC_CONFIG_DIGEST,
        }
    }

    pub(crate) fn tree_state_network(self) -> &'static str {
        match self {
            Self::Testnet => "test",
            Self::Mainnet => "main",
        }
    }

    pub(crate) fn accepts_service_network(self, name: &str) -> bool {
        match self {
            Self::Testnet => matches!(name, "test" | "testnet"),
            Self::Mainnet => matches!(name, "main" | "mainnet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_context_selects_prod() {
        let main = VotingNetwork::for_wallet(crate::Network::MainNetwork);
        assert_eq!(main.network(), zcash_voting::Network::Mainnet);
        assert_eq!(main.label(), "mainnet");
        assert_eq!(main.environment(), "prod");
        assert_eq!(main.static_digest(), "28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe");
        assert_eq!(main.tree_state_network(), "main");
        assert_eq!(
            main.static_source(),
            "https://voting.valargroup.dev/pins/prod/28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe/v2-static-voting-config.json?checksum=sha256:28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe"
        );
        assert!(main.accepts_service_network("main"));
        assert!(main.accepts_service_network("mainnet"));
        for rejected in ["test", "testnet", "regtest", "MAIN", ""] {
            assert!(!main.accepts_service_network(rejected), "{rejected}");
        }
    }

    #[test]
    fn testnet_context_selects_stage() {
        let test = VotingNetwork::for_wallet(crate::Network::TestNetwork);
        assert_eq!(test.network(), zcash_voting::Network::Testnet);
        assert_eq!(test.label(), "testnet");
        assert_eq!(test.environment(), "stage");
        assert_eq!(test.static_digest(), "17484ebabab92225205a02a962add09f1659c9798c2e2e325bd8eac56ab3bf8f");
        assert_eq!(test.tree_state_network(), "test");
        assert_eq!(
            test.static_source(),
            "https://voting.valargroup.dev/pins/stage/17484ebabab92225205a02a962add09f1659c9798c2e2e325bd8eac56ab3bf8f/v2-static-voting-config.json?checksum=sha256:17484ebabab92225205a02a962add09f1659c9798c2e2e325bd8eac56ab3bf8f"
        );
        assert!(test.accepts_service_network("test"));
        assert!(test.accepts_service_network("testnet"));
        for rejected in ["main", "mainnet", "regtest", "TEST", ""] {
            assert!(!test.accepts_service_network(rejected), "{rejected}");
        }
    }
}
