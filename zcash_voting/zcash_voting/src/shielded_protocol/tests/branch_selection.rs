//! Snapshot branch IDs that select Ironwood voting notes.

use super::super::*;

#[test]
fn accepts_nu6_3_and_nu7_ironwood_branches() {
    for branch_id in [BranchId::Nu6_3, BranchId::Nu7] {
        let protocol = VotingShieldedProtocol::for_branch_id(branch_id).unwrap();
        assert_eq!(protocol, VotingShieldedProtocol::Ironwood);
        assert_eq!(protocol.bundle_version(), BundleVersion::ironwood_v3());
        assert_eq!(protocol.note_version(), NoteVersion::V3);
    }

    for branch_id in [BranchId::Nu6_2, BranchId::Sapling] {
        let err = VotingShieldedProtocol::for_branch_id(branch_id).unwrap_err();
        assert!(
            matches!(err, VotingError::InvalidInput { .. }),
            "unexpected error for {branch_id:?}: {err:?}"
        );
    }
}

#[test]
fn mainnet_nu7_switch_keeps_ironwood_v3_voting() {
    let network = crate::Network::Mainnet;
    let before = BlockHeight::from_u32(3_543_404);
    let after = BlockHeight::from_u32(3_543_405);

    assert_eq!(BranchId::for_height(&network, before), BranchId::Nu6_3);
    assert_eq!(BranchId::for_height(&network, after), BranchId::Nu7);
    assert_eq!(
        VotingShieldedProtocol::for_height(&network, after).unwrap(),
        VotingShieldedProtocol::Ironwood
    );
}
