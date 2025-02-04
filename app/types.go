package app

import "justExitMyValidators/wallet"

type RecoveredNodeAddresses struct {
	Text        string
	NodeAddress string
	WalletData  string
}

type MinipoolsData struct {
	NodeAddress string
	NetworkId   uint64
	Validators  []wallet.ValidatorData
}

type BeaconchaValidatorStatusResponse struct {
	Status string `json:"status"`
	Data   []struct {
		ActivationEligibilityEpoch uint64 `json:"activationeligibilityepoch"`
		ActivationEpoch            uint64 `json:"activationepoch"`
		Balance                    uint64 `json:"balance"`
		EffectiveBalance           uint64 `json:"effectivebalance"`
		ExitEpoch                  uint64 `json:"exitepoch"`
		LastAttestationSlot        uint64 `json:"lastattestationslot"`
		Name                       string `json:"name"`
		PubKey                     string `json:"pubkey"`
		Slashed                    bool   `json:"slashed"`
		Status                     string `json:"status"`
		ValidatorIndex             uint64 `json:"validatorindex"`
		WithdrawableEpoch          uint64 `json:"withdrawableepoch"`
		WithdrawalCredentials      string `json:"withdrawalcredentials"`
		TotalWithdrawals           uint64 `json:"total_withdrawals"`
	} `json:"data"`
}

type BeaconchaEpochDataResponse struct {
	Status string `json:"status"`
	Data   struct {
		AttestationsCount       uint64  `json:"attestationscount"`
		AttesterSlashingsCount  uint64  `json:"attesterslashingscount"`
		AverageValidatorBalance uint64  `json:"averagevalidatorbalance"`
		BlocksCount             uint64  `json:"blockscount"`
		DepositsCount           uint64  `json:"depositscount"`
		EligibleEther           uint64  `json:"eligibleether"`
		Epoch                   uint64  `json:"epoch"`
		Finalized               bool    `json:"finalized"`
		GlobalParticipationRate float64 `json:"globalparticipationrate"`
		MissedBlocks            uint64  `json:"missedblocks"`
		OrphanedBlocks          uint64  `json:"orphanedblocks"`
		ProposedBlocks          uint64  `json:"proposedblocks"`
		ProposerSlashingsCount  uint64  `json:"proposerslashingscount"`
		RewardsExported         bool    `json:"rewards_exported"`
		ScheduledBlocks         uint64  `json:"scheduledblocks"`
		TotalValidatorBalance   uint64  `json:"totalvalidatorbalance"`
		Timestamp               string  `json:"ts"`
		ValidatorsCount         uint64  `json:"validatorscount"`
		VoluntaryExitsCount     uint64  `json:"voluntaryexitscount"`
		VotedEther              uint64  `json:"votedether"`
		WithdrawalCount         uint64  `json:"withdrawalcount"`
	} `json:"data"`
}
