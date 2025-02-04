package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"justExitMyValidators/rocketpoolContracts"
	"justExitMyValidators/wallet"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/donseba/go-htmx"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	nmc_validator "github.com/rocket-pool/node-manager-core/node/validator"
	eth2types "github.com/wealdtech/go-eth2-types/v2"
)

const (
	MAINNET_GENESIS_VALIDATORS_ROOT = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
	MAINNET_CAPELLA_FORK_VERSION    = "04000000"

	HOLESKY_GENESIS_VALIDATORS_ROOT = "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"
	HOLESKY_CAPELLA_FORK_VERSION    = "04017000"

	MinipoolPerPage = uint64(10)

	MAINNET_NETWORK_ID = 1
	HOLESKY_NETWORK_ID = 17000

	RPC_URL_MAINNET = "https://eth.llamarpc.com"
	RPC_URL_HOLESKY = "https://rpc.holesky.ethpandaops.io"
)

var (
	indexTemplate               = template.Must(template.ParseFiles("public/index.html"))
	inputMnemonicTemplate       = template.Must(template.ParseFiles("public/mnemonic.html"))
	minipoolsTemplate           = template.Must(template.ParseFiles("public/minipoolList.html"))
	confirmationOverlayTemplate = template.Must(template.ParseFiles("public/confirmationOverlay.html"))
)

type App struct {
	logger *slog.Logger
	htmx   *htmx.HTMX
}

func NewApp(logger *slog.Logger) *App {
	return &App{
		logger: logger.With("module", "app"),
		htmx:   htmx.New(),
	}
}

func (a *App) Home(w http.ResponseWriter, r *http.Request) {
	err := indexTemplate.Execute(w, nil)
	if err != nil {
		a.logger.Error("error rendering", slog.String("error", err.Error()), slog.String("function", "Home"))
	}
}

func (a *App) GetMnemonicInput(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"enteredMnemonic": "",
	}
	err := inputMnemonicTemplate.Execute(w, data)
	if err != nil {
		a.logger.Error("error rendering", slog.String("error", err.Error()), slog.String("function", "mnemonic"))
	}
}

func (a *App) SubmitMnemonicHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "SubmitMnemonicHandler")
	// Ensure it's a POST request
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Unable to parse form data", http.StatusBadRequest)
		return
	}

	// Extract the derivationPath from the form
	derivationPath := r.FormValue("derivationPath")
	logger.Debug("recived custom derivationPath", slog.String("derivationPath", derivationPath))

	// Extract the mnemonic from the form
	mnemonic := r.FormValue("mnemonic")
	logger.Debug("recived mnemonic", slog.String("mnemonic", mnemonic))

	if mnemonic == "" {
		data := map[string]string{
			"errorMsg": "Mnemonic is required",
		}
		err := inputMnemonicTemplate.Execute(w, data)
		if err != nil {
			logger.Error("error rendering", slog.String("error", err.Error()))
		}
		return
	}

	wallet, err := wallet.NewWallet(mnemonic, derivationPath, 0)
	if err != nil {
		data := map[string]string{
			"errorMsg":        err.Error(),
			"enteredMnemonic": mnemonic,
		}
		logger.Error("error creating wallet", slog.String("error", err.Error()))
		err = inputMnemonicTemplate.Execute(w, data)
		if err != nil {
			logger.Error("error rendering", slog.String("error", err.Error()))
		}
		return
	}

	var recoveredNodeAddresses []RecoveredNodeAddresses
	if wallet.CustomKey != nil {
		recoveryData, err := wallet.DefaultNodeKey.Json()
		if err != nil {
			logger.Warn("error getting default node key json", slog.String("error", err.Error()))
			recoveryData = ""
		}
		recoveredNodeAddresses = append(recoveredNodeAddresses, RecoveredNodeAddresses{
			Text:        "Recovered node address using custom derivation path",
			NodeAddress: wallet.CustomKey.Address().Hex(),
			WalletData:  recoveryData,
		})
		logger.Info("mnemonic correct",
			slog.String("nodeAddressCustom", wallet.CustomKey.Address().Hex()),
		)
	} else {
		recoveryData, err := wallet.DefaultNodeKey.Json()
		if err != nil {
			logger.Warn("error getting default node key json", slog.String("error", err.Error()))
			recoveryData = ""
		}
		recoveredNodeAddresses = append(recoveredNodeAddresses, RecoveredNodeAddresses{
			Text:        "Recovered node address using smart node derivation path",
			NodeAddress: wallet.DefaultNodeKey.Address().Hex(),
			WalletData:  recoveryData,
		})

		recoveryData, err = wallet.DefaultNodeKey.Json()
		if err != nil {
			logger.Warn("error getting default node key json", slog.String("error", err.Error()))
			recoveryData = ""
		}
		recoveredNodeAddresses = append(recoveredNodeAddresses, RecoveredNodeAddresses{
			Text:        "Recovered node address using leder derivation path",
			NodeAddress: wallet.LedgerLiveNodeKey.Address().Hex(),
			WalletData:  recoveryData,
		})

		recoveryData, err = wallet.DefaultNodeKey.Json()
		if err != nil {
			logger.Warn("error getting default node key json", slog.String("error", err.Error()))
			recoveryData = ""
		}
		recoveredNodeAddresses = append(recoveredNodeAddresses, RecoveredNodeAddresses{
			Text:        "Recovered node address using my ether wallet derivation path",
			NodeAddress: wallet.MyEtherWalletNodeKey.Address().Hex(),
			WalletData:  recoveryData,
		})
		logger.Info("mnemonic correct",
			slog.String("nodeAddressDefault", wallet.DefaultNodeKey.Address().Hex()),
			slog.String("nodeAddressLedger", wallet.LedgerLiveNodeKey.Address().Hex()),
			slog.String("nodeAddressMyEtherWallet", wallet.MyEtherWalletNodeKey.Address().Hex()),
		)
	}

	data := map[string]interface{}{
		"recoveredNodeAddresses": recoveredNodeAddresses,
		"enteredMnemonic":        mnemonic,
	}

	err = inputMnemonicTemplate.Execute(w, data)
	if err != nil {
		logger.Error("error rendering", slog.String("error", err.Error()))
	}
}

func (a *App) GetMinipoolsHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "GetMinipoolsHandler")
	startTime := time.Now()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Unable to parse form data", http.StatusBadRequest)
		return
	}

	walletJson := r.FormValue("WalletData")
	logger.Debug("recived wallet data", slog.String("WalletData", walletJson))

	nodeKey, err := wallet.NewNodeKeyFromJson(walletJson)
	if err != nil {
		http.Error(w, "Invalid wallet data", http.StatusBadRequest)
		logger.Error("error creating node key from json", slog.String("error", err.Error()))
		return
	}

	nodeAddress := nodeKey.Address()
	a.logger.Debug("recovered node wallet", slog.String("node address", nodeAddress.Hex()), slog.Duration("timeElapsed", time.Since(startTime)))

	pageStr := r.FormValue("page")
	var page uint64
	if pageStr == "" {
		page = uint64(1)
	} else {
		var err error
		pageInt64, err := strconv.ParseInt(pageStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid page", http.StatusBadRequest)
			logger.Error("error parsing page", slog.String("error", err.Error()))
			return
		}
		page = uint64(pageInt64)
	}
	startIndex := (page - 1) * MinipoolPerPage
	endIndex := startIndex + MinipoolPerPage
	logger.Debug("recived page", slog.Uint64("page", page), slog.Uint64("startIndex", startIndex), slog.Uint64("endIndex", endIndex))

	var networkId uint64
	switch r.FormValue("network") {
	case "mainnet":
		networkId = MAINNET_NETWORK_ID
	case "holesky":
		networkId = HOLESKY_NETWORK_ID
	default:
		http.Error(w, "Invalid netowrk id", http.StatusBadRequest)
		return
	}
	logger.Debug("recived network", slog.String("network", r.FormValue("network")))

	validators, err := getExternalValidatorData(r.Context(), logger, startTime, networkId, nodeAddress, startIndex, endIndex)
	if err != nil {
		http.Error(w, "Unable to get validators", http.StatusInternalServerError)
		logger.Error("error getting validators", slog.String("error", err.Error()))
		return
	}
	logger.Debug("fetched validators", slog.Int("count", len(validators)), slog.Duration("timeElapsed", time.Since(startTime)))

	err = nodeKey.RecoverValidatorPrivateKeys(validators)
	if err != nil {
		http.Error(w, "Unable to recover validator private keys", http.StatusInternalServerError)
		logger.Error("error recovering validator private keys", slog.String("error", err.Error()))
		return
	}
	logger.Debug("recovered validator private keys", slog.Duration("timeElapsed", time.Since(startTime)))

	data := MinipoolsData{
		NodeAddress: nodeAddress.Hex(),
		NetworkId:   networkId,
		Validators:  validators,
	}

	err = minipoolsTemplate.Execute(w, data)
	if err != nil {
		http.Error(w, "Unable to render minipools", http.StatusInternalServerError)
		logger.Error("error rendering minipools", slog.String("error", err.Error()))
		return
	}
	logger.Info("minipools fetched", slog.Duration("timeElapsed", time.Since(startTime)))
}

func getExternalValidatorData(
	ctx context.Context,
	logger *slog.Logger,
	startTime time.Time,
	networkId uint64,
	nodeAddress common.Address,
	startIndex,
	endIndex uint64,
) ([]wallet.ValidatorData, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var rpcUrl string
	var beaconchaUrl string
	switch networkId {
	case MAINNET_NETWORK_ID:
		rpcUrl = RPC_URL_MAINNET
		beaconchaUrl = "https://beaconcha.in/api/v1/"
	case HOLESKY_NETWORK_ID:
		rpcUrl = RPC_URL_HOLESKY
		beaconchaUrl = "https://holesky.beaconcha.in/api/v1/"
	default:
		return nil, errors.New("invalid network id")
	}

	fmt.Println("would have connected to", rpcUrl, "todo overwrite this with the real rpc url after multicall is implemented")

	// TODO OVERWRITE THIS WITH THE REAL RPC URL
	rpc, err := ethclient.DialContext(ctx, "http://100.79.40.97:8555")
	if err != nil {
		return nil, errors.Join(errors.New("failed to connect to ethereum rpc"), err)
	}

	mm, err := rocketpoolContracts.NewMinipoolManager(ctx, rpc)
	if err != nil {
		return nil, errors.Join(errors.New("failed to create minipool manager"), err)
	}

	totalCount, err := mm.GetMinipoolCount(ctx, nodeAddress)
	if err != nil {
		return nil, errors.Join(errors.New("failed to get minipool count"), err)
	}
	logger.Debug("fetched minipool count", slog.Uint64("totalCount", totalCount), slog.Duration("timeElapsed", time.Since(startTime)))

	if startIndex > totalCount-1 {
		startIndex = totalCount - 1
	}
	if endIndex > totalCount-1 {
		endIndex = totalCount - 1
	}

	minipools, err := mm.GetMinipools(ctx, nodeAddress, startIndex, endIndex)
	if err != nil {
		return nil, errors.Join(errors.New("failed to get minipools"), err)
	}
	logger.Debug("fetched minipools", slog.Int("count", len(minipools)), slog.Duration("timeElapsed", time.Since(startTime)))

	// building validators data output
	// at the same time, collect all addresses in seperate array
	validators := make([]wallet.ValidatorData, 0, len(minipools))
	validatorsPubKeys := make([]string, len(minipools))
	for i, minipool := range minipools {
		validatorsPubKeys[i] = minipool.ValidatorPubkey.String()

		validators = append(validators, wallet.ValidatorData{
			Number:          startIndex + uint64(i) + 1,
			PubKey:          minipool.ValidatorPubkey.String(),
			MinipoolAddress: minipool.MinipoolAddress.Hex(),
		})
	}

	// get validator data from beaconchain
	url := fmt.Sprintf("%svalidator/%s", beaconchaUrl, strings.Join(validatorsPubKeys, ","))
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Join(errors.New("failed to get validators data"), err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Error("failed to get validators data", slog.String("status", resp.Status))
		return nil, errors.New("failed to get validators data")
	}

	var beaconchaResponse BeaconchaValidatorStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&beaconchaResponse); err != nil {
		return nil, errors.Join(errors.New("failed to decode validators data"), err)
	}

	if beaconchaResponse.Status != "OK" {
		return nil, fmt.Errorf("beaconchain response status is not OK: %s", beaconchaResponse.Status)
	}
	logger.Debug("fetched validators data", slog.Int("count", len(beaconchaResponse.Data)), slog.Duration("timeElapsed", time.Since(startTime)))

	if len(minipools) != len(beaconchaResponse.Data) {
		return nil, errors.New("invalid response from beaconchain, wrong length")
	}

	// matching beaconchain data with minipools
	// seperating this from the above loop in case the order does not match
	for _, validator := range beaconchaResponse.Data {
		for i, minipool := range minipools {
			if strings.EqualFold(minipool.ValidatorPubkey.String(), validator.PubKey) {
				validators[i].Index = validator.ValidatorIndex
				validators[i].Status = validator.Status
				break
			}
		}
	}

	return validators, nil
}

func (a *App) GetSignExitHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "SignExitMsg")
	startTime := time.Now()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Unable to parse form data", http.StatusBadRequest)
		return
	}

	var networkId uint64
	switch r.FormValue("network") {
	case "mainnet":
		networkId = MAINNET_NETWORK_ID
	case "holesky":
		networkId = HOLESKY_NETWORK_ID
	default:
		http.Error(w, "Invalid netowrk id", http.StatusBadRequest)
		return
	}
	logger.Debug("recived network", slog.String("network", r.FormValue("network")))

	validatorKeyStr := r.FormValue("privateKey")
	if validatorKeyStr == "" {
		http.Error(w, "Private key is required", http.StatusBadRequest)
		return
	}

	validatorKeyBytes, err := hex.DecodeString(validatorKeyStr)
	if err != nil {
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		logger.Error("error decoding private key", slog.String("error", err.Error()))
		return
	}

	validatorKey, err := eth2types.BLSPrivateKeyFromBytes(validatorKeyBytes)
	if err != nil {
		http.Error(w, "Invalid private key", http.StatusBadRequest)
		logger.Error("error converting private key", slog.String("error", err.Error()))
		return
	}
	logger.Debug("recived private key", slog.String("validatorKeyStr", validatorKeyStr))

	validatorIndexStr := r.FormValue("validatorIndex")
	if validatorIndexStr == "" {
		http.Error(w, "Validator index is required", http.StatusBadRequest)
		return
	}

	epoch, err := getCurrentEpoch(r.Context(), logger, networkId)
	if err != nil {
		http.Error(w, "Unable to get current epoch", http.StatusInternalServerError)
		logger.Error("error getting current epoch", slog.String("error", err.Error()))
		return
	}
	logger.Debug("using current epoch", slog.Uint64("epoch", epoch), slog.Duration("timeElapsed", time.Since(startTime)))

	signatureDomain, err := getValidatorExitDomain(logger, networkId)
	if err != nil {
		http.Error(w, "Unable to get signature domain", http.StatusInternalServerError)
		a.logger.Error("error getting signature domain", slog.String("error", err.Error()))
		return
	}

	logger.Debug("computed signature domain",
		slog.String("signatureDomain", hex.EncodeToString(signatureDomain)),
		slog.Duration("timeElapsed", time.Since(startTime)),
	)

	// use: https://github.com/rocket-pool/node-manager-core/blob/dfd914e4e77be54fbbf4ebb8e47d7578146bf429/node/validator/voluntary-exit.go#L13
	signature, err := nmc_validator.GetSignedExitMessage(validatorKey, validatorIndexStr, epoch, signatureDomain)
	if err != nil {
		http.Error(w, "Unable to sign exit message", http.StatusInternalServerError)
		logger.Error("error signing exit message", slog.String("error", err.Error()))
		return
	}

	logger.Debug("generated signature", slog.String("signature", signature.HexWithPrefix()), slog.Duration("timeElapsed", time.Since(startTime)))

	signature.HexWithPrefix()

	data := map[string]interface{}{
		"NetworkId":      networkId,
		"ValidatorIndex": validatorIndexStr,
		"PubKey":         "0x" + hex.EncodeToString(validatorKey.PublicKey().Marshal()),
		"Epoch":          fmt.Sprintf("%d", epoch),
		"Signature":      signature.HexWithPrefix(),
	}

	err = confirmationOverlayTemplate.Execute(w, data)
	if err != nil {
		http.Error(w, "Unable to render confirmation overlay", http.StatusInternalServerError)
		logger.Error("error rendering confirmation overlay", slog.String("error", err.Error()))
		return
	}
	logger.Info("signature generated", slog.Duration("timeElapsed", time.Since(startTime)))
}

func getCurrentEpoch(ctx context.Context, logger *slog.Logger, networkId uint64) (uint64, error) {
	var beaconchaUrl string
	switch networkId {
	case MAINNET_NETWORK_ID:
		beaconchaUrl = "https://beaconcha.in/api/v1/epoch/latest"
	case HOLESKY_NETWORK_ID:
		beaconchaUrl = "https://holesky.beaconcha.in/api/v1/epoch/latest"
	default:
		return 0, errors.New("invalid network id")
	}

	// get validator data from beaconchain
	resp, err := http.Get(beaconchaUrl)
	if err != nil {
		return 0, errors.Join(errors.New("failed to get validators data"), err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Error("failed to get validators data", slog.String("status", resp.Status))
		return 0, errors.New("failed to get validators data")
	}

	var beaconchaResponse BeaconchaEpochDataResponse
	if err := json.NewDecoder(resp.Body).Decode(&beaconchaResponse); err != nil {
		return 0, errors.Join(errors.New("failed to decode validators data"), err)
	}

	if beaconchaResponse.Status != "OK" {
		return 0, fmt.Errorf("beaconchain response status is not OK: %s", beaconchaResponse.Status)
	}

	return beaconchaResponse.Data.Epoch, nil
}

func getValidatorExitDomain(logger *slog.Logger, networkId uint64) ([]byte, error) {
	var forkVersionStr string
	var genesisValidatorsRootStr string

	switch networkId {
	case MAINNET_NETWORK_ID:
		forkVersionStr = MAINNET_CAPELLA_FORK_VERSION
		genesisValidatorsRootStr = MAINNET_GENESIS_VALIDATORS_ROOT
	case HOLESKY_NETWORK_ID:
		forkVersionStr = HOLESKY_CAPELLA_FORK_VERSION
		genesisValidatorsRootStr = HOLESKY_GENESIS_VALIDATORS_ROOT
	default:
		return nil, errors.New("invalid network id")
	}

	logger.Debug("computing domain",
		slog.String("using fork version", forkVersionStr),
		slog.String("using genesis validators root", genesisValidatorsRootStr),
	)

	forkVersion, err := hex.DecodeString(forkVersionStr)
	if err != nil {
		return nil, errors.Join(errors.New("failed to decode fork version"), err)
	}

	genesisValidatorsRoot, err := hex.DecodeString(genesisValidatorsRootStr)
	if err != nil {
		return nil, errors.Join(errors.New("failed to decode genesis validators root"), err)
	}

	// convert to [] byte
	var dt [4]byte
	copy(dt[:], eth2types.DomainVoluntaryExit[:])

	return eth2types.ComputeDomain(dt, forkVersion, genesisValidatorsRoot)
}
