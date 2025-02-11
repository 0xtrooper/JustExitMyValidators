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
	"regexp"
	"strconv"
	"strings"
	"time"

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

	MinipoolPerPage = uint64(15)

	MAINNET_NETWORK_ID = 1
	HOLESKY_NETWORK_ID = 17000
)

var (
	baseTemplate                = template.Must(template.ParseFiles("public/base.html"))
	faqTemplate                 = template.Must(template.ParseFiles("public/faq.html"))
	guideTemplate               = template.Must(template.ParseFiles("public/guide.html"))
	errorTemplate               = template.Must(template.ParseFiles("public/errorBox.html"))
	inputMnemonicTemplate       = template.Must(template.ParseFiles("public/mnemonic.html"))
	inputWalletJsonTemplate     = template.Must(template.ParseFiles("public/walletJson.html"))
	minipoolsTemplate           = template.Must(template.ParseFiles("public/minipoolList.html"))
	confirmationOverlayTemplate = template.Must(template.ParseFiles("public/confirmationOverlay.html"))
	confirmWalletTemplate       = template.Must(template.ParseFiles("public/confirmWallet.html"))

	// regex to validate derivation path, allowed formats:
	// m/44'/60'/.../.../... (with optional _'_ and optional _%d_)
	derivationPathRegex = regexp.MustCompile("^m/44'?/60'?/(?:[0-9]+(?:'?)|%d)/(?:[0-9]+|%d)/(?:[0-9]+|%d)$")
)

type App struct {
	logger        *slog.Logger
	mainnetRpcUrl string
	holskyRpcUrl  string
}

func NewApp(logger *slog.Logger, mainnetRpcUrl, holskyRpcUrl string) *App {
	return &App{
		logger:        logger.With("module", "app"),
		mainnetRpcUrl: mainnetRpcUrl,
		holskyRpcUrl:  holskyRpcUrl,
	}
}

func (a *App) HomeFaq(w http.ResponseWriter, r *http.Request) {
	err := renderMainPage(w, r, faqTemplate)
	if err != nil {
		a.logger.Error("error rendering main faq template", slog.String("error", err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *App) HomeGuide(w http.ResponseWriter, r *http.Request) {
	err := renderMainPage(w, r, guideTemplate)
	if err != nil {
		a.logger.Error("error rendering main guide template", slog.String("error", err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// adds specific template context to the base template
func renderMainPage(w http.ResponseWriter, r *http.Request, t *template.Template) error {
	var content strings.Builder
	err := t.Execute(&content, nil)
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"content": template.HTML(content.String()),
	}
	return baseTemplate.Execute(w, data)
}

func (a *App) Faq(w http.ResponseWriter, r *http.Request) {
	err := faqTemplate.Execute(w, nil)
	if err != nil {
		a.logger.Error("error rendering", slog.String("error", err.Error()), slog.String("function", "Faq"))
	}
}

func (a *App) Guide(w http.ResponseWriter, r *http.Request) {
	err := guideTemplate.Execute(w, nil)
	if err != nil {
		a.logger.Error("error rendering", slog.String("error", err.Error()), slog.String("function", "Guide"))
	}
}

func (a *App) GetMnemonicInput(w http.ResponseWriter, r *http.Request) {
	err := inputMnemonicTemplate.Execute(w, nil)
	if err != nil {
		a.logger.Error("error rendering inputMnemonicTemplate", slog.String("error", err.Error()))
	}
}

func (a *App) GetWalletJsonInput(w http.ResponseWriter, r *http.Request) {
	err := inputWalletJsonTemplate.Execute(w, nil)
	if err != nil {
		a.logger.Error("error rendering inputWalletJsonTemplate", slog.String("error", err.Error()))
	}
}

func (a *App) SubmitMnemonicHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "SubmitMnemonicHandler")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing form data", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to parse form data")
		return
	}

	// Extract the derivationPath from the form
	derivationPath := r.FormValue("customDerivationPath")
	if derivationPath != "" {
		logger.Debug("recived custom derivationPath", slog.String("derivationPath", derivationPath))
		if !derivationPathRegex.MatchString(derivationPath) {
			logger.Error("error invalid derivation path", slog.String("derivationPath", derivationPath))
			returnErrorBox(w, r, logger, "Invalid derivation path")
			return
		}
	}

	var index uint
	if indexStr := r.FormValue("customWalletIndex"); indexStr == "" {
		index = 0
		logger.Debug("using default index 0")
	} else {
		indexInt, err := strconv.ParseUint(indexStr, 10, 64)
		if err != nil {
			logger.Error("error parsing index", slog.String("error", err.Error()))
			returnErrorBox(w, r, logger, "Invalid index")
			return
		}
		index = uint(indexInt)
		logger.Debug("recived index", slog.Uint64("index", indexInt))
	}

	mnemonic := r.FormValue("mnemonic")
	if mnemonic == "" {
		logger.Error("error no mnemonic")
		returnErrorBox(w, r, logger, "Mnemonic is required")
		return
	}
	logger.Debug("recived mnemonic", slog.String("mnemonic", mnemonic))

	// create possbile wallet instances
	// custom derivation path: only one wallet is created
	// default derivation path: 3 wallets are created using the common derivation paths
	walletInstance, err := wallet.NewWalletManager(mnemonic, derivationPath, index)
	if err != nil {
		logger.Error("error creating wallet", slog.String("error", err.Error()))
		if errors.Is(err, wallet.ErrInvalidWordCount) {
			returnErrorBox(w, r, logger, wallet.ErrInvalidWordCount.Error())
		} else {
			returnErrorBox(w, r, logger, "Wrong mnemonic")
		}
		return
	}

	recoveredWalletData, err := walletInstance.RecoverWalletData()
	if err != nil {
		logger.Error("error recovering node addresses", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, err.Error())
		return
	}

	data := map[string]interface{}{
		"recoveredWalletData": recoveredWalletData,
	}

	err = confirmWalletTemplate.Execute(w, data)
	if err != nil {
		logger.Error("error rendering", slog.String("error", err.Error()))
	}
}

func (a *App) SubmitWalletJsonHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "SubmitWalletJsonHandler")
	// Ensure it's a POST request
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form data
	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing form data", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to parse form data")
		return
	}

	// Extract the wallet json from the form
	walletStr := r.FormValue("walletJson")
	if walletStr == "" {
		logger.Error("error no walletStr")
		returnErrorBox(w, r, logger, "Wallet JSON is required")
		return
	}

	// Extract the password from the form
	walletPassword := r.FormValue("walletPassword")
	if walletPassword == "" {
		logger.Error("error no walletPassword")
		returnErrorBox(w, r, logger, "walletPassword is required")
		return
	}
	logger.Debug("recived data", slog.String("walletPassword", walletPassword), slog.String("walletStr", walletStr))

	nodeWallet, err := wallet.LoadWallet(walletStr, walletPassword)
	if err != nil {
		logger.Error("error loading wallet", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Invalid wallet data")
		return
	}

	var recoveredWalletData []wallet.RecoveredWalletData

	recoveryData, err := nodeWallet.SerializeDataWithPassword()
	if err != nil {
		logger.Warn("error getting default node key json", slog.String("error", err.Error()))
		recoveryData = ""
	}
	recoveredWalletData = append(recoveredWalletData, wallet.RecoveredWalletData{
		Text:        "Recovered node address",
		NodeAddress: nodeWallet.Address().Hex(),
		Data:        recoveryData,
	})
	logger.Info("wallet json correct", slog.String("nodeAddressCustom", nodeWallet.Address().Hex()))

	data := map[string]interface{}{
		"recoveredWalletData": recoveredWalletData,
	}

	err = confirmWalletTemplate.Execute(w, data)
	if err != nil {
		logger.Error("error rendering", slog.String("error", err.Error()))
	}
}

func (a *App) GetMinipoolsHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "GetMinipoolsHandler")
	startTime := time.Now()

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing form data", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "invalid form data")
		return
	}

	walletStr := r.FormValue("WalletData")
	if walletStr == "" {
		logger.Error("error missing walletStr")
		returnErrorBox(w, r, logger, "Wallet data is required")
		return
	}

	walletPassword := r.FormValue("WalletPassword")
	if walletPassword == "" {
		logger.Error("error missing walletPassword")
		returnErrorBox(w, r, logger, "walletPassword is required")
		return
	}

	logger.Debug("recived wallet data", slog.String("walletStr", walletStr), slog.String("walletPassword", walletPassword))

	nodeWallet, err := wallet.LoadWallet(walletStr, walletPassword)
	if err != nil {
		logger.Error("error creating node key from json", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Invalid wallet data")
		return
	}
	nodeAddress := nodeWallet.Address()
	logger.Debug("recovered node wallet", slog.String("node address", nodeAddress.Hex()), slog.Duration("timeElapsed", time.Since(startTime)))

	pageStr := r.FormValue("page")
	var page uint64
	if pageStr == "" {
		page = uint64(1)
	} else {
		var err error
		pageInt64, err := strconv.ParseInt(pageStr, 10, 64)
		if err != nil {
			logger.Error("error parsing page", slog.String("error", err.Error()))
			returnErrorBox(w, r, logger, "Invalid page")
			return
		}
		page = uint64(pageInt64)
	}
	logger.Debug("recived page", slog.Uint64("page", page))

	var networkId uint64
	var beaconchainUrl string
	switch r.FormValue("network") {
	case "mainnet":
		networkId = MAINNET_NETWORK_ID
		beaconchainUrl = "https://beaconcha.in/api/v1/"
	case "holesky":
		networkId = HOLESKY_NETWORK_ID
		beaconchainUrl = "https://holesky.beaconcha.in/api/v1/"
	default:
		logger.Error("error parsing page", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Invalid network, only mainnet and holesky are supported")
		return
	}
	logger.Debug("recived network", slog.String("network", r.FormValue("network")), slog.Uint64("networkId", networkId))

	rpc, err := a.getRPC(logger, r.FormValue("rpc"), networkId)
	if err != nil {
		logger.Error("error connecting to RPC", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, err.Error())
		return
	}

	beaconchainApiKey := r.FormValue("beaconchainApiKey")
	if beaconchainApiKey != "" {
		logger.Debug("recived beaconchain api key", slog.String("beaconchainApiKey", beaconchainApiKey))
	}

	validators, totalCount, err := getExternalValidatorData(r.Context(), logger, startTime, rpc, beaconchainUrl, page, nodeAddress, beaconchainApiKey)
	if err != nil {
		logger.Error("error getting validators", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to get validators")
		return
	}
	logger.Debug("fetched validators", slog.Int("count", len(validators)), slog.Duration("timeElapsed", time.Since(startTime)))

	err = nodeWallet.RecoverValidatorPrivateKeys(validators)
	if err != nil {
		logger.Error("error recovering validator private keys", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to recover validator private keys")
		return
	}
	logger.Debug("recovered validator private keys", slog.Duration("timeElapsed", time.Since(startTime)))

	outWalletStr, err := nodeWallet.SerializeDataWithPassword()
	if err != nil {
		logger.Error("error getting wallet json", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to get wallet json")
		return
	}

	data := map[string]interface{}{
		"NodeAddress":  nodeAddress.Hex(),
		"NetworkId":    networkId,
		"Validators":   validators,
		"Page":         page,
		"PreviousPage": page - 1,
		"NextPage":     page + 1,
		"TotalPages":   (totalCount + MinipoolPerPage - 1) / MinipoolPerPage,
		"Data":         outWalletStr,
	}

	err = minipoolsTemplate.Execute(w, data)
	if err != nil {
		logger.Error("error rendering minipools", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to render minipools")
		return
	}
	logger.Info("minipools fetched", slog.Duration("timeElapsed", time.Since(startTime)))
}

func getExternalValidatorData(
	ctx context.Context,
	logger *slog.Logger,
	startTime time.Time,
	rpc *ethclient.Client,
	beaconchainUrl string,
	page uint64,
	nodeAddress common.Address,
	beaconchainApiKey string,
) ([]wallet.ValidatorData, uint64, error) {
	startIndex := (page - 1) * MinipoolPerPage
	endIndex := startIndex + MinipoolPerPage
	logger.Debug("recived page", slog.Uint64("page", page), slog.Uint64("startIndex", startIndex), slog.Uint64("endIndex", endIndex))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	mm, err := rocketpoolContracts.NewMinipoolManager(ctx, rpc, logger)
	if err != nil {
		return nil, 0, errors.Join(errors.New("failed to create minipool manager"), err)
	}

	totalCount, err := mm.GetMinipoolCount(ctx, nodeAddress)
	if err != nil {
		return nil, totalCount, errors.Join(errors.New("failed to get minipool count"), err)
	}
	// maxIndex := totalCount - 1
	logger.Debug("fetched minipool count",
		slog.Uint64("totalCount", totalCount),
		slog.Duration("timeElapsed", time.Since(startTime)),
	)

	if startIndex > totalCount {
		startIndex = totalCount
	}
	if endIndex > totalCount {
		endIndex = totalCount
	}

	minipools, err := mm.GetMinipools(ctx, nodeAddress, startIndex, endIndex)
	if err != nil {
		return nil, totalCount, errors.Join(errors.New("failed to get minipools"), err)
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
	url := fmt.Sprintf("%svalidator/%s", beaconchainUrl, strings.Join(validatorsPubKeys, ","))
	if beaconchainApiKey != "" {
		url += "?apikey=" + beaconchainApiKey
	}
	loggerWithUrl := logger.With("url", url)
	resp, err := http.Get(url)
	if err != nil {
		loggerWithUrl.Error("failed to get validators data", slog.String("error", err.Error()))
		return nil, totalCount, errors.Join(errors.New("failed to get validators data"), err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		loggerWithUrl.Error("failed to get validators data", slog.String("status", resp.Status))
		return nil, totalCount, errors.New("failed to get validators data")
	}

	// decode response based on the number of validators
	// for some reason the single validator response is different from the multiple validators response
	if len(validatorsPubKeys) == 1 {
		var beaconchaResponseSingle BeaconchaValidatorStatusResponseSingle
		if err := json.NewDecoder(resp.Body).Decode(&beaconchaResponseSingle); err != nil {
			loggerWithUrl.Error("failed to decode validators data", slog.String("error", err.Error()))
			return nil, totalCount, errors.Join(errors.New("failed to decode validators data"), err)
		}

		if beaconchaResponseSingle.Status != "OK" {
			loggerWithUrl.Error("beaconchain response status is not OK", slog.String("status", beaconchaResponseSingle.Status))
			return nil, totalCount, fmt.Errorf("beaconchain response status is not OK: %s", beaconchaResponseSingle.Status)
		}
		loggerWithUrl.Debug("fetched validators data", slog.Int("count", 1), slog.Duration("timeElapsed", time.Since(startTime)))

		validators[0].Index = beaconchaResponseSingle.Data.ValidatorIndex
		validators[0].Status = beaconchaResponseSingle.Data.Status
	} else {
		var beaconchaResponse BeaconchaValidatorStatusResponse
		if err := json.NewDecoder(resp.Body).Decode(&beaconchaResponse); err != nil {
			loggerWithUrl.Error("failed to decode validators data", slog.String("error", err.Error()))
			return nil, totalCount, errors.Join(errors.New("failed to decode validators data"), err)
		}

		if beaconchaResponse.Status != "OK" {
			loggerWithUrl.Error("beaconchain response status is not OK", slog.String("status", beaconchaResponse.Status))
			return nil, totalCount, fmt.Errorf("beaconchain response status is not OK: %s", beaconchaResponse.Status)
		}
		loggerWithUrl.Debug("fetched validators data", slog.Int("count", len(beaconchaResponse.Data)), slog.Duration("timeElapsed", time.Since(startTime)))

		if len(minipools) != len(beaconchaResponse.Data) {
			return nil, totalCount, errors.New("invalid response from beaconchain, wrong length")
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
	}

	return validators, totalCount, nil
}

func (a *App) GetSignExitHandler(w http.ResponseWriter, r *http.Request) {
	logger := a.logger.With("function", "SignExitMsg")
	startTime := time.Now()

	if err := r.ParseForm(); err != nil {
		logger.Error("error parsing form data", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to parse form data")
		return
	}

	var networkId uint64
	var beaconchainUrl string
	switch r.FormValue("network") {
	case "mainnet":
		networkId = MAINNET_NETWORK_ID
		beaconchainUrl = "https://beaconcha.in/api/v1/epoch/latest"
	case "holesky":
		networkId = HOLESKY_NETWORK_ID
		beaconchainUrl = "https://holesky.beaconcha.in/api/v1/epoch/latest"
	default:
		logger.Error("invalid netowrk id", slog.String("requested", r.FormValue("network")))
		returnErrorBox(w, r, logger, "Invalid netowrk id, only mainnet and holesky are supported")
		return
	}
	logger.Debug("recived network", slog.String("network", r.FormValue("network")), slog.Uint64("networkId", networkId))

	validatorKeyStr := r.FormValue("privateKey")
	if validatorKeyStr == "" {
		logger.Error("error missing private key")
		returnErrorBox(w, r, logger, "Private key is required")
		return
	}

	validatorKeyBytes, err := hex.DecodeString(validatorKeyStr)
	if err != nil {
		logger.Error("error decoding private key", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Validator key is incorrectly formated")
		return
	}

	validatorKey, err := eth2types.BLSPrivateKeyFromBytes(validatorKeyBytes)
	if err != nil {
		logger.Error("error converting private key", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Invalid private key")
		return
	}
	logger.Debug("recived private key", slog.String("validatorKeyStr", validatorKeyStr))

	validatorIndexStr := r.FormValue("validatorIndex")
	if validatorIndexStr == "" {
		logger.Error("error missing validator index")
		returnErrorBox(w, r, logger, "Validator index is required")
		return
	}

	beaconchainApiKey := r.FormValue("beaconchainApiKey")
	if beaconchainApiKey != "" {
		logger.Debug("recived beaconchain api key", slog.String("beaconchainApiKey", beaconchainApiKey))
		beaconchainUrl += "?apikey=" + beaconchainApiKey
	}

	epoch, err := getCurrentEpoch(r.Context(), logger, beaconchainUrl)
	if err != nil {
		logger.Error("error getting current epoch", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to get current epoch")
		return
	}
	logger.Debug("using current epoch", slog.Uint64("epoch", epoch), slog.Duration("timeElapsed", time.Since(startTime)))

	signatureDomain, err := getValidatorExitDomain(logger, networkId)
	if err != nil {
		logger.Error("error getting signature domain", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to get signature domain")
		return
	}

	logger.Debug("computed signature domain",
		slog.String("signatureDomain", hex.EncodeToString(signatureDomain)),
		slog.Duration("timeElapsed", time.Since(startTime)),
	)

	// use: https://github.com/rocket-pool/node-manager-core/blob/dfd914e4e77be54fbbf4ebb8e47d7578146bf429/node/validator/voluntary-exit.go#L13
	signature, err := nmc_validator.GetSignedExitMessage(validatorKey, validatorIndexStr, epoch, signatureDomain)
	if err != nil {
		logger.Error("error signing exit message", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to sign exit message")
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
		logger.Error("error rendering confirmation overlay", slog.String("error", err.Error()))
		returnErrorBox(w, r, logger, "Unable to render confirmation overlay")
		return
	}
	logger.Info("signature generated", slog.Duration("timeElapsed", time.Since(startTime)))
}

func getCurrentEpoch(ctx context.Context, logger *slog.Logger, url string) (uint64, error) {
	// get validator data from beaconchain
	resp, err := http.Get(url)
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

func returnErrorBox(w http.ResponseWriter, r *http.Request, logger *slog.Logger, errMsg string) {
	w.Header().Set("hx-retarget", "#error-box")
	w.Header().Set("hx-reswap", "outerHTML")
	err := errorTemplate.Execute(w, map[string]string{
		"ErrorMsg": errMsg,
	})
	if err != nil {
		logger.Error("error rendering", slog.String("error", err.Error()))
	}
}

func (a *App) getRPC(logger *slog.Logger, customRPC string, networkId uint64) (*ethclient.Client, error) {
	var rpcUrl string
	switch {
	case customRPC != "":
		rpcUrl = customRPC
	case networkId == MAINNET_NETWORK_ID:
		rpcUrl = a.mainnetRpcUrl
	case networkId == HOLESKY_NETWORK_ID:
		rpcUrl = a.holskyRpcUrl
	default:
		return nil, errors.New("invalid network id")
	}

	rpc, err := ethclient.Dial(rpcUrl)
	if err != nil {
		logger.Error("error connecting to RPC", slog.String("error", err.Error()))
		return nil, errors.New("failed to connect to custom RPC")
	}

	if customRPC != "" {
		customRpcNetworkId, err := rpc.NetworkID(context.Background())
		if err != nil {
			logger.Error("error connecting to RPC", slog.String("error", err.Error()))
			return nil, errors.New("failed to connect to custom RPC")
		}

		if customRpcNetworkId.Uint64() != networkId {
			logger.Error("error custom rpc for the wrong network", slog.Uint64("networkId", customRpcNetworkId.Uint64()))
			return nil, errors.New("custom RPC is for the wrong network")
		}

		logger.Info("connected to custom RPC", slog.String("rpcUrl", rpcUrl))
	} else {
		logger.Info("connected to default RPC", slog.String("rpcUrl", rpcUrl))
	}
	return rpc, nil
}
