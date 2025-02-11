package main

import (
	"flag"
	"justExitMyValidators/app"
	"log"
	"log/slog"
	"net/http"
)

const (
	DEFUALT_RPC_URL_MAINNET = "https://eth.llamarpc.com"
	DEFAULT_RPC_URL_HOLESKY = "https://holesky.gateway.tenderly.co"
)

func setupRoutes(app *app.App) (*http.ServeMux, error) {
	mux := http.NewServeMux()
	// serve images
	fs := http.FileServer(http.Dir("./images"))
	mux.Handle("/images/", http.StripPrefix("/images/", fs))

	// serve css
	css := http.FileServer(http.Dir("./public"))
	mux.Handle("/styles.css", css)

	// add routes
	mux.Handle("/", http.HandlerFunc(app.HomeFaq))
	mux.Handle("/guide", http.HandlerFunc(app.HomeGuide))
	mux.Handle("/content/faq", http.HandlerFunc(app.Faq))
	mux.Handle("/content/guide", http.HandlerFunc(app.Guide))
	mux.Handle("/content/mnemonic", http.HandlerFunc(app.GetMnemonicInput))
	mux.Handle("/content/mnemonic/submit", http.HandlerFunc(app.SubmitMnemonicHandler))
	mux.Handle("/content/minipools", http.HandlerFunc(app.GetMinipoolsHandler))
	mux.Handle("/content/validator/signExit", http.HandlerFunc(app.GetSignExitHandler))

	return mux, nil
}

func main() {
	debugPtr := flag.Bool("debug", false, "Enable debug mode")
	rpcMainnetPtr := flag.String("rpc-mainnet", "", "Ethereum RPC URL")
	rpcHoleskyPtr := flag.String("rpc-holesky", "", "Ethereum holesky RPC URL")
	portPtr := flag.String("port", "8080", "Port for the server to run on")
	flag.Parse()
	if *debugPtr {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	logger := slog.Default()

	mainnetRpcUrl := DEFUALT_RPC_URL_MAINNET
	if *rpcMainnetPtr != "" {
		mainnetRpcUrl = *rpcMainnetPtr
	}

	holskyRpcUrl := DEFAULT_RPC_URL_HOLESKY
	if *rpcHoleskyPtr != "" {
		holskyRpcUrl = *rpcHoleskyPtr
	}
	logger.Debug("configured rpcs", slog.String("mainnetRpc", mainnetRpcUrl), slog.String("holskyRpc", holskyRpcUrl))

	app := app.NewApp(logger, mainnetRpcUrl, holskyRpcUrl)
	mux, err := setupRoutes(app)
	if err != nil {
		log.Fatal(err)
	}

	addr := "127.0.0.1" + ":" + *portPtr
	log.Printf("Server running on %s...\n", addr)
	err = http.ListenAndServe(addr, mux)
	log.Fatal(err)
}
