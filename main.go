package main

import (
	"flag"
	"justExitMyValidators/app"
	"log"
	"log/slog"
	"net/http"
)

func setupRoutes(logger *slog.Logger) (*http.ServeMux, error) {
	app := app.NewApp(logger)

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(app.Home))
	mux.Handle("/mnemonic", http.HandlerFunc(app.GetMnemonicInput))
	mux.Handle("/mnemonic/submit", http.HandlerFunc(app.SubmitMnemonicHandler))
	mux.Handle("/minipools", http.HandlerFunc(app.GetMinipoolsHandler))
	mux.Handle("/validator/signExit", http.HandlerFunc(app.GetSignExitHandler))
	// var validatorPath = regexp.MustCompile("^m/12381/3600/[0-9]+/0/0$")

	return mux, nil
}

func main() {
	debugPtr := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()
	if *debugPtr {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	logger := slog.Default()

	mux, err := setupRoutes(logger)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Server running on :8080...")
	err = http.ListenAndServe("127.0.0.1:8080", mux)
	log.Fatal(err)
}
