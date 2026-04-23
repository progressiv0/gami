package main

import (
	"fmt"
	"os"

	"github.com/progressiv0/gami/gami-api/config"
	"github.com/progressiv0/gami/gami-api/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	if err := server.ListenAndServe(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
