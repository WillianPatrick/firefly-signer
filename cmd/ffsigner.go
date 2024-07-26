// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/internal/rpcserver"
	"github.com/hyperledger/firefly-signer/internal/signerconfig"
	"github.com/hyperledger/firefly-signer/internal/signermsgs"
	"github.com/hyperledger/firefly-signer/pkg/azurekeyvault"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/fswallet"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sigs = make(chan os.Signal, 1)

var rootCmd = &cobra.Command{
	Use:   "ffsigner",
	Short: "Hyperledger FireFly Signer",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}

var cfgFile string

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "f", "", "config file")
	rootCmd.AddCommand(versionCommand())
	rootCmd.AddCommand(configCommand())
}

func Execute() error {
	return rootCmd.Execute()
}

func initConfig() {
	signerconfig.Reset()
}

func run() error {
	initConfig()
	router := mux.NewRouter()
	err := config.ReadConfig("ffsigner", cfgFile)

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()
	ctx = log.WithLogger(ctx, logrus.WithField("pid", fmt.Sprintf("%d", os.Getpid())))
	ctx = log.WithLogger(ctx, logrus.WithField("prefix", "ffsigner"))

	config.SetupLogging(ctx)

	if err != nil {
		cancelCtx()
		return i18n.WrapError(ctx, err, i18n.MsgConfigFailed)
	}

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.L(ctx).Infof("Shutting down due to %s", sig.String())
		cancelCtx()
	}()

	var wallet ethsigner.Wallet

	switch {
	case config.GetBool(signerconfig.KeyVaultEnabled):
		azureWallet, err := azurekeyvault.NewAzureKeyVaultWallet(ctx, azurekeyvault.ReadConfig(signerconfig.KeyVaultConfig))
		if err != nil {
			return err
		}
		wallet = azureWallet
	case config.GetBool(signerconfig.FileWalletEnabled):
		fileWallet, err := fswallet.NewFilesystemWallet(ctx, fswallet.ReadConfig(signerconfig.FileWalletConfig))
		if err != nil {
			return err
		}
		wallet = fileWallet
	default:
		return i18n.NewError(ctx, signermsgs.MsgNoWalletEnabled)
	}

	router.HandleFunc("/wallets/create", createWalletHandler(wallet)).Methods("POST")

	server, err := rpcserver.NewServer(ctx, wallet)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:         ":8555",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  90 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.L(ctx).Errorf("HTTP server failed: %s", err)
		}
	}()

	return runServer(server)
}

type CreateWalletRequest struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
}

type CreateWalletResponse struct {
	Address string `json:"address"`
}

func createWalletHandler(wallet ethsigner.Wallet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req CreateWalletRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := context.Background()
		address, err := wallet.CreateWallet(ctx, req.Password, req.PrivateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := CreateWalletResponse{
			Address: address.String(),
		}

		if err := wallet.Refresh(ctx); err != nil {
			log.L(ctx).Errorf("Failed to refresh wallet: %s", err)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.L(ctx).Errorf("Failed to encode response: %s", err)
		}
	}
}

func runServer(server rpcserver.Server) error {
	err := server.Start()
	if err == nil {
		err = server.WaitStop()
	}
	return err
}
