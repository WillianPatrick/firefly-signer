package awskms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	kms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/karlseguin/ccache"
)

type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error)
	AddMappingKeyAddress(key string, address string) error
	Initialize(ctx context.Context) error
	Close() error
}

type kmsWallet struct {
	conf           Config
	signerCache    *ccache.Cache
	signerCacheTTL time.Duration
	mux            sync.Mutex
	kmsClient      *kms.Client
	smClient       *sm.Client
	stopRefresh    chan struct{}
	addressToKeyID map[common.Address]string
}

func NewAWSKMSWallet(ctx context.Context, conf *Config) (Wallet, error) {
	w := &kmsWallet{
		conf: *conf,
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(conf.Region))
	if err != nil {
		return nil, err
	}

	w.kmsClient = kms.NewFromConfig(awsCfg)
	w.smClient = sm.NewFromConfig(awsCfg)

	maxSize := conf.Cache.MaxSize
	if maxSize == 0 {
		maxSize = int64(100)
	}
	itemsToPrune := conf.Cache.ItemsToPrune
	if itemsToPrune == 0 {
		itemsToPrune = uint32(10)
	}

	w.signerCache = ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))

	w.addressToKeyID = make(map[common.Address]string)

	return w, nil
}

func (w *kmsWallet) Initialize(ctx context.Context) error {
	if w.conf.MappingKeyAddress.Enabled && w.conf.MappingKeyAddress.Refresh.Enabled {
		w.startRefreshLoop(ctx)
	}
	return nil
}

func (w *kmsWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.RemoteSign {
		return w.LocalSign(ctx, txn, chainID)
	}
	return w.RemoteSign(ctx, txn, chainID)
}

func (w *kmsWallet) LocalSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AWSKMS - Local Sign - Chain ID: %d - From: %s, Unsigned transaction txn: %s", chainID, key, string(unsignedTxBytes))

	item := w.signerCache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretName := strings.TrimPrefix(key, "0x")
		secretResp, err := w.smClient.GetSecretValue(ctx, &sm.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			return nil, err
		}
		privateKey = *secretResp.SecretString
		w.signerCache.Set(key, privateKey, w.signerCacheTTL)
	}

	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	signedTx, err := txn.Sign(keypair, chainID)
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AWSKMS - Local Sign - Chain ID: %d - From: %s, Signed transaction: %s", chainID, key, hex.EncodeToString(signedTx))

	return signedTx, nil
}

func (w *kmsWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxnJson, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AWSKMS - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction txn: %s", chainID, key, string(unsignedTxnJson))

	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    txn.Nonce.Uint64(),
		To:       (*common.Address)(txn.To),
		Value:    txn.Value.BigInt(),
		Gas:      txn.GasLimit.Uint64(),
		GasPrice: txn.GasPrice.BigInt(),
		Data:     txn.Data,
	})

	hash := signer.Hash(tx)

	keyID, err := w.getKeyIDForAddress(from)
	if err != nil {
		return nil, err
	}

	signInput := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          hash[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	signOutput, err := w.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return nil, err
	}

	derSignature := signOutput.Signature

	r, s, err := parseDERSignature(derSignature)
	if err != nil {
		return nil, err
	}

	// Certifique-se de que 's' está na metade inferior
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)

	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	signature := append(rPadded, sPadded...)

	// Recuperar o ID de recuperação (v)
	publicKey, err := w.getPublicKeyForKeyID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	recID := -1
	for i := 0; i < 2; i++ {
		v := byte(i + 27)
		sig := append(signature, v)
		pubKeyRecovered, err := crypto.SigToPub(hash[:], sig)
		if err == nil && pubKeyRecovered != nil {
			pubKeyBytes := crypto.FromECDSAPub(pubKeyRecovered)
			expectedPubKeyBytes := crypto.FromECDSAPub(publicKey)
			if bytes.Equal(pubKeyBytes, expectedPubKeyBytes) {
				recID = i
				break
			}
		}
	}

	if recID == -1 {
		return nil, errors.New("Falha ao recuperar a chave pública")
	}

	v := byte(recID + 27 + int(chainID)*2 + 8)

	sig := append(signature, v)

	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return nil, err
	}

	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return signedTxBytes, nil
}

func parseDERSignature(der []byte) (r, s *big.Int, err error) {
	var sig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, nil, err
	}
	return sig.R, sig.S, nil
}

func (w *kmsWallet) getKeyIDForAddress(address ethtypes.Address0xHex) (string, error) {
	if keyID, exists := w.addressToKeyID[common.Address(address)]; exists {
		return keyID, nil
	}
	return "", errors.New("Key ID não encontrado para o endereço")
}

func (w *kmsWallet) getPublicKeyForKeyID(ctx context.Context, keyID string) (*ecdsa.PublicKey, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	}
	output, err := w.kmsClient.GetPublicKey(ctx, input)
	if err != nil {
		return nil, err
	}
	pubKeyInterface, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("A chave pública não é ECDSA")
	}
	return pubKey, nil
}

func (w *kmsWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.RemoteSign {
		address, err := w.CreateSecret(ctx, password, privateKeyHex)
		if err != nil {
			return ethsigner.CreateWalletResponse{}, err
		}
		return ethsigner.CreateWalletResponse{
			Address: strings.TrimPrefix(address.String(), "0x"),
		}, nil
	}
	return w.CreateKey(ctx, privateKeyHex)
}

func (w *kmsWallet) CreateSecret(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) {
	var keypair *secp256k1.KeyPair
	var err error
	if privateKeyHex == "" {
		keypair, err = secp256k1.GenerateSecp256k1KeyPair()
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
	} else {
		privateKey, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
		keypair, err = secp256k1.NewSecp256k1KeyPair(privateKey)
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
	}
	err = w.storeKeyPairInSecretsManager(ctx, keypair)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}
	return keypair.Address, nil
}

func (w *kmsWallet) storeKeyPairInSecretsManager(ctx context.Context, keypair *secp256k1.KeyPair) error {
	secretName := strings.TrimPrefix(keypair.Address.String(), "0x")
	secretValue := hex.EncodeToString(keypair.PrivateKeyBytes())

	_, err := w.smClient.CreateSecret(ctx, &sm.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretString: aws.String(secretValue),
		Tags: []smtypes.Tag{
			{
				Key:   aws.String("EthereumAddress"),
				Value: aws.String(keypair.Address.String()),
			},
		},
	})

	if err != nil {
		if strings.Contains(err.Error(), "ResourceExistsException") {
			// Atualizar o segredo existente
			_, err = w.smClient.PutSecretValue(ctx, &sm.PutSecretValueInput{
				SecretId:     aws.String(secretName),
				SecretString: aws.String(secretValue),
			})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return nil
}

func (w *kmsWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if privateKeyHex != "" {
		address, keyID, err := w.ImportKey(ctx, privateKeyHex)
		if err != nil {
			return ethsigner.CreateWalletResponse{}, err
		}
		return ethsigner.CreateWalletResponse{
			Address: strings.TrimPrefix(address.String(), "0x"),
			KeyName: keyID,
		}, nil
	}

	input := &kms.CreateKeyInput{
		KeySpec:  kmstypes.KeySpecEccSecgP256k1,
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		Origin:   kmstypes.OriginTypeAwsKms,
	}
	output, err := w.kmsClient.CreateKey(ctx, input)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, err
	}

	keyID := *output.KeyMetadata.KeyId

	pubKey, err := w.getPublicKeyForKeyID(ctx, keyID)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, err
	}

	address := crypto.PubkeyToAddress(*pubKey)

	w.addressToKeyID[address] = keyID

	return ethsigner.CreateWalletResponse{
		Address: strings.TrimPrefix(address.Hex(), "0x"),
		KeyName: keyID,
	}, nil
}

func (w *kmsWallet) ImportKey(ctx context.Context, privateKeyHex string) (ethtypes.Address0xHex, string, error) {
	return ethtypes.Address0xHex{}, "", errors.New("Importação de chaves privadas não suportada no AWS KMS")
}

func (w *kmsWallet) AddMappingKeyAddress(key string, address string) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return errors.New("Recurso de mapeamento não habilitado")
	}
	w.addressToKeyID[common.HexToAddress(address)] = key
	return nil
}

func (w *kmsWallet) Close() error {
	if w.stopRefresh != nil {
		close(w.stopRefresh)
	}
	return nil
}

func (w *kmsWallet) startRefreshLoop(ctx context.Context) {
	if !w.conf.MappingKeyAddress.Enabled || !w.conf.MappingKeyAddress.Refresh.Enabled {
		return
	}

	if w.conf.MappingKeyAddress.Refresh.Interval <= 0 {
		return
	}

	w.stopRefresh = make(chan struct{})

	go func() {
		ticker := time.NewTicker(w.conf.MappingKeyAddress.Refresh.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := w.refreshAddressToKeyIDMapping(ctx); err != nil {
					log.L(ctx).Errorf("Falha ao atualizar o mapeamento address-to-keyID: %v", err)
				}
			case <-w.stopRefresh:
				return
			}
		}
	}()
}

func (w *kmsWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	// Implementar se necessário
	return nil, errors.New("SignTypedDataV4 não implementado")
}

func (w *kmsWallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	accounts := make([]*ethtypes.Address0xHex, 0, len(w.addressToKeyID))
	for address := range w.addressToKeyID {
		addr := ethtypes.Address0xHex(address)
		accounts = append(accounts, &addr)
	}
	return accounts, nil
}

func (w *kmsWallet) Refresh(ctx context.Context) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return nil
	}
	return w.refreshAddressToKeyIDMapping(ctx)
}

func (w *kmsWallet) refreshAddressToKeyIDMapping(ctx context.Context) error {
	log.L(ctx).Debugf("Atualizando mapeamento de endereços...")

	var nextToken *string

	for {
		input := &kms.ListKeysInput{
			Marker: nextToken,
		}
		output, err := w.kmsClient.ListKeys(ctx, input)
		if err != nil {
			return err
		}

		for _, key := range output.Keys {
			keyID := *key.KeyId
			keyDesc, err := w.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: aws.String(keyID),
			})
			if err != nil {
				continue
			}

			if keyDesc.KeyMetadata.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
				continue
			}

			pubKey, err := w.getPublicKeyForKeyID(ctx, keyID)
			if err != nil {
				continue
			}

			address := crypto.PubkeyToAddress(*pubKey)
			w.addressToKeyID[address] = keyID
		}

		if output.Truncated {
			nextToken = output.NextMarker
		} else {
			break
		}
	}

	log.L(ctx).Debugf("Atualizado: %d endereços mapeados", len(w.addressToKeyID))

	return nil
}
