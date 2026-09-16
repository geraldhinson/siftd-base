package security

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	//	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type RSAJWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type RSAPublicKey struct {
	PublicKeyBytes  []byte
	ParsedPublicKey *rsa.PublicKey
	// current time when this struct was created
	// this is used to determine when to purge the cache
	// of public keys
	createdTime int64
}

type RSAPrivateKey struct {
	privateKeyBytes []byte
	createdTime     int64
	// kid             string
}
type publicKeyMap map[string]RSAPublicKey
type privateKeyMap map[string]RSAPrivateKey

type KeyCache struct {
	mutex         sync.Mutex
	publicKeys    publicKeyMap
	logger        *logrus.Logger
	configuration *viper.Viper
	debugLevel    int
}

func NewPublicKeyCache(configuration *viper.Viper, logger *logrus.Logger) *KeyCache {
	var debugLevel = 0
	if configuration.GetString(constants.DEBUGSIFTD_AUTH) != "" {
		debugLevel = configuration.GetInt(constants.DEBUGSIFTD_AUTH)
	}

	keyCache := &KeyCache{logger: logger, configuration: configuration, debugLevel: debugLevel}
	keyCache.publicKeys = make(publicKeyMap)

	return keyCache
}

func (k *KeyCache) PurgeOldKeys() {
	// hard-coded cache expiry policy of 15 minutes for now
	var expiryTime int64 = 900 // 15 minutes in seconds

	k.mutex.Lock()
	defer k.mutex.Unlock()

	// loop through all keys and purge any that are older than 15 minutes
	for kid, key := range k.publicKeys {
		if time.Now().Unix()-key.createdTime > int64(expiryTime) {
			if k.debugLevel > 0 {
				k.logger.Infof("key cache - Purging old key: %s", kid)
			}
			delete(k.publicKeys, kid)
		}
	}
}

func (k *KeyCache) GetPublicKeyById(kid string) *rsa.PublicKey {
	k.PurgeOldKeys()

	// Check if the key is already in the cache
	var publicKeyBytes []byte
	var err error

	k.mutex.Lock()
	key, ok := k.publicKeys[kid]
	k.mutex.Unlock()
	if ok {
		if k.debugLevel > 0 {
			k.logger.Infof("key cache - Key found in cache: %s", kid)
		}

		if key.ParsedPublicKey != nil { // should never be nil currently
			return key.ParsedPublicKey
		}

		// Defensive fallback for an entry that contains only encoded bytes.
		publicKeyBytes = key.PublicKeyBytes

	} else {
		if k.debugLevel > 0 {
			k.logger.Infof("key cache - Key not found in cache: %s", kid)
		}
		publicKeyBytes, err = k.FetchPublicKeyFromIdentityService(kid)
		if err != nil {
			if k.debugLevel > 0 {
				k.logger.Infof("key cache - failed to fetch public key from identity service: %v", err)
			}
			return nil
		}
	}

	// Parse the public key
	var rsaPubKey *rsa.PublicKey
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	//	if err != nil {
	//		k.logger.Infof("key cache - failed to parse public key: %v", err)
	//		return nil
	//	}
	if err == nil {
		var ok bool
		rsaPubKey, ok = pubKey.(*rsa.PublicKey)
		if !ok {
			k.logger.Info("key cache - Public key found is not an RSA key")
			return nil
		}
	} else {
		// 2️⃣ Fallback: attempt JWKS / JWK parsing (Supabase RS256)

		var jwk RSAJWK
		if err := json.Unmarshal(publicKeyBytes, &jwk); err != nil {
			k.logger.Infof("key cache - failed to parse public key as x509 or jwk: %v", err)
			return nil
		}

		if jwk.Kty != "RSA" {
			k.logger.Info("key cache - JWK is not RSA")
			return nil
		}

		// Decode modulus (n)
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			k.logger.Infof("key cache - failed to decode jwk modulus: %v", err)
			return nil
		}

		// Decode exponent (e)
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			k.logger.Infof("key cache - failed to decode jwk exponent: %v", err)
			return nil
		}

		e := new(big.Int).SetBytes(eBytes).Int64()
		if e > int64(^uint(0)>>1) {
			k.logger.Info("key cache - RSA exponent overflow")
			return nil
		}

		rsaPubKey = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(e),
		}

		/*
			// publicKeyBytes contains ONLY jwk["n"]
			modulusBytes, err := base64.RawURLEncoding.DecodeString(string(publicKeyBytes))
			if err != nil {
				k.logger.Infof("key cache - failed to base64url decode modulus: %v", err)
				return nil
			}

			rsaPubKey = &rsa.PublicKey{
				N: new(big.Int).SetBytes(modulusBytes),
				E: 65537, // Supabase RS256 exponent (AQAB)
			}
		*/
	}

	// Assert that the key is an RSA public key
	//	rsaPubKey, ok = pubKey.(*rsa.PublicKey)
	//	if !ok {
	//		k.logger.Info("key cache - Public key found is not an RSA key")
	//		return nil
	//	}

	// Add the key to the cache
	timeCreated := time.Now().Unix()
	k.mutex.Lock()
	k.publicKeys[kid] = RSAPublicKey{PublicKeyBytes: publicKeyBytes, ParsedPublicKey: rsaPubKey, createdTime: timeCreated}
	k.mutex.Unlock()

	return rsaPubKey
}

func (k *KeyCache) FetchPublicKeyFromIdentityService(kid string) ([]byte, error) {

	listenAddress := k.configuration.GetString(constants.IDENTITY_SERVICE)
	if listenAddress == "" {
		err := fmt.Errorf("key cache - unable to retrieve listen address and port for the identity service - shutting down")
		return nil, err
	}

	requestURL := fmt.Sprintf("%s/v1/keys/%s", listenAddress, kid)
	if k.debugLevel > 0 {
		k.logger.Infof("key cache - calling identity service to fetch public key: %s", requestURL)
	}

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		err = fmt.Errorf("key cache - failed to build identity service request: %s", err)
		return nil, err
	}

	const identityServiceTimeout = 10 * time.Second

	var res *http.Response
	if strings.Contains(listenAddress, "https") && strings.Contains(requestURL, "localhost") {
		// all of this is required if this service is acting as a fake identity service and listening on
		// localhost with a self-signed cert. We have to setup the client call to trust the self-signed cert
		// just like we have to do for postman or a browser.
		path := k.configuration.GetString("RESDIR_PATH")
		if path == "" {
			err = fmt.Errorf("key cache - unable to retrieve RESDIR_PATH - shutting down")
			return nil, err
		}
		httpsListenCert := k.configuration.GetString(constants.HTTPS_CERT_FILENAME)
		if httpsListenCert == "" {
			err = fmt.Errorf("key cache - unable to retrieve HTTPS certificate file name - shutting down")
			return nil, err
		}

		caCert, error := os.ReadFile(path + "/" + httpsListenCert)
		if error != nil {
			return nil, error
		}
		caCertPool := x509.NewCertPool()

		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			err := fmt.Errorf(
				"key cache - unable to add the configured localhost certificate %q to the trusted certificate pool; verify that the file contains a valid PEM CERTIFICATE block",
				httpsListenCert,
			)
			k.logger.Warn(err)
			return nil, err
		}

		client := &http.Client{
			Timeout: identityServiceTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caCertPool,
					ServerName: "localhost", // must match SAN
					//				InsecureSkipVerify: true,
				},
			},
		}
		res, err = client.Do(req)
		if err != nil {
			err = fmt.Errorf("key cache - client call to localhost (aka fake) identity service failed with : %s", err)
			return nil, err
		}
	} else {
		// this is the normal case where we are calling the identity service
		// and it is not localhost and we are not using a self-signed cert
		client := &http.Client{
			Timeout: identityServiceTimeout,
		}

		res, err = client.Do(req)
		if err != nil {
			err = fmt.Errorf("key cache - http client call to identity service failed with : %s", err)
			return nil, err
		}
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("key cache - identity service returned status code: %d", res.StatusCode)
		return nil, err
	}

	// read body but set an upper limit for self defense in case something unexpected / invalid is returned
	const maxPublicKeyResponseSize = 64 * 1024

	limitedReader := io.LimitReader(
		res.Body,
		maxPublicKeyResponseSize+1,
	)
	resBody, err := io.ReadAll(limitedReader)
	if err != nil {
		err = fmt.Errorf("key cache - unable to read identity service reply: %s", err)
		return nil, err
	}
	if len(resBody) > maxPublicKeyResponseSize {
		return nil, fmt.Errorf(
			"key cache - identity service response exceeded %d bytes",
			maxPublicKeyResponseSize,
		)
	}
	// resBody is the public key, return it
	return resBody, nil
}
