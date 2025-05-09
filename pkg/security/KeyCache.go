package security

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type RSAPublicKey struct {
	PublicKeyBytes []byte
	// current time when this struct was created
	// this is used to determine when to purge the cache
	// of public keys
	createdTime int64
	// kid            string
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

	// loop through all keys and purge any that are older than 15 minutes
	for kid, key := range k.publicKeys {
		if time.Now().Unix()-key.createdTime > int64(expiryTime) {
			if k.debugLevel > 0 {
				k.logger.Infof("key cache - Purging old key: %s", kid)
			}
			k.mutex.Lock()
			delete(k.publicKeys, kid)
			k.mutex.Unlock()
		}
	}
}

func (k *KeyCache) GetPublicKeyById(kid string) *rsa.PublicKey {
	k.PurgeOldKeys()

	// Check if the key is already in the cache
	var publicKeyBytes []byte
	var err error
	var foundInCache bool = false

	k.mutex.Lock()
	key, ok := k.publicKeys[kid]
	k.mutex.Unlock()
	if ok {
		foundInCache = true
		if k.debugLevel > 0 {
			k.logger.Infof("key cache - Key found in cache: %s", kid)
		}
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
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		k.logger.Infof("key cache - failed to parse public key: %v", err)
		return nil
	}

	// Assert that the key is an RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		k.logger.Info("key cache - Public key found is not an RSA key")
		return nil
	}

	if !foundInCache {
		// Add the key to the cache
		timeCreated := time.Now().Unix()
		k.mutex.Lock()
		k.publicKeys[kid] = RSAPublicKey{PublicKeyBytes: publicKeyBytes, createdTime: timeCreated}
		k.mutex.Unlock()
	}

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
		caCertPool.AppendCertsFromPEM(caCert)

		client := &http.Client{
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
		res, err = http.DefaultClient.Do(req)
		if err != nil {
			err = fmt.Errorf("key cache - http client call to identity service failed with : %s", err)
			return nil, err
		}
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("key cache - unable to read identity service reply: %s", err)
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("key cache - identity service returned status code: %d", res.StatusCode)
		return nil, err
	}

	// resBody is the public key, return it
	return resBody, nil
}
