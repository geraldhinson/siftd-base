package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// these are for signing JWT tokens for testing purposes only
const LocalPrivateKeyFilename = "/private.pem"
const LocalPublicKeyFilename = "/public.pem"

type KeyStore struct {
	logger           *logrus.Logger
	configuration    *viper.Viper
	publicKeys       publicKeyMap
	privateKeys_test privateKeyMap
	currentKid_test  string
	debugLevel       int
}

func NewFakeKeyStore(configuration *viper.Viper, logger *logrus.Logger) *KeyStore {
	var debugLevel = 0
	if configuration.GetString(constants.DEBUGSIFTD_AUTH) != "" {
		debugLevel = configuration.GetInt(constants.DEBUGSIFTD_AUTH)
	}

	keyStore := &KeyStore{logger: logger, configuration: configuration, debugLevel: debugLevel}
	keyStore.publicKeys = make(publicKeyMap)
	keyStore.privateKeys_test = make(privateKeyMap)

	keyStore.generatePrivPubKeys()

	return keyStore
}

func (k *KeyStore) GetPublicKey(kid string) ([]byte, error) {
	if key, ok := k.publicKeys[kid]; ok {
		return key.PublicKeyBytes, nil
	}
	return nil, fmt.Errorf("public key not found")
}

// JwtFakeUserLogin and JwtFakeServiceLogin both create a fake JWT token with a hard-coded id for testing purposes only
// This is useful for testing the API without the need of procuring a real JWT token signed by a legit key (aka a dangerous/real one).
// The P/p key pair used for this is generated on the fly every time this service starts up.
func (k *KeyStore) JwtFakeUserLogin() (based64JWT []byte, err error) {

	// ensure that we are only running this in a local environment
	listenAddress := k.configuration.GetString(constants.LISTEN_ADDRESS)
	if !strings.Contains(listenAddress, "localhost") {
		return nil, fmt.Errorf("fake JWT tokens can only be generated when the queries service is listening on localhost")
	}

	// Create the JWT token
	token := jwt.New(jwt.SigningMethodRS256)

	// Claims
	header := token.Header
	header["alg"] = "RS256"
	header["typ"] = "JWT"
	header["kid"] = k.currentKid_test
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = uuid.New().String()
	claims["sub"] = "GUID-fake-member-GUID"
	claims["sub_type"] = "Member"
	claims["sub_name"] = "Fake (Member) User"
	claims["iat"] = time.Now().Add(time.Hour).Unix() // TODO: why add an hour vs current time? Bug?
	claims["iss"] = "siftd-service-base"
	claims["roles"] = []string{"admin"}

	// Sign the token
	tokenString, err := token.SignedString(k.GetPrivateKeyInUse())
	if err != nil {
		return nil, err
	}

	return []byte(tokenString), nil
}

func (k *KeyStore) JwtFakeServiceLogin() (based64JWT []byte, err error) {

	// ensure that we are only running this in a local environment
	listenAddress := k.configuration.GetString(constants.LISTEN_ADDRESS)
	if !strings.Contains(listenAddress, "localhost") {
		return nil, fmt.Errorf("fake JWT tokens can only be generated when the queries service is listening on localhost")
	}

	// Create the JWT token
	token := jwt.New(jwt.SigningMethodRS256)

	// Claims
	header := token.Header
	header["alg"] = "RS256"
	header["typ"] = "JWT"
	header["kid"] = k.currentKid_test
	claims := token.Claims.(jwt.MapClaims)
	claims["jti"] = uuid.New().String()
	claims["sub"] = "GUID-fake-service-GUID"
	claims["sub_type"] = "Machine"
	claims["sub_name"] = "Fake (Machine) Service"
	claims["iat"] = time.Now().Add(time.Hour).Unix() // TODO: why add an hour vs current time? Bug?
	claims["iss"] = "siftd-service-base"

	// Sign the token
	tokenString, err := token.SignedString(k.GetPrivateKeyInUse())
	if err != nil {
		return nil, err
	}

	return []byte(tokenString), nil
}

func (k *KeyStore) GetPrivateKeyInUse() *rsa.PrivateKey {
	prvKey, err := x509.ParsePKCS1PrivateKey(k.privateKeys_test[k.currentKid_test].privateKeyBytes)
	if err != nil {
		k.logger.Fatalf("Failed to parse (test) private key: %v", err)
		return nil
	}

	return prvKey
}

// for signing fake JWT tokens for testing purposes only
func (k *KeyStore) generatePrivPubKeys() {
	path := k.configuration.GetString("RESDIR_PATH")

	// generate key pair
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		k.logger.Fatalf("Cannot generate RSA key pair for testing: %s \n", err)
	}
	publickey := &privatekey.PublicKey
	timeCreated := time.Now().Unix()

	// create kid for lookup of keys
	k.currentKid_test = uuid.New().String()
	if k.debugLevel > 0 {
		k.logger.Infof("FakeKeyStore: the key id for private/public key pair generated is: %s", k.currentKid_test)
	}

	var privateKeyMap RSAPrivateKey
	//	privateKeyMap.kid = k.currentKid_test
	privateKeyMap.createdTime = timeCreated
	privateKeyMap.privateKeyBytes = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyMap.privateKeyBytes,
	}
	k.privateKeys_test[k.currentKid_test] = privateKeyMap

	privatePem, err := os.Create(path + LocalPrivateKeyFilename)
	if err != nil {
		k.logger.Fatalf("Error when creating private.pem for testing: %s", err)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		k.logger.Fatalf("Error when encoding private pem for testing: %s", err)
	}

	// dump public key to file
	var publicKeyMap RSAPublicKey
	//	publicKeyMap.kid = k.currentKid_test
	publicKeyMap.createdTime = timeCreated
	publicKeyMap.PublicKeyBytes, err = x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		k.logger.Fatalf("Error when dumping publickey for testing: %s", err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyMap.PublicKeyBytes,
	}
	k.publicKeys[k.currentKid_test] = publicKeyMap

	publicPem, err := os.Create(path + LocalPublicKeyFilename)
	if err != nil {
		k.logger.Fatalf("Error when creating public.pem for testing: %s", err)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		k.logger.Fatalf("Error when encoding public pem for testing: %s", err)
	}
}
