package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/geraldhinson/siftd/service-base/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type AuthTypes int

const (
	NO_AUTH AuthTypes = iota
	VALID_IDENTITY
	MATCHING_IDENTITY
	MATCHING_GROUP
	MACHINE_IDENTITY
)

type AuthTimeout int

const (
	// JWT_SECRET is the secret key used to sign the JWT token
	ONE_HOUR AuthTimeout = 3600
	ONE_DAY  AuthTimeout = 86400
)

type AuthGroups string
type AuthModel struct {
	Configuration  *viper.Viper
	Logger         *logrus.Logger
	KeyCache       *KeyCache
	tokenTimeout   AuthTimeout // in seconds
	authTypes      []AuthTypes
	acceptedGroups []AuthGroups
}

func NewAuthModel(configuration *viper.Viper, Logger *logrus.Logger, KeyCache *KeyCache, authTypes []AuthTypes) *AuthModel {
	var authModelUsers = NewAuthModelExpanded(
		configuration,
		Logger,
		KeyCache,
		ONE_DAY,
		authTypes,
		nil,
	)
	if authModelUsers == nil {
		Logger.Info("Failed to initialize AuthModel")
	}
	return authModelUsers
}

func NewAuthModelExpanded(configuration *viper.Viper, Logger *logrus.Logger, KeyCache *KeyCache, authTimeout AuthTimeout, authTypes []AuthTypes, acceptedGroups []AuthGroups) *AuthModel {
	Logger.Info("---------------------------------------")
	Logger.Info("New Auth Model being created as:")

	// Check the timeout
	Logger.Info("Tokens timeout after:")
	switch authTimeout {
	case ONE_HOUR:
		Logger.Info("  One Hour")
	case ONE_DAY:
		Logger.Info("  One Day")
	default:
		Logger.Info(" Token timeout: Unknown Timeout - Aborting")
		return nil
	}

	// Check the auth types
	Logger.Info("Accepted Auth Models are:")
	for _, authType := range authTypes {
		switch authType {
		case NO_AUTH:
			Logger.Info("  No Auth")
		case VALID_IDENTITY:
			Logger.Info("  Valid Identity")
		case MATCHING_IDENTITY:
			Logger.Info("  Matching Identity")
		case MATCHING_GROUP:
			Logger.Info("  Matching Group")
		case MACHINE_IDENTITY:
			Logger.Info("  Machine Identity")
		default:
			Logger.Info(" Unknown Auth Type - Aborting")
			return nil
		}
	}

	// Check the accepted groups?
	if acceptedGroups == nil {
		if slices.Contains(authTypes, MATCHING_GROUP) {
			Logger.Info(" No groups were provided for the MATCHING_GROUP auth option - Aborting")
			return nil
		}
	} else {
		if !slices.Contains(authTypes, MATCHING_GROUP) {
			Logger.Info(" Groups were provided without an accompanying MATCHING_GROUP auth option - Aborting")
			return nil
		}
	}

	Logger.Info("Accepted Groups:")
	for _, group := range acceptedGroups {
		Logger.Print(" ")
		Logger.Info(group)
	}

	Logger.Info("---------------------------------------")

	return &AuthModel{
		Configuration:  configuration,
		Logger:         Logger,
		KeyCache:       KeyCache,
		tokenTimeout:   authTimeout,
		authTypes:      authTypes,
		acceptedGroups: acceptedGroups,
	}
}

func (a *AuthModel) jwtAuthNCallback(token *jwt.Token) (interface{}, error) {
	// Return the key for validation (replace with your actual key)
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	iat, err := token.Claims.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("error getting issued at claim: %v", err)
	}
	// check if iat was issue over our configured expiry time above
	var timeout = a.tokenTimeout
	if (token.Claims.(jwt.MapClaims)["sub_type"]) == "Machine" {
		timeout = ONE_HOUR
	}

	var expiry = iat.Add(time.Duration(timeout) * time.Second)
	if !time.Now().Before(expiry) {
		return nil, fmt.Errorf("expired token issued over %d seconds ago", a.tokenTimeout)
	}

	publicKey := a.KeyCache.GetPublicKeyById(token.Header["kid"].(string))
	if publicKey == nil {
		return nil, fmt.Errorf("error getting signing key")
	}

	if constants.DEBUGTRACE {
		a.Logger.Infof("Public Key fetched: %v", publicKey)
	}

	return publicKey, nil
}

func (a *AuthModel) jwtAuthZCallback(token *jwt.Token, r *http.Request) (bool, int) {
	if constants.DEBUGTRACE {
		a.Logger.Infof("AuthZ Callback - token: %v", token)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		a.Logger.Info("Error getting claims from token")
		return false, http.StatusUnauthorized
	}

	if constants.DEBUGTRACE {
		a.Logger.Infof("AuthZ Callback - claims: %v", claims)
		a.Logger.Infof("AuthZ Callback - sub: %v", claims["sub"])
		a.Logger.Infof("AuthZ Callback - sub_type: %v", claims["sub_type"])
	}

	// for loop to iterate through authTypes on authmodel
	if slices.Contains(a.authTypes, VALID_IDENTITY) {
		if constants.DEBUGTRACE {
			a.Logger.Infof("Valid Identity")
			// already verified in AuthN routine call prior to this
			a.Logger.Infof(" Authorized based on Valid Identity")
		}
		return true, http.StatusOK
	}

	if slices.Contains(a.authTypes, MACHINE_IDENTITY) {
		if constants.DEBUGTRACE {
			a.Logger.Infof("Machine Identity")
		}

		if claims["sub_type"] == "Machine" {
			if constants.DEBUGTRACE {
				a.Logger.Infof(" Authorized based on Machine Identity")
			}

			return true, http.StatusOK
		}

		if constants.DEBUGTRACE {
			a.Logger.Infof(" Identity did not match Machine Identity")
		}
	}

	if slices.Contains(a.authTypes, MATCHING_IDENTITY) {
		if constants.DEBUGTRACE {
			a.Logger.Infof("Matching Identity")
		}

		params := mux.Vars(r)
		urlIdentity := params["identityId"]
		if urlIdentity == claims["sub"] {
			if constants.DEBUGTRACE {
				a.Logger.Infof(" Authorized based on matching (URL) identity")
			}

			return true, http.StatusOK
		}
		if constants.DEBUGTRACE {
			a.Logger.Infof(" Identity did not match URL")
		}
	}

	if slices.Contains(a.authTypes, MATCHING_GROUP) {
		if constants.DEBUGTRACE {
			a.Logger.Infof("Matching Group")
		}
		// loop through groups on claims and see if any match acceptedGroups
		roles := claims["roles"]
		if roles != nil {
			for _, group := range roles.([]interface{}) {
				groupStr, ok := group.(string)
				if !ok {
					continue
				}
				if constants.DEBUGTRACE {
					a.Logger.Infof(" Group: %v", groupStr)
				}
				if slices.Contains(a.acceptedGroups, AuthGroups(groupStr)) {
					if constants.DEBUGTRACE {
						a.Logger.Infof(" Authorized based on a group (roles) match")
					}

					return true, http.StatusOK
				}
			}
		}
		if constants.DEBUGTRACE {
			a.Logger.Infof(" Group did not match URL")
		}
	}

	// Default to unauthorized
	return false, http.StatusUnauthorized
}

func (a *AuthModel) ValidateSecurity(w http.ResponseWriter, r *http.Request) bool {
	if a.authTypes[0] == NO_AUTH {
		return true
	}

	// retrieve the token from the header
	var base64token = r.Header.Get("Authorization")

	// AUTHN - decode to jwt struct and Authenticate
	parsedToken, err := jwt.Parse(string(base64token), a.jwtAuthNCallback)
	if err != nil {
		if constants.DEBUGTRACE {
			a.Logger.Infof("Error authenticating token: %v", err)
		}
		a.writeHttpResponse(w, http.StatusUnauthorized, []byte(""))
		return false
	}

	if constants.DEBUGTRACE {
		// print the parsed token (debugging use only)
		parsedTokenJSON, err := json.Marshal(parsedToken)
		if err != nil {
			a.Logger.Infof("Error marshaling token for debug logging: %v", err)
			return false
		}
		a.Logger.Infof("Parsed Token JSON: %v", string(parsedTokenJSON))
	}

	// AUTHZ - now do Authorization
	if ok, err := a.jwtAuthZCallback(parsedToken, r); !ok {
		if constants.DEBUGTRACE {
			a.Logger.Infof("Error authorizing token: %v", err)
		}
		a.writeHttpResponse(w, http.StatusForbidden, []byte(""))
		return false
	}

	return true
}

func (a *AuthModel) Secure(nakedFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if constants.DEBUGTRACE {
			start := time.Now()
			defer func() {
				elapsed := time.Since(start)
				a.Logger.Infof("Elapsed time for request: %v", elapsed)
			}()
		}

		// Check the security
		if !a.ValidateSecurity(w, r) {
			if constants.DEBUGTRACE {
				a.Logger.Infof("Failed security - not continuing the call")
			}

			return
		}

		// Passed security checks - now call the router function we protected
		nakedFunc(w, r)
	}
}

func (a *AuthModel) writeHttpResponse(w http.ResponseWriter, status int, v []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(v) > 0 {
		w.Write(v)
	}
}
