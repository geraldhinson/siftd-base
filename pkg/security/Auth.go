package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	NO_REALM       string = "NoRealm"
	REALM_MACHINE         = "Machine"
	REALM_MEMBER          = "Member"
	REALM_PARTNER         = "Partner"
	REALM_INTERNAL        = "Internal"
	REALM_CSRC            = "CustomerServiceRep"
	REALM_OPS             = "Operations"
)

type AuthTypes int

const (
	NO_AUTH AuthTypes = iota
	VALID_IDENTITY
	MATCHING_IDENTITY
	APPROVED_GROUPS
	APPROVED_IDENTITIES
)

type AuthTimeout int

const (
	NO_EXPIRY AuthTimeout = 0
	ONE_HOUR  AuthTimeout = 3600
	ONE_DAY   AuthTimeout = 86400
)

type AuthPolicy struct {
	Realm       string
	AuthType    AuthTypes
	AuthTimeout AuthTimeout
	Listed      []string
}

type AuthModel struct {
	Configuration *viper.Viper
	Logger        *logrus.Logger
	KeyCache      *KeyCache
	authPolicy    *[]AuthPolicy
	debugLevel    int
}

func NewAuthModel(configuration *viper.Viper, Logger *logrus.Logger, KeyCache *KeyCache) *AuthModel {

	var debugLevel = 0
	if configuration.GetString(constants.DEBUGSIFTD_AUTH) != "" {
		debugLevel = configuration.GetInt(constants.DEBUGSIFTD_AUTH)
	}

	return &AuthModel{
		Configuration: configuration,
		Logger:        Logger,
		KeyCache:      KeyCache,
		authPolicy:    &[]AuthPolicy{},
		debugLevel:    debugLevel,
	}
}

func (a *AuthModel) AddPolicy(realm string, authType AuthTypes, authTimeout AuthTimeout, list []string) error {
	// check for validity of the policy

	// if any of these are true..
	if (realm == NO_REALM) || (authType == NO_AUTH) || (authTimeout == NO_EXPIRY) {
		// they all have to be true
		if (realm == NO_REALM) && (authType == NO_AUTH) && (authTimeout == NO_EXPIRY) {
			// and if they are we add them, but only if the list is empty
			if len(list) > 0 {
				return fmt.Errorf("Invalid policy - Use of approved list is not supported for NO_REALM, NO_AUTH, and NO_EXPIRY")
			}
			// and only if it is the only policy in the array
			if len(*a.authPolicy) > 0 {
				return fmt.Errorf("Invalid policy - NO_REALM, NO_AUTH, and NO_EXPIRY must be the only policy when in use")
			}

			*a.authPolicy = append(*a.authPolicy, AuthPolicy{Realm: NO_REALM, AuthType: NO_AUTH, AuthTimeout: NO_EXPIRY, Listed: nil})
		} else {
			return fmt.Errorf("Invalid policy - NO_AUTH can only be used with NO_REALM and NO_EXPIRY")
		}
	}

	// APPROVED_GROUPS and APPROVED_IDENTITIES must have a non-empty list
	if (authType == APPROVED_GROUPS || authType == APPROVED_IDENTITIES) && len(list) == 0 {
		return fmt.Errorf("Invalid policy - APPROVED_GROUPS and APPROVED_IDENTITIES must have a non-empty list")
	}

	// if not APPROVED_GROUPS or APPROVED_IDENTITIES, the list must be empty
	if (authType != APPROVED_GROUPS && authType != APPROVED_IDENTITIES) && len(list) > 0 {
		return fmt.Errorf("Invalid policy - the approved list is only valid when specifying APPROVED_GROUPS or APPROVED_IDENTITIES")
	}

	// if a pre-existing policy for a given realm exists, their authTimeout value must match
	for _, policy := range *a.authPolicy {
		if policy.Realm == realm {
			if policy.AuthTimeout != authTimeout {
				return fmt.Errorf("Invalid policy - all authTimeout values must match for a given realm: Realm %s timeout %d differs from previous timeout %d", realm, authTimeout, policy.AuthTimeout)
			}
		}
	}

	*a.authPolicy = append(*a.authPolicy, AuthPolicy{Realm: realm, AuthType: authType, AuthTimeout: authTimeout, Listed: list})

	return nil
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
	// find an authPolicy that matches the realm and use the authTimeout from it
	var timeout int
	for _, policy := range *a.authPolicy {
		if policy.Realm == token.Claims.(jwt.MapClaims)["realm"] {
			timeout = int(policy.AuthTimeout)
			break
		}
	}

	var expiry = iat.Add(time.Duration(timeout) * time.Second)
	if !time.Now().Before(expiry) {
		return nil, fmt.Errorf("expired token issued over %d seconds ago", timeout)
	}

	publicKey := a.KeyCache.GetPublicKeyById(token.Header["kid"].(string))
	if publicKey == nil {
		return nil, fmt.Errorf("error getting signing key")
	}

	if a.debugLevel > 0 {
		a.Logger.Infof("Public Key fetched: %v", publicKey)
	}

	return publicKey, nil
}

func (a *AuthModel) jwtAuthZCallback(token *jwt.Token, r *http.Request) (bool, int) {
	if a.debugLevel > 0 {
		a.Logger.Infof("AuthZ Callback - token: %v", token)
	}

	// there must be a policy in the array
	if len(*a.authPolicy) == 0 {
		a.Logger.Info("No auth policy was found - unauthorized")
		return false, http.StatusUnauthorized
	}
	// if the first policy in the array is NO_AUTH/NO_REALM then return true
	if (*a.authPolicy)[0].AuthType == NO_AUTH {
		if a.debugLevel > 0 {
			a.Logger.Infof("A NO_AUTH policy was found - authorized")
		}
		return true, http.StatusOK
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		a.Logger.Info("Error getting claims from token")
		return false, http.StatusUnauthorized
	}

	if a.debugLevel > 0 {
		a.Logger.Infof("AuthZ Callback - claims: %v", claims)
		a.Logger.Infof("AuthZ Callback - sub (name): %v", claims["sub"])
		a.Logger.Infof("AuthZ Callback - sub_type (realm): %v", claims["sub_type"])
		a.Logger.Infof("AuthZ Callback - sub_name (friendly name): %v", claims["sub_name"])
	}

	// loop through policies and to see if any authorize the request
	for _, policy := range *a.authPolicy {
		if policy.Realm == claims["sub_type"] {

			if policy.AuthType == VALID_IDENTITY {
				if a.debugLevel > 0 {
					a.Logger.Infof("Valid Identity")
				}
				// already verified in AuthN routine call prior to this
				if a.debugLevel > 0 {
					a.Logger.Infof(" Authorized based on valid identity")
				}
				return true, http.StatusOK
			}

			if policy.AuthType == MATCHING_IDENTITY {
				if a.debugLevel > 0 {
					a.Logger.Infof("Matching Identity")
				}

				params := mux.Vars(r)
				urlIdentity := params["identityId"]
				if urlIdentity == claims["sub"] {
					if a.debugLevel > 0 {
						a.Logger.Infof(" Authorized based on matching (URL) identity")
					}

					return true, http.StatusOK
				}
				if a.debugLevel > 0 {
					a.Logger.Infof(" Identity did not match URL")
				}
			}

			if policy.AuthType == APPROVED_GROUPS {
				if a.debugLevel > 0 {
					a.Logger.Infof("Approved Groups")
				}
				// loop through groups on claims and see if any match the list on the policy

				roles := claims["roles"]
				if roles != nil {
					for _, group := range roles.([]interface{}) {
						groupStr, ok := group.(string)
						if !ok {
							continue
						}
						if a.debugLevel > 0 {
							a.Logger.Infof(" Checking for token-specified group: %v", groupStr)
						}
						// check if the group is in policy.Listed
						if slices.Contains(policy.Listed, groupStr) {
							if a.debugLevel > 0 {
								a.Logger.Infof(" Authorized based on a group (roles) match")
							}

							return true, http.StatusOK
						}
					}
				}
				if a.debugLevel > 0 {
					a.Logger.Infof("Group not found in the approved list")
				}
			}

			if policy.AuthType == APPROVED_IDENTITIES {
				if a.debugLevel > 0 {
					a.Logger.Infof("Approved Identities")
				}
				// loop through list on policy to see if this claims[sub] is in the list
				for _, identity := range policy.Listed {
					if identity == claims["sub"] {
						if a.debugLevel > 0 {
							a.Logger.Infof(" Authorized based on presence in approved identities list")
						}

						return true, http.StatusOK
					}
				}

				// if we get here, the identity was not found in the list
				if a.debugLevel > 0 {
					a.Logger.Infof(" Identity not found in the approved list")
				}
			}
		}
	}

	// Default to unauthorized
	return false, http.StatusUnauthorized
}

func (a *AuthModel) ValidateSecurity(w http.ResponseWriter, r *http.Request) bool {
	if (*a.authPolicy)[0].AuthType == NO_AUTH {
		return true
	}

	// retrieve the token from the header
	var base64token = r.Header.Get("Authorization")

	// AUTHN - decode to jwt struct and Authenticate
	parsedToken, err := jwt.Parse(string(base64token), a.jwtAuthNCallback)
	if err != nil {
		if a.debugLevel > 0 {
			a.Logger.Infof("Error authenticating token: %v", err)
		}
		a.writeHttpResponse(w, http.StatusUnauthorized, []byte(""))
		return false
	}

	if a.debugLevel > 0 {
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
		if a.debugLevel > 0 {
			a.Logger.Infof("Error authorizing token: %v", err)
		}
		a.writeHttpResponse(w, http.StatusForbidden, []byte(""))
		return false
	}

	return true
}

func (a *AuthModel) Secure(nakedFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.debugLevel > 0 {
			start := time.Now()
			defer func() {
				elapsed := time.Since(start)
				a.Logger.Infof("Elapsed time for request: %v", elapsed)
			}()
		}

		// Check the security
		if !a.ValidateSecurity(w, r) {
			if a.debugLevel > 0 {
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
