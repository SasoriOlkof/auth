package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

const (
	defaultSteamCommunityBase  = "steamcommunity.com"
	defaultSteamPartnerAPIBase = "partner.steam-api.com"

	steamOpenIDPath            = "/openid/login"
	steamPlayerSummariesPath   = "/ISteamUser/GetPlayerSummaries/v2/"
	steamCheckAppOwnershipPath = "/ISteamUser/CheckAppOwnership/v4/"

	steamOpenIDNS         = "http://specs.openid.net/auth/2.0"
	steamIdentifierSelect = "http://specs.openid.net/auth/2.0/identifier_select"

	// SteamIssuer is used as the issuer claim for identities created via Steam.
	SteamIssuer = "https://steamcommunity.com/openid"
)

// ErrSteamOpenIDCancelled is returned when the user cancels the login on the
// Steam OpenID page (openid.mode=cancel).
var ErrSteamOpenIDCancelled = errors.New("steam: OpenID authentication cancelled by user")

// Steam documents the claimed_id as http://steamcommunity.com/openid/id/<id>
// but currently returns https; accept both schemes since the host is pinned
// and the value is verified through check_authentication anyway.
var steamClaimedIDRegexp = regexp.MustCompile(`^https?://steamcommunity\.com/openid/id/(\d+)$`)

// SteamProvider implements Steam login via OpenID 2.0. Steam has no OAuth2
// flow: there is no authorization code and no tokens. The user is redirected
// to the Steam OpenID endpoint and the signed positive assertion returned on
// the callback is verified server-side with a check_authentication round trip.
// It intentionally implements only the Provider interface, not OAuthProvider.
type SteamProvider struct {
	OpenIDURL       string
	PublisherAPIURL string
	// PublisherKey is a Steam publisher Web API key that owns RequiredAppID,
	// used on the partner host for both ownership and profile enrichment.
	PublisherKey  string
	CallbackURL   string
	RequiredAppID string
	// RequirePermanent requires genuine permanent ownership (excludes Family
	// Sharing, free weekends and PC cafés).
	RequirePermanent bool
}

type steamPlayer struct {
	SteamID      string `json:"steamid"`
	PersonaName  string `json:"personaname"`
	ProfileURL   string `json:"profileurl"`
	Avatar       string `json:"avatar"`
	AvatarMedium string `json:"avatarmedium"`
	AvatarFull   string `json:"avatarfull"`
}

type steamPlayerSummariesResponse struct {
	Response struct {
		Players []steamPlayer `json:"players"`
	} `json:"response"`
}

// steamAppOwnership is a single CheckAppOwnership record. appid is only present
// in the array-shaped response variant.
type steamAppOwnership struct {
	AppID     json.Number `json:"appid"`
	OwnsApp   bool        `json:"ownsapp"`
	Permanent bool        `json:"permanent"`
}

// steamCheckAppOwnershipResponse defers decoding of the appownership value
// because Steam has returned it both as a single object and as an object
// wrapping an "apps" array across API versions.
type steamCheckAppOwnershipResponse struct {
	AppOwnership json.RawMessage `json:"appownership"`
}

// NewSteamProvider creates a Steam provider using OpenID 2.0.
func NewSteamProvider(ext conf.SteamProviderConfiguration) (*SteamProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	return &SteamProvider{
		OpenIDURL: chooseHost(ext.URL, defaultSteamCommunityBase) + steamOpenIDPath,
		// Publisher methods live on the partner host in production; tests
		// override ext.ApiURL so it points at the fake server.
		PublisherAPIURL:  chooseHost(ext.ApiURL, defaultSteamPartnerAPIBase),
		PublisherKey:     ext.PublisherKey,
		CallbackURL:      ext.RedirectURI,
		RequiredAppID:    ext.RequiredAppID,
		RequirePermanent: ext.RequirePermanent,
	}, nil
}

// AuthCodeURL builds the Steam OpenID 2.0 checkid_setup redirect URL. The
// state is round-tripped through the return_to query string so the callback
// carries it like a regular OAuth callback would.
func (p *SteamProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	callback, err := url.Parse(p.CallbackURL)
	if err != nil {
		return ""
	}

	v := url.Values{}
	v.Set("openid.ns", steamOpenIDNS)
	v.Set("openid.mode", "checkid_setup")
	v.Set("openid.claimed_id", steamIdentifierSelect)
	v.Set("openid.identity", steamIdentifierSelect)
	v.Set("openid.return_to", p.CallbackURL+"?state="+state)
	v.Set("openid.realm", callback.Scheme+"://"+callback.Host)

	return p.OpenIDURL + "?" + v.Encode()
}

// VerifyAssertion validates the OpenID 2.0 positive assertion returned by
// Steam on the callback and returns the verified 64-bit SteamID. The
// check_authentication request is always sent to the configured endpoint,
// never to the openid.op_endpoint value from the response.
func (p *SteamProvider) VerifyAssertion(ctx context.Context, params url.Values) (string, error) {
	mode := params.Get("openid.mode")
	if mode == "cancel" {
		return "", ErrSteamOpenIDCancelled
	}
	if mode != "id_res" {
		return "", fmt.Errorf("steam: unexpected openid.mode %q", mode)
	}

	claimedID := params.Get("openid.claimed_id")
	matches := steamClaimedIDRegexp.FindStringSubmatch(claimedID)
	if matches == nil {
		return "", fmt.Errorf("steam: invalid openid.claimed_id %q", claimedID)
	}
	if params.Get("openid.identity") != claimedID {
		return "", errors.New("steam: openid.identity does not match openid.claimed_id")
	}

	if err := p.verifyReturnTo(params); err != nil {
		return "", err
	}

	signed := strings.Split(params.Get("openid.signed"), ",")
	for _, required := range []string{"claimed_id", "identity", "return_to", "response_nonce"} {
		found := false
		for _, field := range signed {
			if field == required {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("steam: openid.signed does not cover %q", required)
		}
	}

	if err := p.checkAuthentication(ctx, params); err != nil {
		return "", err
	}

	return matches[1], nil
}

// verifyReturnTo checks that openid.return_to points at our configured
// callback and carries the same state as the callback request itself.
func (p *SteamProvider) verifyReturnTo(params url.Values) error {
	returnTo, err := url.Parse(params.Get("openid.return_to"))
	if err != nil {
		return fmt.Errorf("steam: invalid openid.return_to: %w", err)
	}
	callback, err := url.Parse(p.CallbackURL)
	if err != nil {
		return fmt.Errorf("steam: invalid callback URL: %w", err)
	}
	if returnTo.Scheme != callback.Scheme || returnTo.Host != callback.Host || returnTo.Path != callback.Path {
		return fmt.Errorf("steam: openid.return_to %q does not match the configured callback", returnTo.String())
	}
	if returnTo.Query().Get("state") != params.Get("state") {
		return errors.New("steam: openid.return_to state does not match callback state")
	}
	return nil
}

// checkAuthentication replays the signed assertion to Steam with
// openid.mode=check_authentication and requires an is_valid:true response.
func (p *SteamProvider) checkAuthentication(ctx context.Context, params url.Values) error {
	verification := url.Values{}
	for key, values := range params {
		if strings.HasPrefix(key, "openid.") && len(values) > 0 {
			verification.Set(key, values[0])
		}
	}
	verification.Set("openid.mode", "check_authentication")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.OpenIDURL, strings.NewReader(verification.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: defaultTimeout}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("steam: check_authentication returned status %d", res.StatusCode)
	}

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "is_valid:true" {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return errors.New("steam: check_authentication did not validate the assertion")
}

// OwnsRequiredApp reports whether the given Steam account owns the configured
// RequiredAppID, using ISteamUser/CheckAppOwnership on the partner host. It is
// authoritative (ignores library privacy) and distinguishes genuine permanent
// ownership from temporary access (Family Sharing, free weekends, PC cafés)
// via the permanent flag. Callers should treat errors as a failed check
// (fail-closed) since this is an authorization gate.
func (p *SteamProvider) OwnsRequiredApp(ctx context.Context, steamID string) (bool, error) {
	v := url.Values{}
	v.Set("key", p.PublisherKey)
	v.Set("steamid", steamID)
	v.Set("appid", p.RequiredAppID)

	var resp steamCheckAppOwnershipResponse
	if err := p.getJSON(ctx, p.PublisherAPIURL+steamCheckAppOwnershipPath+"?"+v.Encode(), &resp); err != nil {
		return false, err
	}

	ownership, err := p.parseAppOwnership(resp.AppOwnership)
	if err != nil {
		return false, err
	}

	if p.RequirePermanent {
		return ownership.Permanent, nil
	}
	return ownership.OwnsApp, nil
}

// parseAppOwnership decodes the appownership value, which Steam has returned
// both as a single object and as an object wrapping an "apps" array. In the
// array form the entry matching RequiredAppID is selected.
func (p *SteamProvider) parseAppOwnership(raw json.RawMessage) (steamAppOwnership, error) {
	if len(raw) == 0 {
		return steamAppOwnership{}, errors.New("steam: empty appownership in CheckAppOwnership response")
	}

	var arrForm struct {
		Apps []steamAppOwnership `json:"apps"`
	}
	if err := json.Unmarshal(raw, &arrForm); err == nil && arrForm.Apps != nil {
		for _, app := range arrForm.Apps {
			if app.AppID.String() == p.RequiredAppID {
				return app, nil
			}
		}
		// The array was returned but did not include the requested app.
		return steamAppOwnership{}, nil
	}

	var single steamAppOwnership
	if err := json.Unmarshal(raw, &single); err != nil {
		return steamAppOwnership{}, fmt.Errorf("steam: could not decode appownership: %w", err)
	}
	return single, nil
}

// GetUserProfile builds the user data for a verified SteamID. Steam never
// returns an email address. Profile enrichment via GetPlayerSummaries on the
// partner host is best effort: when no publisher key is configured or the
// request fails, a minimal profile derived from the SteamID alone is returned
// instead of an error, since authentication was already established by the
// OpenID assertion.
func (p *SteamProvider) GetUserProfile(ctx context.Context, steamID string) *UserProvidedData {
	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:  SteamIssuer,
			Subject: steamID,
			Profile: "https://steamcommunity.com/profiles/" + steamID,
			CustomClaims: map[string]interface{}{
				"steamid": steamID,
			},

			// To be deprecated
			ProviderId: steamID,
		},
	}

	if p.PublisherKey == "" {
		return data
	}

	v := url.Values{}
	v.Set("key", p.PublisherKey)
	v.Set("steamids", steamID)

	var summaries steamPlayerSummariesResponse
	err := p.getJSON(ctx, p.PublisherAPIURL+steamPlayerSummariesPath+"?"+v.Encode(), &summaries)
	if err == nil && len(summaries.Response.Players) == 0 {
		err = errors.New("steam: player summaries response contained no players")
	}
	if err != nil {
		logrus.WithError(err).WithField("provider", "steam").Warn("Unable to fetch Steam player summary, continuing with minimal profile")
		return data
	}

	player := summaries.Response.Players[0]
	claims := data.Metadata
	claims.Name = player.PersonaName
	claims.PreferredUsername = player.PersonaName
	claims.Picture = player.AvatarFull
	if player.ProfileURL != "" {
		claims.Profile = player.ProfileURL
	}
	claims.CustomClaims["profileurl"] = player.ProfileURL
	claims.CustomClaims["avatar"] = player.Avatar
	claims.CustomClaims["avatarmedium"] = player.AvatarMedium

	// To be deprecated
	claims.FullName = player.PersonaName
	claims.AvatarURL = player.AvatarFull
	claims.UserNameKey = player.PersonaName

	return data
}

func (p *SteamProvider) getJSON(ctx context.Context, requestURL string, dst interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: defaultTimeout}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("steam: request to %s returned status %d", req.URL.Path, res.StatusCode)
	}

	return json.NewDecoder(res.Body).Decode(dst)
}
