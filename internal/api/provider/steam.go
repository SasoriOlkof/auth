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
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

const (
	defaultSteamCommunityBase = "steamcommunity.com"
	defaultSteamAPIBase       = "api.steampowered.com"

	steamOpenIDPath          = "/openid/login"
	steamPlayerSummariesPath = "/ISteamUser/GetPlayerSummaries/v2/"
	steamOwnedGamesPath      = "/IPlayerService/GetOwnedGames/v1/"

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
	OpenIDURL     string
	APIURL        string
	APIKey        string
	CallbackURL   string
	RequiredAppID string
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

type steamOwnedGamesResponse struct {
	Response struct {
		GameCount int `json:"game_count"`
		Games     []struct {
			AppID uint64 `json:"appid"`
		} `json:"games"`
	} `json:"response"`
}

// NewSteamProvider creates a Steam provider using OpenID 2.0.
func NewSteamProvider(ext conf.SteamProviderConfiguration) (*SteamProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	return &SteamProvider{
		OpenIDURL:     chooseHost(ext.URL, defaultSteamCommunityBase) + steamOpenIDPath,
		APIURL:        chooseHost(ext.ApiURL, defaultSteamAPIBase),
		APIKey:        ext.Secret,
		CallbackURL:   ext.RedirectURI,
		RequiredAppID: ext.RequiredAppID,
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
// RequiredAppID, using IPlayerService/GetOwnedGames. Callers should treat
// errors as a failed check (fail-closed) since this is an authorization gate.
// Note that a private game library is indistinguishable from not owning the
// app: Steam returns an empty list in both cases.
func (p *SteamProvider) OwnsRequiredApp(ctx context.Context, steamID string) (bool, error) {
	// GetOwnedGames is a Service interface: all arguments except the key are
	// passed as a single JSON object in input_json, with steamid as uint64
	// and appids_filter as an array of uint32.
	steamIDNum, err := strconv.ParseUint(steamID, 10, 64)
	if err != nil {
		return false, fmt.Errorf("steam: invalid steamid %q: %w", steamID, err)
	}
	appID, err := strconv.ParseUint(p.RequiredAppID, 10, 32)
	if err != nil {
		return false, fmt.Errorf("steam: invalid required app ID %q: %w", p.RequiredAppID, err)
	}

	inputJSON, err := json.Marshal(map[string]interface{}{
		"steamid":                   steamIDNum,
		"appids_filter":             []uint64{appID},
		"include_played_free_games": true,
	})
	if err != nil {
		return false, err
	}

	v := url.Values{}
	v.Set("key", p.APIKey)
	v.Set("input_json", string(inputJSON))

	var result steamOwnedGamesResponse
	if err := p.getJSON(ctx, p.APIURL+steamOwnedGamesPath+"?"+v.Encode(), &result); err != nil {
		return false, err
	}

	for _, game := range result.Response.Games {
		if game.AppID == appID {
			return true, nil
		}
	}
	return false, nil
}

// GetUserProfile builds the user data for a verified SteamID. Steam never
// returns an email address. Profile enrichment through the Steam Web API is
// best effort: when no API key is configured or the request fails, a minimal
// profile derived from the SteamID alone is returned instead of an error,
// since authentication was already established by the OpenID assertion.
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

	if p.APIKey == "" {
		return data
	}

	v := url.Values{}
	v.Set("key", p.APIKey)
	v.Set("steamids", steamID)

	var summaries steamPlayerSummariesResponse
	err := p.getJSON(ctx, p.APIURL+steamPlayerSummariesPath+"?"+v.Encode(), &summaries)
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
