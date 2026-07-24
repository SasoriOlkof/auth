package provider

import (
	"bufio"
	"context"
	"encoding/hex"
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
	defaultSteamCommunityBase  = "steamcommunity.com"
	defaultSteamPartnerAPIBase = "partner.steam-api.com"

	steamOpenIDPath                 = "/openid/login"
	steamPlayerSummariesPath        = "/ISteamUser/GetPlayerSummaries/v2/"
	steamCheckAppOwnershipPath      = "/ISteamUser/CheckAppOwnership/v4/"
	steamAuthenticateUserTicketPath = "/ISteamUserAuth/AuthenticateUserTicket/v1/"

	maxSteamTicketHexLen = 8192

	steamOpenIDNS         = "http://specs.openid.net/auth/2.0"
	steamIdentifierSelect = "http://specs.openid.net/auth/2.0/identifier_select"

	SteamIssuer = "https://steamcommunity.com/openid"
)

var ErrSteamOpenIDCancelled = errors.New("steam: OpenID authentication cancelled by user")

var (
	ErrSteamTicketInvalid  = errors.New("steam: invalid ticket")
	ErrSteamTicketRejected = errors.New("steam: ticket rejected")
)

var steamClaimedIDRegexp = regexp.MustCompile(`^https?://steamcommunity\.com/openid/id/(\d+)$`)

// SteamProvider implements Steam login via OpenID 2.0 and native session tickets.
type SteamProvider struct {
	OpenIDURL        string
	PublisherAPIURL  string
	PublisherKey     string
	CallbackURL      string
	RequiredAppID    string
	RequirePermanent bool
	AppID            string
	TicketIdentity   string
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

type steamAppOwnership struct {
	AppID     json.Number `json:"appid"`
	OwnsApp   bool        `json:"ownsapp"`
	Permanent bool        `json:"permanent"`
}

type steamCheckAppOwnershipResponse struct {
	AppOwnership json.RawMessage `json:"appownership"`
}

type steamAuthTicketResponse struct {
	Response struct {
		Params *struct {
			Result  string `json:"result"`
			SteamID string `json:"steamid"`
		} `json:"params"`
		Error *struct {
			ErrorCode int    `json:"errorcode"`
			ErrorDesc string `json:"errordesc"`
		} `json:"error"`
	} `json:"response"`
}

func NewSteamProvider(ext conf.SteamProviderConfiguration) (*SteamProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	return &SteamProvider{
		OpenIDURL:        chooseHost(ext.URL, defaultSteamCommunityBase) + steamOpenIDPath,
		PublisherAPIURL:  chooseHost(ext.ApiURL, defaultSteamPartnerAPIBase),
		PublisherKey:     ext.PublisherKey,
		CallbackURL:      ext.RedirectURI,
		RequiredAppID:    ext.RequiredAppID,
		RequirePermanent: ext.RequirePermanent,
		AppID:            ext.AppID,
		TicketIdentity:   ext.TicketIdentity,
	}, nil
}

// AuthCodeURL builds the Steam OpenID 2.0 checkid_setup redirect URL, carrying
// the state through the return_to query string.
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

// VerifyAssertion validates the OpenID 2.0 assertion from the callback and
// returns the verified 64-bit SteamID.
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

// OwnsRequiredApp reports whether the account owns RequiredAppID via
// CheckAppOwnership. Callers should treat errors as a failed check (fail-closed).
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
		return steamAppOwnership{}, nil
	}

	var single steamAppOwnership
	if err := json.Unmarshal(raw, &single); err != nil {
		return steamAppOwnership{}, fmt.Errorf("steam: could not decode appownership: %w", err)
	}
	return single, nil
}

// AuthenticateUserTicket verifies a hex-encoded Steam session ticket with
// AuthenticateUserTicket and returns the verified 64-bit SteamID.
func (p *SteamProvider) AuthenticateUserTicket(ctx context.Context, ticketHex string) (string, error) {
	if ticketHex == "" {
		return "", fmt.Errorf("%w: empty ticket", ErrSteamTicketInvalid)
	}
	if len(ticketHex) > maxSteamTicketHexLen {
		return "", fmt.Errorf("%w: ticket exceeds %d characters", ErrSteamTicketInvalid, maxSteamTicketHexLen)
	}
	if _, err := hex.DecodeString(ticketHex); err != nil {
		return "", fmt.Errorf("%w: ticket is not valid hexadecimal", ErrSteamTicketInvalid)
	}

	v := url.Values{}
	v.Set("key", p.PublisherKey)
	v.Set("appid", p.AppID)
	v.Set("ticket", ticketHex)
	v.Set("identity", p.TicketIdentity)

	var resp steamAuthTicketResponse
	if err := p.getJSON(ctx, p.PublisherAPIURL+steamAuthenticateUserTicketPath+"?"+v.Encode(), &resp); err != nil {
		return "", err
	}

	if resp.Response.Error != nil {
		return "", fmt.Errorf("%w: code %d", ErrSteamTicketRejected, resp.Response.Error.ErrorCode)
	}
	params := resp.Response.Params
	if params == nil || !strings.EqualFold(params.Result, "OK") {
		return "", ErrSteamTicketRejected
	}
	if _, err := strconv.ParseUint(params.SteamID, 10, 64); err != nil {
		return "", errors.New("steam: ambiguous AuthenticateUserTicket response: invalid steamid")
	}
	return params.SteamID, nil
}

// GetUserProfile builds the user data for a verified SteamID. Profile
// enrichment is best effort and falls back to a minimal SteamID-only profile.
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
