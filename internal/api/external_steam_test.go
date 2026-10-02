package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/supabase/auth/internal/models"
)

const (
	steamTestID     = "76561197960287930"
	steamTestPlayer = `{"response":{"players":[{"steamid":"76561197960287930","personaname":"Steam User","profileurl":"https://steamcommunity.com/id/test/","avatar":"http://example.com/avatar.jpg","avatarmedium":"http://example.com/avatar_medium.jpg","avatarfull":"http://example.com/avatar_full.jpg"}]}}`
)

func (ts *ExternalTestSuite) TestSignupExternalSteam() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=steam", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	ts.Equal("/openid/login", u.Path)
	q := u.Query()
	ts.Equal("http://specs.openid.net/auth/2.0", q.Get("openid.ns"))
	ts.Equal("checkid_setup", q.Get("openid.mode"))
	ts.Equal("http://specs.openid.net/auth/2.0/identifier_select", q.Get("openid.claimed_id"))
	ts.Equal("http://specs.openid.net/auth/2.0/identifier_select", q.Get("openid.identity"))
	ts.Equal("https://identity.services.netlify.com", q.Get("openid.realm"))

	returnTo, err := url.Parse(q.Get("openid.return_to"))
	ts.Require().NoError(err)
	state := returnTo.Query().Get("state")
	ts.Equal(ts.Config.External.Steam.RedirectURI+"?state="+state, q.Get("openid.return_to"))

	assertValidOAuthState(ts, state, "steam")
}

// SteamTestSetup fakes the Steam OpenID endpoint and the Steam Web API on a
// single server. verifyCount counts check_authentication round trips and
// userCount counts GetPlayerSummaries calls.
func SteamTestSetup(ts *ExternalTestSuite, verifyCount *int, userCount *int, isValid bool, player string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openid/login":
			*verifyCount++
			ts.Equal(http.MethodPost, r.Method)
			ts.Equal("check_authentication", r.FormValue("openid.mode"))
			ts.NotEmpty(r.FormValue("openid.sig"))
			ts.NotEmpty(r.FormValue("openid.signed"))
			fmt.Fprintf(w, "ns:http://specs.openid.net/auth/2.0\nis_valid:%v\n", isValid)
		case "/ISteamUser/GetPlayerSummaries/v2/":
			*userCount++
			ts.Equal("testpublisherkey", r.URL.Query().Get("key"))
			ts.Equal(steamTestID, r.URL.Query().Get("steamids"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, player)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown steam call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Steam.URL = server.URL
	ts.Config.External.Steam.ApiURL = server.URL

	return server
}

// steamCallbackParams builds a well-formed OpenID 2.0 positive assertion for
// the test SteamID, bound to the given state.
func steamCallbackParams(ts *ExternalTestSuite, state string) url.Values {
	claimedID := "https://steamcommunity.com/openid/id/" + steamTestID
	v := url.Values{}
	v.Set("state", state)
	v.Set("openid.ns", "http://specs.openid.net/auth/2.0")
	v.Set("openid.mode", "id_res")
	v.Set("openid.claimed_id", claimedID)
	v.Set("openid.identity", claimedID)
	v.Set("openid.return_to", ts.Config.External.Steam.RedirectURI+"?state="+state)
	v.Set("openid.assoc_handle", "1234567890")
	v.Set("openid.response_nonce", "2026-07-22T00:00:00Zabcdef")
	v.Set("openid.signed", "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle")
	v.Set("openid.sig", "dGVzdHNpZw==")
	return v
}

// performSteamAuthorization drives the full authorize → callback flow. Steam's
// callback carries OpenID assertion params instead of an OAuth code, so the
// generic performAuthorization helper does not apply.
func performSteamAuthorization(ts *ExternalTestSuite, mutate func(url.Values)) *url.URL {
	w := performAuthorizationRequest(ts, "steam", "")
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	returnTo, err := url.Parse(u.Query().Get("openid.return_to"))
	ts.Require().NoError(err)
	state := returnTo.Query().Get("state")
	ts.Require().NotEmpty(state)

	v := steamCallbackParams(ts, state)
	if mutate != nil {
		mutate(v)
	}

	testURL, err := url.Parse("http://localhost/callback")
	ts.Require().NoError(err)
	testURL.RawQuery = v.Encode()
	req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	return u
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_Success() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	assertAuthorizationSuccess(ts, u, verifyCount, userCount, "", "Steam User", steamTestID, "http://example.com/avatar_full.jpg")
}

func (ts *ExternalTestSuite) TestSignupExternalSteamDisableSignupSuccessWithExistingUser() {
	ts.Config.DisableSignup = true

	ts.createUserWithIdentity("steam", steamTestID, "", "Steam User", "http://example.com/avatar_full.jpg", "")

	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	assertAuthorizationSuccess(ts, u, verifyCount, userCount, "", "Steam User", steamTestID, "http://example.com/avatar_full.jpg")
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_MinimalProfileWithoutPublisherKey() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	publisherKey := ts.Config.External.Steam.PublisherKey
	ts.Config.External.Steam.PublisherKey = ""
	defer func() { ts.Config.External.Steam.PublisherKey = publisherKey }()

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"))
	ts.Equal(1, verifyCount)
	ts.Equal(0, userCount, "the Steam Web API must not be called without a publisher key")

	identity := &models.Identity{}
	ts.Require().NoError(ts.API.db.Q().Where("provider_id = ?", steamTestID).First(identity))
	ts.Equal("https://steamcommunity.com/profiles/"+steamTestID, identity.IdentityData["profile"])
	ts.Nil(identity.IdentityData["full_name"])
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_MinimalProfileOnAPIFailure() {
	verifyCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openid/login":
			verifyCount++
			fmt.Fprint(w, "ns:http://specs.openid.net/auth/2.0\nis_valid:true\n")
		case "/ISteamUser/GetPlayerSummaries/v2/":
			w.WriteHeader(500)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown steam call %s", r.URL.Path)
		}
	}))
	defer server.Close()
	ts.Config.External.Steam.URL = server.URL
	ts.Config.External.Steam.ApiURL = server.URL

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"), "profile enrichment failures must not block the login")
	ts.Equal(1, verifyCount)

	identity := &models.Identity{}
	ts.Require().NoError(ts.API.db.Q().Where("provider_id = ?", steamTestID).First(identity))
	ts.Equal("https://steamcommunity.com/profiles/"+steamTestID, identity.IdentityData["profile"])
}

// Steam's documentation specifies the claimed_id with an http scheme while
// the live service currently returns https; both must be accepted.
func (ts *ExternalTestSuite) TestSignupExternalSteam_HTTPClaimedIDAccepted() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, func(v url.Values) {
		claimedID := "http://steamcommunity.com/openid/id/" + steamTestID
		v.Set("openid.claimed_id", claimedID)
		v.Set("openid.identity", claimedID)
	})
	ts.Require().Equal("/admin", u.Path)

	assertAuthorizationSuccess(ts, u, verifyCount, userCount, "", "Steam User", steamTestID, "http://example.com/avatar_full.jpg")
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_InvalidAssertionRejected() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, false, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, nil)

	assertAuthorizationFailure(ts, u, "OpenID verification failed", "invalid_request", "")
	ts.Equal(1, verifyCount)
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_ForgedClaimedIDRejected() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, func(v url.Values) {
		v.Set("openid.claimed_id", "https://evil.example.com/openid/id/1")
		v.Set("openid.identity", "https://evil.example.com/openid/id/1")
	})

	assertAuthorizationFailure(ts, u, "OpenID verification failed", "invalid_request", "")
	ts.Equal(0, verifyCount, "a forged claimed_id must be rejected before any network call")
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_UnsignedClaimedIDRejected() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, func(v url.Values) {
		v.Set("openid.signed", "signed,op_endpoint,identity,return_to,response_nonce")
	})

	assertAuthorizationFailure(ts, u, "OpenID verification failed", "invalid_request", "")
	ts.Equal(0, verifyCount)
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_ForeignReturnToRejected() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, func(v url.Values) {
		v.Set("openid.return_to", "https://evil.example.com/callback?state="+v.Get("state"))
	})

	assertAuthorizationFailure(ts, u, "OpenID verification failed", "invalid_request", "")
	ts.Equal(0, verifyCount)
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_Cancelled() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	u := performSteamAuthorization(ts, func(v url.Values) {
		v.Set("openid.mode", "cancel")
	})

	assertAuthorizationFailure(ts, u, "OpenID authentication cancelled by user", "access_denied", "")
	ts.Equal(0, verifyCount)
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_CallbackReplayRejected() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	w := performAuthorizationRequest(ts, "steam", "")
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)
	returnTo, err := url.Parse(u.Query().Get("openid.return_to"))
	ts.Require().NoError(err)
	state := returnTo.Query().Get("state")

	callbackURL, err := url.Parse("http://localhost/callback")
	ts.Require().NoError(err)
	callbackURL.RawQuery = steamCallbackParams(ts, state).Encode()

	req := httptest.NewRequest(http.MethodGet, callbackURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	firstRedirect, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)
	fragment, err := url.ParseQuery(firstRedirect.Fragment)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(fragment.Get("access_token"))

	// replaying the exact same callback must fail: the flow state is consumed
	req = httptest.NewRequest(http.MethodGet, callbackURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusSeeOther, w.Code)
	ts.Equal(1, verifyCount)
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_PKCE() {
	verifyCount, userCount := 0, 0
	server := SteamTestSetup(ts, &verifyCount, &userCount, true, steamTestPlayer)
	defer server.Close()

	w := performPKCEAuthorizationRequest(ts, "steam", "2b51b4a42d8b25dcae3d0b9f9a0f8a2d84c3b6a1a7d8f9b0c1d2e3f4a5b6c7d8", "plain")
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)
	returnTo, err := url.Parse(u.Query().Get("openid.return_to"))
	ts.Require().NoError(err)
	state := returnTo.Query().Get("state")
	ts.Require().NotEmpty(state)

	callbackURL, err := url.Parse("http://localhost/callback")
	ts.Require().NoError(err)
	callbackURL.RawQuery = steamCallbackParams(ts, state).Encode()
	req := httptest.NewRequest(http.MethodGet, callbackURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)

	q := u.Query()
	ts.Require().Empty(q.Get("error_description"))
	ts.NotEmpty(q.Get("code"), "PKCE flow should return an auth code")
	ts.Equal(1, verifyCount)
}

// SteamPublisherTestSetup fakes the CheckAppOwnership endpoint used when the
// publisher API is enabled. ownershipBody is the JSON returned; passing an
// empty string with a non-200 status simulates an API outage.
func SteamPublisherTestSetup(ts *ExternalTestSuite, verifyCount *int, ownershipBody string, ownershipStatus int) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openid/login":
			*verifyCount++
			fmt.Fprint(w, "ns:http://specs.openid.net/auth/2.0\nis_valid:true\n")
		case "/ISteamUser/CheckAppOwnership/v4/":
			ts.Equal("testpublisherkey", r.URL.Query().Get("key"))
			ts.Equal(steamTestID, r.URL.Query().Get("steamid"))
			ts.Equal("440", r.URL.Query().Get("appid"))
			if ownershipStatus != http.StatusOK {
				w.WriteHeader(ownershipStatus)
				return
			}
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, ownershipBody)
		case "/ISteamUser/GetPlayerSummaries/v2/":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, steamTestPlayer)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown steam call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Steam.URL = server.URL
	ts.Config.External.Steam.ApiURL = server.URL

	return server
}

// enablePublisherGate configures the ownership gate and returns a cleanup
// function that restores the previous config. The publisher key itself comes
// from the test environment.
func (ts *ExternalTestSuite) enablePublisherGate(requirePermanent bool) func() {
	ts.Config.External.Steam.RequiredAppID = "440"
	ts.Config.External.Steam.RequirePermanent = requirePermanent
	return func() {
		ts.Config.External.Steam.RequiredAppID = ""
		ts.Config.External.Steam.RequirePermanent = false
	}
}

// object-shaped appownership response
const steamOwnsPermanent = `{"appownership":{"ownsapp":true,"permanent":true,"ownersteamid":"76561197960287930","sitelicense":false}}`

// array-shaped appownership response (a different API version)
const steamOwnsPermanentArray = `{"appownership":{"apps":[{"appid":440,"ownsapp":true,"permanent":true,"ownersteamid":"76561197960287930","sitelicense":false}]}}`

// active but temporary access (e.g. Family Sharing / free weekend)
const steamOwnsTemporary = `{"appownership":{"ownsapp":true,"permanent":false,"ownersteamid":"76561197960287931","sitelicense":false}}`

const steamDoesNotOwn = `{"appownership":{"ownsapp":false,"permanent":false,"sitelicense":false}}`

func (ts *ExternalTestSuite) TestSignupExternalSteam_PublisherPermanentOwned() {
	verifyCount := 0
	server := SteamPublisherTestSetup(ts, &verifyCount, steamOwnsPermanent, http.StatusOK)
	defer server.Close()
	defer ts.enablePublisherGate(true)()

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"))
	ts.Equal(1, verifyCount)
}

// The array-shaped response variant must be parsed identically.
func (ts *ExternalTestSuite) TestSignupExternalSteam_PublisherArrayResponse() {
	verifyCount := 0
	server := SteamPublisherTestSetup(ts, &verifyCount, steamOwnsPermanentArray, http.StatusOK)
	defer server.Close()
	defer ts.enablePublisherGate(true)()

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"))
}

// With RequirePermanent, temporary access (Family Sharing / free weekend) is
// rejected even though ownsapp is true.
func (ts *ExternalTestSuite) TestSignupExternalSteam_PublisherTemporaryRejectedWhenPermanentRequired() {
	verifyCount := 0
	server := SteamPublisherTestSetup(ts, &verifyCount, steamOwnsTemporary, http.StatusOK)
	defer server.Close()
	defer ts.enablePublisherGate(true)()

	u := performSteamAuthorization(ts, nil)

	assertAuthorizationFailure(ts, u, "Steam account does not own the required app", "access_denied", "")
	ts.Equal(1, verifyCount)
}

// Without RequirePermanent, temporary access is accepted.
func (ts *ExternalTestSuite) TestSignupExternalSteam_PublisherTemporaryAcceptedWhenPermanentNotRequired() {
	verifyCount := 0
	server := SteamPublisherTestSetup(ts, &verifyCount, steamOwnsTemporary, http.StatusOK)
	defer server.Close()
	defer ts.enablePublisherGate(false)()

	u := performSteamAuthorization(ts, nil)
	ts.Require().Equal("/admin", u.Path)

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"))
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_PublisherNotOwned() {
	verifyCount := 0
	server := SteamPublisherTestSetup(ts, &verifyCount, steamDoesNotOwn, http.StatusOK)
	defer server.Close()
	defer ts.enablePublisherGate(true)()

	u := performSteamAuthorization(ts, nil)

	assertAuthorizationFailure(ts, u, "Steam account does not own the required app", "access_denied", "")
	ts.Equal(1, verifyCount)
}

func (ts *ExternalTestSuite) TestSignupExternalSteam_PublisherFailsClosed() {
	verifyCount := 0
	server := SteamPublisherTestSetup(ts, &verifyCount, "", http.StatusInternalServerError)
	defer server.Close()
	defer ts.enablePublisherGate(true)()

	u := performSteamAuthorization(ts, nil)

	assertAuthorizationFailure(ts, u, "Error verifying app ownership with external provider", "server_error", "")
	ts.Equal(1, verifyCount)
}
