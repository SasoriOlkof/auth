package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/supabase/auth/internal/models"
)

const steamValidTicket = "140000005f6e0a0b"

func (ts *ExternalTestSuite) setupSteamTicket(result, steamID string, useError bool, status int) (*httptest.Server, *int) {
	authCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ISteamUserAuth/AuthenticateUserTicket/v1/":
			authCount++
			ts.Equal("testpublisherkey", r.URL.Query().Get("key"))
			ts.Equal("480", r.URL.Query().Get("appid"))
			ts.Equal("test-identity", r.URL.Query().Get("identity"))
			ts.NotEmpty(r.URL.Query().Get("ticket"))
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			w.Header().Add("Content-Type", "application/json")
			if useError {
				fmt.Fprint(w, `{"response":{"error":{"errorcode":101,"errordesc":"Invalid ticket"}}}`)
				return
			}
			fmt.Fprintf(w, `{"response":{"params":{"result":%q,"steamid":%q}}}`, result, steamID)
		case "/ISteamUser/GetPlayerSummaries/v2/":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, steamTestPlayer)
		case "/ISteamUser/CheckAppOwnership/v4/":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"appownership":{"ownsapp":true,"permanent":true}}`)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown steam call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Steam.ApiURL = server.URL
	ts.Config.External.Steam.AppID = "480"
	ts.Config.External.Steam.TicketIdentity = "test-identity"

	return server, &authCount
}

func (ts *ExternalTestSuite) resetSteamNative() {
	ts.Config.External.Steam.ApiURL = ""
	ts.Config.External.Steam.AppID = ""
	ts.Config.External.Steam.TicketIdentity = ""
	ts.Config.External.Steam.RequiredAppID = ""
}

func (ts *ExternalTestSuite) postSteamTicket(ticket string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	ts.Require().NoError(json.NewEncoder(&buf).Encode(map[string]string{"ticket": ticket}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=steam_ticket", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_CreatesUser() {
	server, authCount := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusOK, w.Code)

	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&resp))
	ts.NotEmpty(resp.AccessToken)
	ts.NotEmpty(resp.RefreshToken)
	ts.Equal("bearer", resp.TokenType)
	ts.Equal(1, *authCount)

	identity := &models.Identity{}
	ts.Require().NoError(ts.API.db.Q().Where("provider_id = ?", steamTestID).First(identity))
	ts.Equal("steam", identity.Provider)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_ExistingUser() {
	ts.createUserWithIdentity("steam", steamTestID, "", "Steam User", "http://example.com/avatar_full.jpg", "")
	server, authCount := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusOK, w.Code)
	ts.Equal(1, *authCount)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_NonHexRejectedBeforeSteam() {
	server, authCount := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket("nothexZZ")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
	ts.Equal(0, *authCount, "a malformed ticket must not reach Steam")
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_EmptyRejectedBeforeSteam() {
	server, authCount := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket("")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
	ts.Equal(0, *authCount)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_NotOKRejected() {
	server, _ := ts.setupSteamTicket("Expired", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusBadRequest, w.Code)
	ts.Contains(w.Body.String(), "invalid_grant")
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_SteamErrorRejected() {
	server, _ := ts.setupSteamTicket("", "", true, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusBadRequest, w.Code)
	ts.Contains(w.Body.String(), "invalid_grant")
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_SteamUnavailable() {
	server, _ := ts.setupSteamTicket("", "", false, http.StatusInternalServerError)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusInternalServerError, w.Code)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_Disabled() {
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusUnprocessableEntity, w.Code)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_DisableSignupRejectsNew() {
	ts.Config.DisableSignup = true
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusUnprocessableEntity, w.Code)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_DisableSignupAllowsExisting() {
	ts.createUserWithIdentity("steam", steamTestID, "", "Steam User", "", "")
	ts.Config.DisableSignup = true
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusOK, w.Code)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_BannedUser() {
	u, err := ts.createUserWithIdentity("steam", steamTestID, "", "Steam User", "", "")
	ts.Require().NoError(err)
	until := time.Now().Add(time.Hour)
	u.BannedUntil = &until
	ts.Require().NoError(ts.API.db.UpdateOnly(u, "banned_until"))

	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusForbidden, w.Code)
}

func (ts *ExternalTestSuite) TestSteamTicketGrant_OwnershipGate() {
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()
	ts.Config.External.Steam.RequiredAppID = "440"

	w := ts.postSteamTicket(steamValidTicket)
	ts.Require().Equal(http.StatusOK, w.Code)
}

func (ts *ExternalTestSuite) generateAccessTokenAndSession(u *models.User) string {
	s, err := models.NewSession(u.ID, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(s))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, u, &s.ID, models.PasswordGrant)
	ts.Require().NoError(err)
	return token
}

func (ts *ExternalTestSuite) createDeviceUser(email string) *models.User {
	u, err := models.NewUser("", email, "password", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(u))
	ts.Require().NoError(u.Confirm(ts.API.db))
	return u
}

func (ts *ExternalTestSuite) postSteamTicketLink(token, ticket string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	ts.Require().NoError(json.NewEncoder(&buf).Encode(map[string]string{"ticket": ticket}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/user/identities/steam-ticket", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *ExternalTestSuite) TestSteamTicketLink_CreatesIdentityKeepsUser() {
	ts.Config.Security.ManualLinkingEnabled = true
	defer func() { ts.Config.Security.ManualLinkingEnabled = false }()
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	u := ts.createDeviceUser("device1@example.com")
	token := ts.generateAccessTokenAndSession(u)

	w := ts.postSteamTicketLink(token, steamValidTicket)
	ts.Require().Equal(http.StatusOK, w.Code)

	identity := &models.Identity{}
	ts.Require().NoError(ts.API.db.Q().Where("provider_id = ?", steamTestID).First(identity))
	ts.Equal(u.ID, identity.UserID)
	ts.Equal("steam", identity.Provider)
}

func (ts *ExternalTestSuite) TestSteamTicketLink_Idempotent() {
	ts.Config.Security.ManualLinkingEnabled = true
	defer func() { ts.Config.Security.ManualLinkingEnabled = false }()
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	u := ts.createDeviceUser("device2@example.com")
	token := ts.generateAccessTokenAndSession(u)

	ts.Require().Equal(http.StatusOK, ts.postSteamTicketLink(token, steamValidTicket).Code)
	ts.Require().Equal(http.StatusOK, ts.postSteamTicketLink(token, steamValidTicket).Code)

	n, err := ts.API.db.Q().Where("provider = ? and provider_id = ?", "steam", steamTestID).Count(&models.Identity{})
	ts.Require().NoError(err)
	ts.Equal(1, n)
}

func (ts *ExternalTestSuite) TestSteamTicketLink_ConflictWithAnotherUser() {
	ts.Config.Security.ManualLinkingEnabled = true
	defer func() { ts.Config.Security.ManualLinkingEnabled = false }()
	ts.createUserWithIdentity("steam", steamTestID, "", "Steam User", "", "")
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	u := ts.createDeviceUser("device3@example.com")
	token := ts.generateAccessTokenAndSession(u)

	w := ts.postSteamTicketLink(token, steamValidTicket)
	ts.Require().Equal(http.StatusConflict, w.Code)
	ts.Contains(w.Body.String(), "steam_identity_already_linked")
}

func (ts *ExternalTestSuite) TestSteamTicketLink_DeAnonymizes() {
	ts.Config.Security.ManualLinkingEnabled = true
	defer func() { ts.Config.Security.ManualLinkingEnabled = false }()
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	u, err := models.NewUser("", "", "", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	u.IsAnonymous = true
	ts.Require().NoError(ts.API.db.Create(u))
	token := ts.generateAccessTokenAndSession(u)

	w := ts.postSteamTicketLink(token, steamValidTicket)
	ts.Require().Equal(http.StatusOK, w.Code)

	updated, err := models.FindUserByID(ts.API.db, u.ID)
	ts.Require().NoError(err)
	ts.False(updated.IsAnonymous)
}

func (ts *ExternalTestSuite) TestSteamTicketLink_InvalidTicket() {
	ts.Config.Security.ManualLinkingEnabled = true
	defer func() { ts.Config.Security.ManualLinkingEnabled = false }()
	server, authCount := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	u := ts.createDeviceUser("device4@example.com")
	token := ts.generateAccessTokenAndSession(u)

	w := ts.postSteamTicketLink(token, "nothexZZ")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
	ts.Equal(0, *authCount)
}

func (ts *ExternalTestSuite) TestSteamTicketLink_NativeDisabled() {
	ts.Config.Security.ManualLinkingEnabled = true
	defer func() { ts.Config.Security.ManualLinkingEnabled = false }()
	defer ts.resetSteamNative()

	u := ts.createDeviceUser("device5@example.com")
	token := ts.generateAccessTokenAndSession(u)

	w := ts.postSteamTicketLink(token, steamValidTicket)
	ts.Require().Equal(http.StatusUnprocessableEntity, w.Code)
}

func (ts *ExternalTestSuite) TestSteamTicketLink_ManualLinkingDisabled() {
	server, _ := ts.setupSteamTicket("OK", steamTestID, false, http.StatusOK)
	defer server.Close()
	defer ts.resetSteamNative()

	u := ts.createDeviceUser("device6@example.com")
	token := ts.generateAccessTokenAndSession(u)

	w := ts.postSteamTicketLink(token, steamValidTicket)
	ts.Require().Equal(http.StatusNotFound, w.Code)
}
