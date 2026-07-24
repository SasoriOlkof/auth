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
