package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type SteamTicketGrantParams struct {
	Ticket string `json:"ticket"`
}

// SteamTicketGrant exchanges a Steam session ticket for a Supabase session.
func (a *API) SteamTicketGrant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	config := a.config
	db := a.db.WithContext(ctx)

	if !config.External.Steam.NativeEnabled() {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeProviderDisabled, "Steam native login is disabled")
	}

	params := &SteamTicketGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	providerCandidate, _, err := a.Provider(ctx, "steam", "")
	if err != nil {
		return apierrors.NewInternalServerError("Unable to initialise the Steam provider").WithInternalError(err)
	}
	steamProvider, ok := providerCandidate.(*provider.SteamProvider)
	if !ok {
		return apierrors.NewInternalServerError("Provider steam is misconfigured")
	}

	steamID, err := steamProvider.AuthenticateUserTicket(ctx, params.Ticket)
	if err != nil {
		switch {
		case errors.Is(err, provider.ErrSteamTicketInvalid):
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid Steam ticket")
		case errors.Is(err, provider.ErrSteamTicketRejected):
			return apierrors.NewOAuthError("invalid_grant", "Steam ticket was rejected")
		default:
			return apierrors.NewInternalServerError("Steam authentication is unavailable").WithInternalError(err)
		}
	}

	if config.External.Steam.RequiredAppID != "" {
		owns, err := steamProvider.OwnsRequiredApp(ctx, steamID)
		if err != nil {
			return apierrors.NewInternalServerError("Error verifying app ownership with external provider").WithInternalError(err)
		}
		if !owns {
			return apierrors.NewOAuthError("access_denied", "Steam account does not own the required app")
		}
	}

	userData := steamProvider.GetUserProfile(ctx, steamID)

	const providerType = "steam"
	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)

	if err := a.triggerBeforeUserCreatedExternal(r, db, userData, providerType); err != nil {
		return err
	}

	var token *AccessTokenResponse
	var createdUser bool
	var user *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		var decision models.AccountLinkingDecision
		decision, user, terr = a.createAccountFromExternalIdentity(tx, r, userData, providerType, true)
		if terr != nil {
			return terr
		}
		createdUser = decision == models.CreateAccount

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": providerType,
		}); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(r, w.Header(), tx, user, models.SteamTicket, grantParams)
		if terr != nil {
			return terr
		}

		return nil
	})
	if err != nil {
		switch err.(type) {
		case *storage.CommitWithError:
			return err
		case *HTTPError:
			return err
		default:
			return apierrors.NewOAuthError("server_error", "Internal Server Error").WithInternalError(err)
		}
	}

	if createdUser {
		if err := a.triggerAfterUserCreated(r, db, user); err != nil {
			return err
		}
	}

	metering.RecordLogin(metering.LoginTypeSteam, token.User.ID, &metering.LoginData{
		Provider: providerType,
	})

	return sendJSON(w, http.StatusOK, token)
}
