package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/fatih/structs"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/metering"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// SteamTicketGrantParams are the parameters the SteamTicketGrant method accepts
type SteamTicketGrantParams struct {
	Ticket string `json:"ticket"`
}

func (a *API) authenticateSteamTicket(ctx context.Context, ticket string) (*provider.SteamProvider, string, error) {
	providerCandidate, _, err := a.Provider(ctx, "steam", "")
	if err != nil {
		return nil, "", apierrors.NewInternalServerError("Unable to initialise the Steam provider").WithInternalError(err)
	}
	steamProvider, ok := providerCandidate.(*provider.SteamProvider)
	if !ok {
		return nil, "", apierrors.NewInternalServerError("Provider steam is misconfigured")
	}

	steamID, err := steamProvider.AuthenticateUserTicket(ctx, ticket)
	if err != nil {
		switch {
		case errors.Is(err, provider.ErrSteamTicketInvalid):
			return nil, "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid Steam ticket")
		case errors.Is(err, provider.ErrSteamTicketRejected):
			return nil, "", apierrors.NewOAuthError("invalid_grant", "Steam ticket was rejected")
		default:
			return nil, "", apierrors.NewInternalServerError("Steam authentication is unavailable").WithInternalError(err)
		}
	}
	return steamProvider, steamID, nil
}

func (a *API) enforceSteamOwnership(ctx context.Context, p *provider.SteamProvider, steamID string) error {
	if a.config.External.Steam.RequiredAppID == "" {
		return nil
	}
	owns, err := p.OwnsRequiredApp(ctx, steamID)
	if err != nil {
		return apierrors.NewInternalServerError("Error verifying app ownership with external provider").WithInternalError(err)
	}
	if !owns {
		return apierrors.NewOAuthError("access_denied", "Steam account does not own the required app")
	}
	return nil
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

	steamProvider, steamID, err := a.authenticateSteamTicket(ctx, params.Ticket)
	if err != nil {
		return err
	}
	if err := a.enforceSteamOwnership(ctx, steamProvider, steamID); err != nil {
		return err
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

// LinkSteamTicketIdentity links a verified Steam identity to the authenticated user, keeping the same user ID.
func (a *API) LinkSteamTicketIdentity(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	if !config.External.Steam.NativeEnabled() {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeProviderDisabled, "Steam native login is disabled")
	}

	user := getUser(ctx)
	if user == nil {
		return apierrors.NewInternalServerError("Could not read authenticated user")
	}
	if user.IsBanned() {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeUserBanned, "User is banned")
	}

	params := &SteamTicketGrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	steamProvider, steamID, err := a.authenticateSteamTicket(ctx, params.Ticket)
	if err != nil {
		return err
	}
	if err := a.enforceSteamOwnership(ctx, steamProvider, steamID); err != nil {
		return err
	}

	const providerType = "steam"
	userData := steamProvider.GetUserProfile(ctx, steamID)

	err = db.Transaction(func(tx *storage.Connection) error {
		existing, terr := models.FindIdentityByIdAndProvider(tx, steamID, providerType)
		if terr != nil && !models.IsNotFoundError(terr) {
			return apierrors.NewInternalServerError("Database error finding identity").WithInternalError(terr)
		}
		if existing != nil {
			if existing.UserID == user.ID {
				return nil
			}
			return apierrors.NewHTTPError(http.StatusConflict, apierrors.ErrorCodeSteamIdentityAlreadyLinked, "Steam identity is already linked to another user")
		}

		identity, terr := a.createNewIdentity(tx, user, providerType, structs.Map(userData.Metadata))
		if terr != nil {
			return terr
		}
		user.Identities = append(user.Identities, *identity)

		if user.IsAnonymous {
			user.IsAnonymous = false
			if terr := tx.UpdateOnly(user, "is_anonymous"); terr != nil {
				return terr
			}
		}
		if terr := user.UpdateAppMetaDataProviders(tx); terr != nil {
			return terr
		}
		return models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.IdentityLinkAction, "", map[string]interface{}{
			"provider":    providerType,
			"provider_id": steamID,
		})
	})
	if err != nil {
		switch err.(type) {
		case *storage.CommitWithError:
			return err
		case *HTTPError:
			return err
		default:
			return apierrors.NewInternalServerError("Failed to link Steam identity").WithInternalError(err)
		}
	}

	return sendJSON(w, http.StatusOK, user)
}
