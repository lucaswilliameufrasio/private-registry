package workspaces

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/bootstrap"
	"private-registry/internal/email"
	"private-registry/internal/password"
)

const (
	invitationPrefix     = "prinv_"
	defaultInvitationTTL = 7 * 24 * time.Hour
	maxInvitationTTL     = 30 * 24 * time.Hour
)

// SignupPolicy controls who may create a local account. "open" exists in the
// schema but needs verified email, which has no transport yet, so it cannot be
// selected.
type SignupPolicy string

const (
	SignupClosed      SignupPolicy = "closed"
	SignupInvitations SignupPolicy = "invitations"
)

var (
	ErrInvitationUnavailable = errors.New("invitation is invalid, expired, revoked or already used")
	ErrInvalidInvitation     = errors.New("invitation request is invalid")
	ErrSignupClosed          = errors.New("account creation by invitation is disabled on this installation")
	ErrLoginNameTaken        = errors.New("login name is already taken")
	ErrInvalidAccount        = errors.New("login name, display name or password does not meet the requirements")
	ErrAlreadyMember         = errors.New("account is already a member of this workspace")
	ErrEmailUnavailable      = errors.New("email delivery is not configured on this installation")
)

type IssuedInvitation struct {
	ID        string
	Role      string
	ExpiresAt time.Time
	// Token is shown once and never stored.
	Token string
}

type Invitation struct {
	ID        string
	Role      string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	State     string // pending, redeemed, revoked, expired
	// Email is the address the invitation was sent to, if any.
	Email string
}

// SignupPolicyValue returns the installation's account creation policy.
func (s *Service) SignupPolicyValue(ctx context.Context, actorUserID string) (SignupPolicy, error) {
	var policy SignupPolicy
	err := s.withInstanceAdministrator(ctx, actorUserID, func(tx *sql.Tx, _ string) error {
		var value string
		if err := tx.QueryRowContext(ctx, `SELECT signup_policy FROM registry_installation WHERE singleton_id = 1`).Scan(&value); err != nil {
			return errors.New("signup policy could not be read")
		}
		policy = SignupPolicy(value)
		return nil
	})
	return policy, err
}

// SetSignupPolicy lets an installation administrator allow or forbid account
// creation through workspace invitations.
func (s *Service) SetSignupPolicy(ctx context.Context, actorUserID string, policy SignupPolicy) error {
	if policy != SignupClosed && policy != SignupInvitations {
		return ErrInvalidPolicy
	}
	return s.withInstanceAdministrator(ctx, actorUserID, func(tx *sql.Tx, actor string) error {
		result, err := tx.ExecContext(ctx, `UPDATE registry_installation SET signup_policy = `+bind(s.driver, 1)+` WHERE singleton_id = 1 AND signup_policy <> `+bind(s.driver, 2), string(policy), string(policy))
		if err != nil {
			return errors.New("signup policy could not be updated")
		}
		if changed, err := result.RowsAffected(); err != nil {
			return errors.New("signup policy could not be updated")
		} else if changed == 0 {
			return nil
		}
		return recordAudit(ctx, tx, s.driver, actor, "signup_policy.changed", "installation", "1")
	})
}

func (s *Service) withInstanceAdministrator(ctx context.Context, actorUserID string, operation func(*sql.Tx, string) error) error {
	if ctx == nil {
		return errors.New("installation policy context is required")
	}
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		isAdministrator, err := isInstanceAdministrator(ctx, tx, s.driver, actorID)
		if err != nil {
			return errors.New("administrator authorization could not be checked")
		}
		if !isAdministrator {
			return ErrForbidden
		}
		return operation(tx, actorID)
	})
}

// CreateInvitation issues a single-use invitation to one workspace. Owners may
// invite administrators or members; administrators may invite members only,
// matching the membership delegation rules. The invitation grants membership
// only: repository grants are still assigned explicitly.
func (s *Service) CreateInvitation(ctx context.Context, actorUserID, workspaceID, role string, ttl time.Duration) (IssuedInvitation, error) {
	return s.CreateInvitationFor(ctx, actorUserID, workspaceID, role, ttl, "")
}

// CreateInvitationFor is CreateInvitation that, when address is set, emails
// the link to it. Redeeming an emailed invitation to create an account
// makes that address the account's confirmed address.
func (s *Service) CreateInvitationFor(ctx context.Context, actorUserID, workspaceID, role string, ttl time.Duration, address string) (IssuedInvitation, error) {
	address = strings.TrimSpace(address)
	if address != "" {
		if s.mail == nil {
			return IssuedInvitation{}, ErrEmailUnavailable
		}
		if !email.ValidAddress(address) {
			return IssuedInvitation{}, ErrInvalidInvitation
		}
	}
	if ctx == nil {
		return IssuedInvitation{}, errors.New("invitation context is required")
	}
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return IssuedInvitation{}, ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return IssuedInvitation{}, ErrInvalidWorkspaceID
	}
	if role != RoleAdministrator && role != RoleMember {
		return IssuedInvitation{}, ErrInvalidMembershipRole
	}
	if ttl == 0 {
		ttl = defaultInvitationTTL
	}
	if ttl < time.Minute || ttl > maxInvitationTTL {
		return IssuedInvitation{}, ErrInvalidInvitation
	}
	id, err := uuid.NewV7()
	if err != nil {
		return IssuedInvitation{}, errors.New("invitation identity could not be created")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return IssuedInvitation{}, errors.New("invitation secret could not be created")
	}
	defer clear(secret[:])
	digest := sha256.Sum256(secret[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	issued := IssuedInvitation{ID: id.String(), Role: role, ExpiresAt: now.Add(ttl), Token: invitationPrefix + id.String() + "." + base64.RawURLEncoding.EncodeToString(secret[:])}
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		actorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if actorRole != RoleOwner && actorRole != RoleAdministrator {
			return ErrForbidden
		}
		if actorRole == RoleAdministrator && role != RoleMember {
			return ErrForbidden
		}
		var recipient any
		if address != "" {
			recipient = address
		}
		query := `INSERT INTO registry_workspace_invitations (invitation_id, workspace_id, role, token_sha256, created_by, created_at_ms, expires_at_ms, email) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `)`
		if _, err := tx.ExecContext(ctx, query, issued.ID, workspaceID, role, hex.EncodeToString(digest[:]), actorID, now.UnixMilli(), issued.ExpiresAt.UnixMilli(), recipient); err != nil {
			return errors.New("invitation could not be created")
		}
		if address != "" {
			if err := s.mail.send(ctx, tx, s.driver, issued, workspaceID, actorID, address); err != nil {
				return err
			}
		}
		return recordAudit(ctx, tx, s.driver, actorID, "workspace.invitation.created", "workspace_invitation", issued.ID)
	})
	if err != nil {
		return IssuedInvitation{}, err
	}
	return issued, nil
}

// ListInvitations returns metadata only, for workspace owners and
// administrators. Tokens are never returned.
func (s *Service) ListInvitations(ctx context.Context, actorUserID, workspaceID string) ([]Invitation, error) {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return nil, ErrInvalidWorkspaceID
	}
	var items []Invitation
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		actorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if actorRole != RoleOwner && actorRole != RoleAdministrator {
			return ErrForbidden
		}
		rows, err := tx.QueryContext(ctx, `SELECT invitation_id, role, created_by, created_at_ms, expires_at_ms, redeemed_at_ms, revoked_at_ms, email FROM registry_workspace_invitations WHERE workspace_id = `+bind(s.driver, 1)+` ORDER BY invitation_id DESC LIMIT 200`, workspaceID)
		if err != nil {
			return errors.New("invitations could not be listed")
		}
		defer rows.Close()
		now := time.Now().UTC().UnixMilli()
		for rows.Next() {
			var item Invitation
			var created, expires int64
			var redeemed, revoked sql.NullInt64
			var recipient sql.NullString
			if err := rows.Scan(&item.ID, &item.Role, &item.CreatedBy, &created, &expires, &redeemed, &revoked, &recipient); err != nil {
				return errors.New("invitation could not be read")
			}
			item.CreatedAt, item.ExpiresAt = time.UnixMilli(created).UTC(), time.UnixMilli(expires).UTC()
			item.Email = recipient.String
			switch {
			case redeemed.Valid:
				item.State = "redeemed"
			case revoked.Valid:
				item.State = "revoked"
			case now >= expires:
				item.State = "expired"
			default:
				item.State = "pending"
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

// RevokeInvitation is idempotent for pending invitations.
func (s *Service) RevokeInvitation(ctx context.Context, actorUserID, workspaceID, invitationID string) error {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return ErrInvalidWorkspaceID
	}
	parsed, err := uuid.Parse(invitationID)
	if err != nil || parsed.String() != invitationID {
		return ErrInvitationUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		actorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if actorRole != RoleOwner && actorRole != RoleAdministrator {
			return ErrForbidden
		}
		var role string
		var redeemed, revoked sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT role, redeemed_at_ms, revoked_at_ms FROM registry_workspace_invitations WHERE invitation_id = `+bind(s.driver, 1)+` AND workspace_id = `+bind(s.driver, 2), invitationID, workspaceID).Scan(&role, &redeemed, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvitationUnavailable
		} else if err != nil {
			return errors.New("invitation could not be read")
		}
		if actorRole == RoleAdministrator && role != RoleMember {
			return ErrForbidden
		}
		if redeemed.Valid {
			return ErrInvitationUnavailable
		}
		if revoked.Valid {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_workspace_invitations SET revoked_at_ms = `+bind(s.driver, 1)+` WHERE invitation_id = `+bind(s.driver, 2)+` AND revoked_at_ms IS NULL AND redeemed_at_ms IS NULL`, time.Now().UTC().UnixMilli(), invitationID); err != nil {
			return errors.New("invitation could not be revoked")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "workspace.invitation.revoked", "workspace_invitation", invitationID)
	})
}

type pendingInvitation struct {
	id, workspaceID, role, creator string
	email                          sql.NullString
}

// checkInvitation validates the token without using it.
func (s *Service) checkInvitation(ctx context.Context, tx *sql.Tx, token string) (pendingInvitation, error) {
	fail := func(err error) (pendingInvitation, error) { return pendingInvitation{}, err }
	idText, encoded, found := strings.Cut(strings.TrimPrefix(token, invitationPrefix), ".")
	parsed, err := uuid.Parse(idText)
	if !strings.HasPrefix(token, invitationPrefix) || !found || err != nil || parsed.String() != idText || len(encoded) != 43 {
		return fail(ErrInvitationUnavailable)
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return fail(ErrInvitationUnavailable)
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	var workspaceID, role, storedHash, creator string
	var expires int64
	var redeemed, revoked sql.NullInt64
	var recipient sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT i.workspace_id, i.role, i.token_sha256, i.created_by, i.expires_at_ms, i.redeemed_at_ms, i.revoked_at_ms, i.email FROM registry_workspace_invitations i JOIN registry_workspaces w ON w.workspace_id = i.workspace_id WHERE i.invitation_id = `+bind(s.driver, 1)+` AND w.status = 'active'`, idText).Scan(&workspaceID, &role, &storedHash, &creator, &expires, &redeemed, &revoked, &recipient)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(ErrInvitationUnavailable)
	} else if err != nil {
		return fail(errors.New("invitation could not be read"))
	}
	stored, err := hex.DecodeString(storedHash)
	if err != nil || len(stored) != sha256.Size || subtle.ConstantTimeCompare(stored, digest[:]) != 1 || redeemed.Valid || revoked.Valid || time.Now().UTC().UnixMilli() >= expires {
		return fail(ErrInvitationUnavailable)
	}
	// The inviter must still be allowed to invite this role; a demoted or
	// removed inviter's pending invitations stop working.
	creatorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, creator)
	if err != nil || (creatorRole != RoleOwner && creatorRole != RoleAdministrator) || (creatorRole == RoleAdministrator && role != RoleMember) {
		return fail(ErrInvitationUnavailable)
	}
	if err := requireActiveUser(ctx, tx, s.driver, creator); err != nil {
		return fail(ErrInvitationUnavailable)
	}
	return pendingInvitation{id: idText, workspaceID: workspaceID, role: role, creator: creator, email: recipient}, nil
}

// consumeInvitation validates the token and marks it used by userID inside the
// caller's transaction, then adds the membership.
func (s *Service) consumeInvitation(ctx context.Context, tx *sql.Tx, token, userID string) (pendingInvitation, error) {
	invitation, err := s.checkInvitation(ctx, tx, token)
	if err != nil {
		return pendingInvitation{}, err
	}
	workspaceID, err := s.applyInvitation(ctx, tx, invitation, userID)
	if err != nil {
		return pendingInvitation{}, err
	}
	invitation.workspaceID = workspaceID
	return invitation, nil
}

func (s *Service) applyInvitation(ctx context.Context, tx *sql.Tx, invitation pendingInvitation, userID string) (string, error) {
	idText, workspaceID, role, creator := invitation.id, invitation.workspaceID, invitation.role, invitation.creator
	_, status, exists, err := readMembership(ctx, tx, s.driver, workspaceID, userID)
	if err != nil {
		return "", errors.New("workspace membership could not be read")
	}
	if exists && status == "active" {
		return "", ErrAlreadyMember
	}
	if exists && status == "suspended" {
		return "", ErrMembershipUnavailable
	}
	result, err := tx.ExecContext(ctx, `UPDATE registry_workspace_invitations SET redeemed_at_ms = `+bind(s.driver, 1)+`, redeemed_by = `+bind(s.driver, 2)+` WHERE invitation_id = `+bind(s.driver, 3)+` AND redeemed_at_ms IS NULL AND revoked_at_ms IS NULL`, time.Now().UTC().UnixMilli(), userID, idText)
	if err != nil {
		return "", errors.New("invitation could not be redeemed")
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return "", ErrInvitationUnavailable
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if exists {
		_, err = tx.ExecContext(ctx, `UPDATE registry_workspace_memberships SET role = `+bind(s.driver, 1)+`, status = 'active', updated_at = `+bind(s.driver, 2)+` WHERE workspace_id = `+bind(s.driver, 3)+` AND user_id = `+bind(s.driver, 4), role, now, workspaceID, userID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, 'active', `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`, `+bind(s.driver, 6)+`)`, workspaceID, userID, role, creator, now, now)
	}
	if err != nil {
		return "", errors.New("workspace membership could not be created")
	}
	if err := recordAudit(ctx, tx, s.driver, userID, "workspace.invitation.redeemed", "workspace_invitation", idText); err != nil {
		return "", err
	}
	return workspaceID, nil
}

// AcceptInvitation adds the signed-in account to the invitation's workspace.
// It does not depend on the signup policy: no account is created.
func (s *Service) AcceptInvitation(ctx context.Context, actorUserID, token string) (string, error) {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return "", ErrUnauthenticated
	}
	var workspaceID string
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		invitation, err := s.consumeInvitation(ctx, tx, token, actorID)
		workspaceID = invitation.workspaceID
		return err
	})
	return workspaceID, err
}

// RedeemInvitation creates a local account and its membership in one
// transaction. The installation must allow signup by invitation. The account
// gets no repository access; if the invitation is for an administrator, the
// next sign-in requires TOTP enrollment.
func (s *Service) RedeemInvitation(ctx context.Context, token, loginName, displayName string, passwordValue []byte) (string, string, error) {
	if ctx == nil {
		return "", "", errors.New("invitation context is required")
	}
	login, display, err := bootstrap.ValidateLocalAccount(loginName, displayName, passwordValue)
	if err != nil {
		return "", "", ErrInvalidAccount
	}
	// Hash outside the transaction: Argon2id is deliberately slow.
	hash, err := password.Hash(passwordValue)
	if err != nil {
		return "", "", errors.New("password could not be hashed")
	}
	userID, err := uuid.NewV7()
	if err != nil {
		return "", "", errors.New("account identity could not be created")
	}
	var workspaceID string
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		var policy string
		if err := tx.QueryRowContext(ctx, `SELECT signup_policy FROM registry_installation WHERE singleton_id = 1`).Scan(&policy); err != nil {
			return errors.New("signup policy could not be read")
		}
		if policy != string(SignupInvitations) {
			return ErrSignupClosed
		}
		var taken bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_local_credentials WHERE login_name = `+bind(s.driver, 1)+`)`, login).Scan(&taken); err != nil {
			return errors.New("login name could not be checked")
		}
		// The token is checked before the login name result is reported, so
		// an invalid token cannot be used to probe which names exist.
		if taken {
			if _, err := s.checkInvitation(ctx, tx, token); err != nil {
				return err
			}
			return ErrLoginNameTaken
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		{
			if _, err := tx.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`)`, userID.String(), display, now, now); err != nil {
				return errors.New("account could not be created")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO registry_local_credentials (user_id, login_name, password_hash, created_at, updated_at, password_changed_at) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`, `+bind(s.driver, 6)+`)`, userID.String(), login, hash, now, now, now); err != nil {
				return ErrLoginNameTaken
			}
		}
		invitation, err := s.consumeInvitation(ctx, tx, token, userID.String())
		if err != nil {
			return err
		}
		workspaceID = invitation.workspaceID
		// The link reached this person at the invited address.
		if invitation.email.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE registry_users SET email = `+bind(s.driver, 1)+`, email_verified = TRUE WHERE user_id = `+bind(s.driver, 2), invitation.email.String, userID.String()); err != nil {
				return errors.New("account email could not be recorded")
			}
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return userID.String(), workspaceID, nil
}
