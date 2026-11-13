package repositories

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"private-registry/internal/workspaces"
)

var ErrReviewPolicyRevision = errors.New("review policy revision is stale")

type ReviewPolicy struct {
	Required bool
	Revision int64
}

func (s *Service) GoReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (ReviewPolicy, error) {
	return s.reviewPolicy(ctx, actorUserID, workspaceID, repositoryID, FormatGo)
}

// CargoReviewPolicy remains internal until reviewed publication is available.
func (s *Service) CargoReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (ReviewPolicy, error) {
	return s.reviewPolicy(ctx, actorUserID, workspaceID, repositoryID, FormatCargo)
}

// NPMReviewPolicy remains internal until npm publication is available.
func (s *Service) NPMReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (ReviewPolicy, error) {
	return s.reviewPolicy(ctx, actorUserID, workspaceID, repositoryID, FormatNPM)
}

// OCIReviewPolicy reports whether new OCI manifests wait for human review.
func (s *Service) OCIReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (ReviewPolicy, error) {
	return s.reviewPolicy(ctx, actorUserID, workspaceID, repositoryID, FormatOCI)
}

// SetOCIReviewPolicy changes whether new OCI manifests wait for review.
// Content already published is unaffected.
func (s *Service) SetOCIReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, required bool) (ReviewPolicy, error) {
	return s.setReviewPolicy(ctx, actorUserID, workspaceID, repositoryID, expectedRevision, required, FormatOCI)
}

// PubReviewPolicy remains internal until Pub publication is available.
func (s *Service) PubReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (ReviewPolicy, error) {
	return s.reviewPolicy(ctx, actorUserID, workspaceID, repositoryID, FormatPub)
}

func (s *Service) reviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, format Format) (ReviewPolicy, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ReviewPolicy{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return ReviewPolicy{}, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return ReviewPolicy{}, ErrInvalidRepositoryID
	}
	if ctx == nil {
		return ReviewPolicy{}, errors.New("review policy context is required")
	}
	var policy ReviewPolicy
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner && role != workspaces.RoleAdministrator {
			return ErrForbidden
		}
		if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, format); err != nil {
			return err
		}
		query := `SELECT review_required, review_revision FROM registry_repositories WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2)
		var required int
		if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&required, &policy.Revision); err != nil {
			return errors.New("repository review policy could not be read")
		}
		policy.Required = required == 1
		return nil
	})
	if err != nil {
		return ReviewPolicy{}, err
	}
	return policy, nil
}

// SetGoReviewPolicy is internal until reviewer management and reviewed
// publication exist. Enabling it holds all in-flight and received Go uploads;
// disabling it never clears existing holds.
func (s *Service) SetGoReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, required bool) (ReviewPolicy, error) {
	return s.setReviewPolicy(ctx, actorUserID, workspaceID, repositoryID, expectedRevision, required, FormatGo)
}

// SetCargoReviewPolicy holds pending Cargo receipts when review becomes
// required. Disabling the policy never clears an existing review hold.
func (s *Service) SetCargoReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, required bool) (ReviewPolicy, error) {
	return s.setReviewPolicy(ctx, actorUserID, workspaceID, repositoryID, expectedRevision, required, FormatCargo)
}

// SetNPMReviewPolicy holds pending npm receipts when review becomes required;
// disabling the policy never clears an existing hold.
func (s *Service) SetNPMReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, required bool) (ReviewPolicy, error) {
	return s.setReviewPolicy(ctx, actorUserID, workspaceID, repositoryID, expectedRevision, required, FormatNPM)
}

// SetPubReviewPolicy holds pending Pub receipts without clearing existing holds.
func (s *Service) SetPubReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, required bool) (ReviewPolicy, error) {
	return s.setReviewPolicy(ctx, actorUserID, workspaceID, repositoryID, expectedRevision, required, FormatPub)
}

func (s *Service) setReviewPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, required bool, format Format) (ReviewPolicy, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ReviewPolicy{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return ReviewPolicy{}, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return ReviewPolicy{}, ErrInvalidRepositoryID
	}
	if ctx == nil || expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return ReviewPolicy{}, ErrReviewPolicyRevision
	}
	var policy ReviewPolicy
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner && role != workspaces.RoleAdministrator {
			return ErrForbidden
		}
		if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, format); err != nil {
			return err
		}
		query := `SELECT review_required, review_revision FROM registry_repositories WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2)
		var old int
		if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&old, &policy.Revision); err != nil {
			return errors.New("repository review policy could not be read")
		}
		if policy.Revision != expectedRevision {
			return ErrReviewPolicyRevision
		}
		policy.Required = old == 1
		if policy.Required == required {
			return nil
		}
		value := 0
		if required {
			value = 1
		}
		query = `UPDATE registry_repositories SET review_required = ` + bind(s.driver, 1) + `, review_revision = review_revision + 1 WHERE workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND review_revision = ` + bind(s.driver, 4)
		result, err := tx.ExecContext(ctx, query, value, workspaceID, repositoryID, expectedRevision)
		if err != nil {
			return errors.New("repository review policy could not be changed")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrReviewPolicyRevision
		}
		if required {
			if format == FormatGo {
				query = `UPDATE registry_go_upload_sessions SET review_hold = 1 WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status IN ('receiving', 'uploading', 'uploaded')`
			} else if format == FormatCargo {
				query = `UPDATE registry_cargo_reservations SET review_hold = 1 WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_cargo_publications p WHERE p.reservation_id = registry_cargo_reservations.reservation_id)`
			} else if format == FormatNPM {
				query = `UPDATE registry_npm_reservations SET review_hold = 1 WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_npm_publications p WHERE p.reservation_id = registry_npm_reservations.reservation_id)`
			} else if format == FormatPub {
				query = `UPDATE registry_pub_reservations SET review_hold = 1 WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_pub_publications p WHERE p.reservation_id = registry_pub_reservations.reservation_id)`
			} else if format != FormatOCI {
				return errors.New("repository review format is unsupported")
			}
			// OCI has no upload reservations to hold: manifests are checked
			// against the policy when they are pushed.
			if format != FormatOCI {
				if _, err := tx.ExecContext(ctx, query, workspaceID, repositoryID); err != nil {
					return errors.New("pending uploads could not be held for review")
				}
			}
		}
		if err := recordAudit(ctx, tx, s.driver, actorID, "repository.review_policy.changed", "repository", repositoryID); err != nil {
			return err
		}
		policy.Required = required
		policy.Revision++
		return nil
	})
	if err != nil {
		return ReviewPolicy{}, err
	}
	return policy, nil
}
