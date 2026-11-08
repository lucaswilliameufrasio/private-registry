-- +goose Up
ALTER TABLE registry_repositories DROP CONSTRAINT registry_repositories_format_check;
ALTER TABLE registry_repositories ADD CONSTRAINT registry_repositories_format_check CHECK (format IN ('generic', 'go', 'cargo', 'npm', 'pub'));

-- +goose Down
-- Forward-only: repository identities and format assignments must not be discarded.
