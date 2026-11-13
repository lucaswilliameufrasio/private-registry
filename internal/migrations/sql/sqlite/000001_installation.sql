-- +goose Up
CREATE TABLE registry_installation (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    installation_id TEXT NOT NULL UNIQUE CHECK (length(installation_id) = 36),
    created_at TEXT NOT NULL
);

-- +goose Down
DROP TABLE registry_installation;
