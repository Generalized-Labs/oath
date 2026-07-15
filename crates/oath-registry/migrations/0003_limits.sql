CREATE TABLE IF NOT EXISTS registry_rate_limits (
    subject_hash TEXT NOT NULL,
    bucket TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    request_count BIGINT NOT NULL,
    PRIMARY KEY(subject_hash,bucket,window_start)
);
CREATE INDEX IF NOT EXISTS registry_rate_limits_expiry
    ON registry_rate_limits(window_start);
