DROP TABLE IF EXISTS rate_limiter;
CREATE TABLE rate_limiter(
    request_url BLOB,
    class_name VARCHAR(25),
    method_name VARCHAR(25),
    ip_address VARCHAR(25),
    blocked_till DATETIME,
    created_at DATETIME DEFAULT NOW(),
    last_updated_at DATETIME,
    UNIQUE INDEX idx (class_name, method_name, ip_address, created_at)
);