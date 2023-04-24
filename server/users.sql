CREATE TABLE IF NOT EXISTS  users(
        id INTEGER PRIMARY KEY,
        name VARCHAR,
        created INTEGER,
        last_login INTEGER,
        hash VARCHAR,
        pub_key VARCHAR
);