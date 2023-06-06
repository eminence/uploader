CREATE TABLE aliases (
	alias  TEXT PRIMARY KEY,
	uuid TEXT NOT NULL,
    blob TEXT NOT NULL,
	created NUMBER NOT NULL,
	expires NUMBER NOT NULL,
	cf TEXT,
	contentType TEXT,
);