-- Schéma de l'issuer (base "issuer")
CREATE SCHEMA IF NOT EXISTS issuer;

-- Identité de la personne (clé = NIN, imprimé au verso)
CREATE TABLE issuer.person (
    nin             VARCHAR(32) PRIMARY KEY,
    given_name      VARCHAR(128) NOT NULL,
    family_name     VARCHAR(128) NOT NULL,
    date_of_birth   DATE NOT NULL,
    place_of_birth  VARCHAR(128),
    sex             CHAR(1) NOT NULL CHECK (sex IN ('M','F')),
    height_cm       INTEGER,
    nationality     VARCHAR(3) NOT NULL DEFAULT 'SEN',
    address         TEXT,
    photo_jpeg      BYTEA,
    status          VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','DECEASED')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Carte d'identité CEDEAO : recto + MRZ du verso (contrôlée par l'application)
CREATE TABLE issuer.id_card (
    card_number          VARCHAR(32) PRIMARY KEY,          -- 17 chiffres, sans espaces
    nin                  VARCHAR(32) NOT NULL REFERENCES issuer.person(nin),
    date_of_issue        DATE NOT NULL,
    date_of_expiry       DATE NOT NULL,
    registration_center  VARCHAR(64),
    issuing_country      VARCHAR(3) NOT NULL DEFAULT 'SEN',
    mrz_line1            CHAR(30) NOT NULL,
    mrz_line2            CHAR(30) NOT NULL,
    mrz_line3            CHAR(30) NOT NULL,
    status               VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','LOST','REVOKED')),
    CHECK (date_of_expiry > date_of_issue)
);
CREATE INDEX ix_id_card_nin ON issuer.id_card(nin);

-- Informations électorales (verso)
CREATE TABLE issuer.electoral_registration (
    nin              VARCHAR(32) PRIMARY KEY REFERENCES issuer.person(nin),
    voter_number     VARCHAR(16) NOT NULL UNIQUE,
    region           VARCHAR(64),
    department       VARCHAR(64),
    arrondissement   VARCHAR(64),
    commune          VARCHAR(128),
    polling_place    VARCHAR(128),
    polling_station  VARCHAR(8)
);

-- Journal des VC émis
CREATE TABLE issuer.issued_credential (
    id                UUID PRIMARY KEY,
    vc_id             VARCHAR(64) NOT NULL UNIQUE,
    nin               VARCHAR(32) NOT NULL REFERENCES issuer.person(nin),
    card_number       VARCHAR(32) NOT NULL REFERENCES issuer.id_card(card_number),
    configuration_id  VARCHAR(64) NOT NULL,
    holder_id         TEXT,
    keycloak_subject  VARCHAR(64),
    client_id         VARCHAR(128),
    credential        JSONB NOT NULL,
    status            VARCHAR(16) NOT NULL DEFAULT 'VALID',
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ
);
CREATE INDEX ix_issued_credential_nin ON issuer.issued_credential(nin);

-- Clé de signature de l'issuer
CREATE TABLE issuer.issuer_key (
    kid                   VARCHAR(128) PRIMARY KEY,
    key_type              VARCHAR(32) NOT NULL DEFAULT 'Ed25519',
    public_key_multibase  VARCHAR(128) NOT NULL,
    private_key_pem       BYTEA NOT NULL,                  -- PKCS#8 chiffré (ISSUER_KEY_PASSPHRASE)
    active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- c_nonce OID4VCI (usage unique)
CREATE TABLE issuer.c_nonce (
    nonce       VARCHAR(64) PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE
);
