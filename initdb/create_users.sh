#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$user" --dbname "$database" <<-EOSQL
	CREATE USER ${readOnlyUser} WITH LOGIN PASSWORD '${readOnlyUserPassword}';
	\connect ${database};
	GRANT CONNECT ON DATABASE ${database} TO ${readOnlyUser};
    GRANT USAGE ON SCHEMA public TO ${readOnlyUser};
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${readOnlyUser};


    CREATE USER ${writeOnlyUser} WITH PASSWORD '${writeOnlyUserPassword}';
    GRANT CONNECT ON DATABASE ${database} TO ${writeOnlyUser};
    \c ${database}
    GRANT USAGE ON SCHEMA public TO ${writeOnlyUser};
    GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${writeOnlyUser};
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT, UPDATE, DELETE ON TABLES TO ${writeOnlyUser};
EOSQL