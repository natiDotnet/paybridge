//! Database access. SQLite for local development (default), PostgreSQL for
//! production — selected at compile time with `--features pg`.
//!
//! All queries are written once in the SQLite dialect (`?` placeholders) and
//! translated for Postgres by the q() helper: `?` becomes `$1, $2, ...` (no
//! SQL literal in this codebase contains a literal `?`). Column types that
//! decode as i64 on both (INTEGER on SQLite) are BIGINT in the Postgres
//! schema (migrations_postgres/).

#[cfg(feature = "pg")]
use std::collections::HashMap;
#[cfg(not(feature = "pg"))]
use std::str::FromStr;
#[cfg(feature = "pg")]
use std::sync::Mutex;

#[cfg(not(feature = "pg"))]
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
#[cfg(feature = "pg")]
use sqlx::postgres::PgPoolOptions;

/// The active database driver.
#[cfg(not(feature = "pg"))]
pub type Db = sqlx::Sqlite;
#[cfg(feature = "pg")]
pub type Db = sqlx::Postgres;

/// The connection pool held in app state.
#[cfg(not(feature = "pg"))]
pub type Pool = sqlx::SqlitePool;
#[cfg(feature = "pg")]
pub type Pool = sqlx::PgPool;

/// QueryBuilder bound to the active driver (dynamic WHERE clauses).
#[cfg(not(feature = "pg"))]
pub type QueryBuilderDb<'args> = sqlx::query_builder::QueryBuilder<'args, sqlx::Sqlite>;
#[cfg(feature = "pg")]
pub type QueryBuilderDb<'args> = sqlx::query_builder::QueryBuilder<'args, sqlx::Postgres>;

/// Open the pool for DATABASE_URL (sqlite:// in dev, postgres:// in prod).
pub async fn create_pool(url: &str) -> Result<Pool, sqlx::Error> {
    #[cfg(not(feature = "pg"))]
    {
        let opts = SqliteConnectOptions::from_str(url)?
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
    }
    #[cfg(feature = "pg")]
    {
        PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await
    }
}

/// Apply migrations for the active driver.
pub async fn migrate(pool: &Pool) -> Result<(), sqlx::migrate::MigrateError> {
    #[cfg(not(feature = "pg"))]
    return sqlx::migrate!().run(pool).await;
    #[cfg(feature = "pg")]
    {
        use sqlx::migrate::{Migration, MigrationType, Migrator};
        static SQL: &str = include_str!("../migrations_postgres/0001_schema.sql");
        let migration = Migration::new(
            1,
            std::borrow::Cow::Borrowed("init"),
            MigrationType::Simple,
            std::borrow::Cow::Borrowed(SQL),
            false,
        );
        let migrations = vec![migration];
        let migrator = Migrator {
            ignore_missing: false,
            locking: true,
            no_tx: false,
            migrations: std::borrow::Cow::Owned(migrations),
        };
        migrator.run(pool).await
    }
}

/// Translate a query written in the SQLite dialect to the active driver.
/// Postgres: ? placeholders become $1, $2, ... cached per unique query.
/// SQLite: the query passes through unchanged.
fn q<'q>(sql: &'q str) -> &'q str {
    #[cfg(not(feature = "pg"))]
    {
        sql
    }
    #[cfg(feature = "pg")]
    {
        static CACHE: Mutex<Option<HashMap<&'static str, &'static str>>> = Mutex::new(None);
        let mut cache = CACHE.lock().expect("q() cache poisoned");
        let cache = cache.get_or_insert_with(HashMap::new);
        let bare: &str = sql;
        if let Some(found) = cache.get(bare) {
            return found;
        }
        let mut translated = String::with_capacity(sql.len() + 8);
        let mut n = 0usize;
        for ch in sql.chars() {
            if ch == '?' {
                n += 1;
                translated.push_str(&format!("${n}"));
            } else {
                translated.push(ch);
            }
        }
        // The set of distinct query strings is bounded (~120), so leaking the
        // cache entries keeps them valid for the request lifetime safely.
        let key: &'static str = Box::leak(sql.to_string().into_boxed_str());
        let leaked: &'static str = Box::leak(translated.into_boxed_str());
        cache.insert(key, leaked);
        leaked
    }
}

/// sqlx::query in the active dialect.
pub fn query<'q>(
    sql: &'q str,
) -> sqlx::query::Query<'q, Db, <Db as sqlx::Database>::Arguments<'q>> {
    sqlx::query(q(sql))
}

/// sqlx::query_as in the active dialect.
pub fn query_as<'q, T>(
    sql: &'q str,
) -> sqlx::query::QueryAs<'q, Db, T, <Db as sqlx::Database>::Arguments<'q>>
where
    T: for<'r> sqlx::FromRow<'r, <Db as sqlx::Database>::Row>,
{
    sqlx::query_as::<Db, T>(q(sql))
}

/// QueryBuilder in the active dialect (dynamic filters).
pub fn query_builder<'args>(sql: &'args str) -> QueryBuilderDb<'args> {
    QueryBuilderDb::new(q(sql))
}
