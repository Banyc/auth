use std::sync::Arc;

use rand::Rng;
use serde::{Deserialize, Serialize};

/// Obfuscated user credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: Arc<str>,
    pub password: Password,
}
/// Obfuscated password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Password {
    hash: U256,
    salt: u64,
}
impl Credential {
    /// Obfuscate the sensitive credential
    pub fn generate(username: Arc<str>, password: &str) -> Self {
        let salt: u64 = rand::thread_rng().gen();
        let hash = hash_password(password, salt);
        let password = Password { hash, salt };
        Self { username, password }
    }

    /// Check if the provided credential is valid
    pub fn matches(&self, username: &str, password: &str) -> bool {
        if username != self.username.as_ref() {
            return false;
        }
        let hash = hash_password(password, self.password.salt);
        if self.password.hash != hash {
            return false;
        }
        true
    }
}

/// Hash a password into a 256-bit unsigned integer
fn hash_password(password: &str, salt: u64) -> U256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt.to_le_bytes());
    let hash = hasher.finalize();
    let hash: [u8; 32] = hash.into();
    U256::from(hash)
}

/// Represent a 256-bit unsigned integer with only the flat fields
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct U256 {
    u_0: u64,
    u_1: u64,
    u_2: u64,
    u_3: u64,
}
impl From<[u8; 32]> for U256 {
    fn from(value: [u8; 32]) -> Self {
        let u_0 = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let u_1 = u64::from_le_bytes(value[8..16].try_into().unwrap());
        let u_2 = u64::from_le_bytes(value[16..24].try_into().unwrap());
        let u_3 = u64::from_le_bytes(value[24..32].try_into().unwrap());
        Self { u_0, u_1, u_2, u_3 }
    }
}
impl PartialEq for U256 {
    fn eq(&self, other: &Self) -> bool {
        self.u_0 == other.u_0
            && self.u_1 == other.u_1
            && self.u_2 == other.u_2
            && self.u_3 == other.u_3
    }
}

#[cfg(test)]
mod tests {
    use sqlx::{Connection, SqliteConnection};

    use super::*;

    #[test]
    fn test_matches() {
        let c = Credential::generate("foo".into(), "bar");
        assert!(c.matches("foo", "bar"));
        assert!(!c.matches("foo", "foo"));
    }

    #[tokio::test]
    async fn test_db_compatibility() {
        // Map a credential to the database model
        let c = Credential::generate("foo".into(), "bar");
        let password = ron::to_string(&c.password).unwrap();
        let u = User {
            username: c.username.to_string(),
            password,
            role: String::from("guest"),
        };

        // Write and read the database
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query(r#"create table user ( username text primary key, password text not null, role text not null )"#)
            .execute(&mut conn)
            .await.unwrap();
        sqlx::query(r#"insert into user ( username, password, role ) values ( $1, $2, $3 )"#)
            .bind(&u.username)
            .bind(&u.password)
            .bind(&u.role)
            .execute(&mut conn)
            .await
            .unwrap();
        let r_u: User = sqlx::query_as(r#"select * from user where username = $1"#)
            .bind(&u.username)
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(u, r_u);

        // Decode the credential part
        let password = ron::from_str(&r_u.password).unwrap();
        let r_c = Credential {
            username: r_u.username.into(),
            password,
        };

        // Auth
        assert!(r_c.matches(&c.username, "bar"));

        #[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
        struct User {
            username: String,
            password: String,
            role: String,
        }
    }
}
