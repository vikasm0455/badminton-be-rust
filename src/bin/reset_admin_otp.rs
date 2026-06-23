//! Admin recovery CLI (PRD §4.3.1). Clears OTP rate limits, attempt counters,
//! and the lockout flag for ADMIN_EMAIL so a locked-out owner can log in again.
//!
//! Usage: `cargo run --bin reset-admin-otp`

use redis::AsyncCommands;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let admin_email = match std::env::var("ADMIN_EMAIL") {
        Ok(e) if !e.trim().is_empty() => e.trim().to_lowercase(),
        _ => {
            eprintln!("ADMIN_EMAIL is not set in the environment / .env");
            std::process::exit(1);
        }
    };
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(redis_url).expect("invalid REDIS_URL");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("could not connect to Redis");

    let keys = [
        format!("otp:login:{admin_email}"),
        format!("otp:login:{admin_email}:attempts"),
        format!("otp:login:{admin_email}:sent_at"),
        format!("otp:signup:{admin_email}"),
        format!("otp:signup:{admin_email}:attempts"),
        format!("otp:signup:{admin_email}:sent_at"),
        format!("otp_req:{admin_email}"),
        format!("failcount:{admin_email}"),
        format!("lockflag:{admin_email}"),
    ];

    let mut cleared = 0u32;
    for key in &keys {
        let removed: i64 = conn.del(key).await.unwrap_or(0);
        cleared += removed as u32;
    }

    println!("Cleared {cleared} rate-limit/lockout key(s) for {admin_email}.");
    println!("The admin can now request a fresh login code.");
}
