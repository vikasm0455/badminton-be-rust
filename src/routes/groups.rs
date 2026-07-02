//! Groups: creation, membership, email invites, and active-group switching.
//! Every gameplay surface (polls, courts, logins) is scoped to the caller's
//! ACTIVE group; users may belong to many groups but play with one at a time.

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::models::ApiResponse;
use crate::state::AppState;
use crate::email;

const MAX_GROUPS_PER_USER: i64 = 20;
const MAX_PENDING_INVITES_PER_GROUP: i64 = 50;
const INVITE_TTL_DAYS: i64 = 30;

// ---- active-group context ----------------------------------------------------

/// The caller's active group + their role in it. The unit of scoping for the
/// whole gameplay API.
pub struct GroupCtx {
    pub group_id: Uuid,
    pub role: String,
}

impl GroupCtx {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// Resolve the caller's active group, verifying they're still a member of it.
pub async fn active_group(state: &AppState, user_id: Uuid) -> Result<GroupCtx, ApiError> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT gm.group_id, gm.role
         FROM users u
         JOIN group_members gm ON gm.group_id = u.active_group_id AND gm.user_id = u.id
         WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    row.map(|(group_id, role)| GroupCtx { group_id, role })
        .ok_or_else(|| ApiError::Conflict("You're not in a group yet — create or join one first.".into()))
}

/// Like active_group, but requires the caller to be that group's admin.
pub async fn require_group_admin(state: &AppState, user_id: Uuid) -> Result<GroupCtx, ApiError> {
    let ctx = active_group(state, user_id).await?;
    if !ctx.is_admin() {
        return Err(ApiError::Forbidden);
    }
    Ok(ctx)
}

// ---- my groups ----------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct GroupBrief {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub member_count: i64,
    pub is_active: bool,
}

pub async fn list_mine(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Vec<GroupBrief>>>, ApiError> {
    let rows = my_groups(&state, user.id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

async fn my_groups(state: &AppState, user_id: Uuid) -> Result<Vec<GroupBrief>, ApiError> {
    let rows: Vec<GroupBrief> = sqlx::query_as(
        "SELECT g.id, g.name, gm.role,
                (SELECT COUNT(*) FROM group_members m2 WHERE m2.group_id = g.id) AS member_count,
                (g.id IS NOT DISTINCT FROM u.active_group_id) AS is_active
         FROM group_members gm
         JOIN groups g ON g.id = gm.group_id
         JOIN users u ON u.id = gm.user_id
         WHERE gm.user_id = $1
         ORDER BY g.created_at ASC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

#[derive(Deserialize)]
pub struct CreateGroupReq {
    pub name: String,
}

fn valid_group_name(name: &str) -> bool {
    let len = name.chars().count();
    (2..=60).contains(&len)
}

pub async fn create_group(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateGroupReq>,
) -> Result<Json<ApiResponse<GroupBrief>>, ApiError> {
    let name = req.name.trim().to_string();
    if !valid_group_name(&name) {
        return Err(ApiError::BadRequest("Group name must be 2–60 characters.".into()));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE user_id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await?;
    if count >= MAX_GROUPS_PER_USER {
        return Err(ApiError::BadRequest("You're already in the maximum number of groups.".into()));
    }

    let mut tx = state.db.begin().await?;
    let gid: Uuid = sqlx::query_scalar("INSERT INTO groups (name, created_by) VALUES ($1, $2) RETURNING id")
        .bind(&name)
        .bind(user.id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'admin')")
        .bind(gid)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    // Creating a group makes it your active one.
    sqlx::query("UPDATE users SET active_group_id = $1 WHERE id = $2")
        .bind(gid)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(ApiResponse::ok(GroupBrief {
        id: gid,
        name,
        role: "admin".into(),
        member_count: 1,
        is_active: true,
    })))
}

#[derive(Deserialize)]
pub struct SetActiveReq {
    pub group_id: Uuid,
}

pub async fn set_active(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SetActiveReq>,
) -> Result<Json<ApiResponse<Vec<GroupBrief>>>, ApiError> {
    let member: Option<(String,)> =
        sqlx::query_as("SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2")
            .bind(req.group_id)
            .bind(user.id)
            .fetch_optional(&state.db)
            .await?;
    if member.is_none() {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("UPDATE users SET active_group_id = $1 WHERE id = $2")
        .bind(req.group_id)
        .bind(user.id)
        .execute(&state.db)
        .await?;
    let rows = my_groups(&state, user.id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

// ---- current group detail ------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct GroupMemberRow {
    pub id: Uuid,
    pub display_name: String,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct GroupDetail {
    pub id: Uuid,
    pub name: String,
    pub my_role: String,
    pub members: Vec<GroupMemberRow>,
}

pub async fn current_group(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<GroupDetail>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let name: String = sqlx::query_scalar("SELECT name FROM groups WHERE id = $1")
        .bind(ctx.group_id)
        .fetch_one(&state.db)
        .await?;
    let members: Vec<GroupMemberRow> = sqlx::query_as(
        "SELECT u.id, u.display_name, gm.role, gm.joined_at
         FROM group_members gm JOIN users u ON u.id = gm.user_id
         WHERE gm.group_id = $1
         ORDER BY (gm.role = 'admin') DESC, u.display_name ASC",
    )
    .bind(ctx.group_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ApiResponse::ok(GroupDetail {
        id: ctx.group_id,
        name,
        my_role: ctx.role,
        members,
    })))
}

#[derive(Deserialize)]
pub struct RenameGroupReq {
    pub name: String,
}

pub async fn rename_group(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RenameGroupReq>,
) -> Result<Json<ApiResponse<GroupDetail>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    let name = req.name.trim().to_string();
    if !valid_group_name(&name) {
        return Err(ApiError::BadRequest("Group name must be 2–60 characters.".into()));
    }
    sqlx::query("UPDATE groups SET name = $1 WHERE id = $2")
        .bind(&name)
        .bind(ctx.group_id)
        .execute(&state.db)
        .await?;
    current_group(State(state), user).await
}

// ---- membership management -----------------------------------------------------

#[derive(Deserialize)]
pub struct SetRoleReq {
    pub role: String,
}

pub async fn set_member_role(
    State(state): State<AppState>,
    user: AuthUser,
    Path(member_id): Path<Uuid>,
    Json(req): Json<SetRoleReq>,
) -> Result<Json<ApiResponse<GroupDetail>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    if !matches!(req.role.as_str(), "admin" | "member") {
        return Err(ApiError::BadRequest("role must be admin or member".into()));
    }
    // Never allow a demotion that would leave the group without any admin.
    if req.role == "member" {
        let other_admins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM group_members
             WHERE group_id = $1 AND role = 'admin' AND user_id <> $2",
        )
        .bind(ctx.group_id)
        .bind(member_id)
        .fetch_one(&state.db)
        .await?;
        if other_admins == 0 {
            return Err(ApiError::Conflict("A group needs at least one admin.".into()));
        }
    }
    let res = sqlx::query("UPDATE group_members SET role = $1 WHERE group_id = $2 AND user_id = $3")
        .bind(&req.role)
        .bind(ctx.group_id)
        .bind(member_id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    current_group(State(state), user).await
}

pub async fn remove_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(member_id): Path<Uuid>,
) -> Result<Json<ApiResponse<GroupDetail>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    if member_id == user.id {
        return Err(ApiError::BadRequest("Use “Leave group” to remove yourself.".into()));
    }
    let res = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
        .bind(ctx.group_id)
        .bind(member_id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    repoint_active_group(&state, member_id, ctx.group_id).await?;
    current_group(State(state), user).await
}

pub async fn leave_group(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Vec<GroupBrief>>>, ApiError> {
    let ctx = active_group(&state, user.id).await?;
    let member_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
        .bind(ctx.group_id)
        .fetch_one(&state.db)
        .await?;

    if member_count == 1 {
        // Sole member walking away → the group dissolves (CASCADE cleans up).
        sqlx::query("DELETE FROM groups WHERE id = $1").bind(ctx.group_id).execute(&state.db).await?;
    } else {
        if ctx.is_admin() {
            let other_admins: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM group_members
                 WHERE group_id = $1 AND role = 'admin' AND user_id <> $2",
            )
            .bind(ctx.group_id)
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;
            if other_admins == 0 {
                return Err(ApiError::Conflict(
                    "You're the only admin — promote another member first.".into(),
                ));
            }
        }
        sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND user_id = $2")
            .bind(ctx.group_id)
            .bind(user.id)
            .execute(&state.db)
            .await?;
    }

    repoint_active_group(&state, user.id, ctx.group_id).await?;
    let rows = my_groups(&state, user.id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// If `user`'s active group is `left_group`, repoint it to their most recently
/// joined other group (or NULL when they have none left).
async fn repoint_active_group(state: &AppState, user_id: Uuid, left_group: Uuid) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET active_group_id =
            (SELECT group_id FROM group_members
             WHERE user_id = $1 AND group_id <> $2
             ORDER BY joined_at DESC LIMIT 1)
         WHERE id = $1 AND active_group_id = $2",
    )
    .bind(user_id)
    .bind(left_group)
    .execute(&state.db)
    .await?;
    Ok(())
}

// ---- invites: group-admin side ---------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct GroupInviteRow {
    pub id: Uuid,
    pub email: String,
    pub invited_by_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct SendInviteReq {
    pub email: String,
}

pub async fn send_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SendInviteReq>,
) -> Result<Json<ApiResponse<Vec<GroupInviteRow>>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    let invite_email = req.email.trim().to_lowercase();
    if !invite_email.contains('@') || invite_email.len() < 5 || invite_email.len() > 254 {
        return Err(ApiError::BadRequest("a valid email is required".into()));
    }

    // Already a member? (by account email)
    let already: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id FROM users u
         JOIN group_members gm ON gm.user_id = u.id AND gm.group_id = $1
         WHERE LOWER(u.email) = $2",
    )
    .bind(ctx.group_id)
    .bind(&invite_email)
    .fetch_optional(&state.db)
    .await?;
    if already.is_some() {
        return Err(ApiError::Conflict("That person is already in this group.".into()));
    }

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM group_invites
         WHERE group_id = $1 AND accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL",
    )
    .bind(ctx.group_id)
    .fetch_one(&state.db)
    .await?;
    if pending >= MAX_PENDING_INVITES_PER_GROUP {
        return Err(ApiError::BadRequest("Too many pending invites — revoke some first.".into()));
    }

    let inserted = sqlx::query(
        "INSERT INTO group_invites (group_id, email, invited_by, expires_at)
         VALUES ($1, $2, $3, NOW() + make_interval(days => $4))",
    )
    .bind(ctx.group_id)
    .bind(&invite_email)
    .bind(user.id)
    .bind(INVITE_TTL_DAYS as i32)
    .execute(&state.db)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            return Err(ApiError::Conflict("There's already a pending invite for that email.".into()));
        }
        Err(e) => return Err(e.into()),
    }

    // Best-effort email; the invite is visible in-app either way.
    let (group_name, inviter): (String, String) = sqlx::query_as(
        "SELECT g.name, u.display_name FROM groups g, users u WHERE g.id = $1 AND u.id = $2",
    )
    .bind(ctx.group_id)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;
    email::send_group_invite(&state, &invite_email, &group_name, &inviter).await.ok();

    list_group_invites_inner(&state, ctx.group_id).await.map(|rows| Json(ApiResponse::ok(rows)))
}

pub async fn list_group_invites(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Vec<GroupInviteRow>>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    let rows = list_group_invites_inner(&state, ctx.group_id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

async fn list_group_invites_inner(state: &AppState, group_id: Uuid) -> Result<Vec<GroupInviteRow>, ApiError> {
    let rows: Vec<GroupInviteRow> = sqlx::query_as(
        "SELECT gi.id, gi.email, u.display_name AS invited_by_name, gi.created_at, gi.expires_at
         FROM group_invites gi JOIN users u ON u.id = gi.invited_by
         WHERE gi.group_id = $1 AND gi.accepted_at IS NULL AND gi.declined_at IS NULL
           AND gi.revoked_at IS NULL AND gi.expires_at > NOW()
         ORDER BY gi.created_at DESC",
    )
    .bind(group_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

pub async fn revoke_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invite_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<GroupInviteRow>>>, ApiError> {
    let ctx = require_group_admin(&state, user.id).await?;
    let res = sqlx::query(
        "UPDATE group_invites SET revoked_at = NOW()
         WHERE id = $1 AND group_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(invite_id)
    .bind(ctx.group_id)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let rows = list_group_invites_inner(&state, ctx.group_id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

// ---- invites: invitee side --------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct MyInvite {
    pub id: Uuid,
    pub group_id: Uuid,
    pub group_name: String,
    pub invited_by_name: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
}

pub async fn my_invites(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<ApiResponse<Vec<MyInvite>>>, ApiError> {
    let rows = my_invites_inner(&state, user.id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

async fn my_invites_inner(state: &AppState, user_id: Uuid) -> Result<Vec<MyInvite>, ApiError> {
    let rows: Vec<MyInvite> = sqlx::query_as(
        "SELECT gi.id, gi.group_id, g.name AS group_name, iu.display_name AS invited_by_name,
                (SELECT COUNT(*) FROM group_members m WHERE m.group_id = gi.group_id) AS member_count,
                gi.created_at
         FROM group_invites gi
         JOIN groups g ON g.id = gi.group_id
         JOIN users iu ON iu.id = gi.invited_by
         JOIN users me ON me.id = $1
         WHERE LOWER(gi.email) = LOWER(me.email)
           AND gi.accepted_at IS NULL AND gi.declined_at IS NULL AND gi.revoked_at IS NULL
           AND gi.expires_at > NOW()
           AND NOT EXISTS (SELECT 1 FROM group_members gm WHERE gm.group_id = gi.group_id AND gm.user_id = $1)
         ORDER BY gi.created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows)
}

pub async fn accept_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invite_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<GroupBrief>>>, ApiError> {
    // The invite must be addressed to MY account email and still be live.
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT gi.group_id FROM group_invites gi JOIN users me ON me.id = $2
         WHERE gi.id = $1 AND LOWER(gi.email) = LOWER(me.email)
           AND gi.accepted_at IS NULL AND gi.declined_at IS NULL AND gi.revoked_at IS NULL
           AND gi.expires_at > NOW()",
    )
    .bind(invite_id)
    .bind(user.id)
    .fetch_optional(&state.db)
    .await?;
    let (group_id,) = row.ok_or_else(|| ApiError::BadRequest("This invite is no longer valid.".into()))?;

    let mut tx = state.db.begin().await?;
    // Conditional claim: a concurrent revoke/decline/expiry between the SELECT
    // above and here loses the race cleanly instead of being overwritten.
    let claimed = sqlx::query(
        "UPDATE group_invites SET accepted_at = NOW()
         WHERE id = $1 AND accepted_at IS NULL AND declined_at IS NULL
           AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(invite_id)
    .execute(&mut *tx)
    .await?;
    if claimed.rows_affected() == 0 {
        return Err(ApiError::BadRequest("This invite is no longer valid.".into()));
    }
    sqlx::query(
        "INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')
         ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;
    // First group? It becomes the active one.
    sqlx::query("UPDATE users SET active_group_id = $1 WHERE id = $2 AND active_group_id IS NULL")
        .bind(group_id)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let rows = my_groups(&state, user.id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}

pub async fn decline_invite(
    State(state): State<AppState>,
    user: AuthUser,
    Path(invite_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<MyInvite>>>, ApiError> {
    let res = sqlx::query(
        "UPDATE group_invites gi SET declined_at = NOW()
         FROM users me
         WHERE gi.id = $1 AND me.id = $2 AND LOWER(gi.email) = LOWER(me.email)
           AND gi.accepted_at IS NULL AND gi.declined_at IS NULL AND gi.revoked_at IS NULL",
    )
    .bind(invite_id)
    .bind(user.id)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let rows = my_invites_inner(&state, user.id).await?;
    Ok(Json(ApiResponse::ok(rows)))
}
