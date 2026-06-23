use std::convert::Infallible;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::AuthUser;
use crate::state::AppState;

/// Real-time nudge stream (PRD §14.4). Emits small typed events; clients refetch
/// the affected resource. Keep-alive comments keep proxies from closing it.
pub async fn reservations_stream(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(ev) => Some(Ok(Event::default()
            .json_data(&ev)
            .unwrap_or_else(|_| Event::default().data("{}")))),
        // Dropped messages on lag: skip rather than tear down the stream.
        Err(_) => None,
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive"),
    )
}
