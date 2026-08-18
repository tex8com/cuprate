use std::{
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Instant,
};

use futures::channel::oneshot;
use rayon::ThreadPool;
use tower::Service;

use cuprate_database::{ConcreteEnv, DbResult, RuntimeError};
use cuprate_helper::asynch::InfallibleOneshotReceiver;

fn sync_db_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CUPRATE_SYNC_DB_TRACE").is_some())
}

/// The [`rayon::ThreadPool`] service.
///
/// Uses an inner request handler and a rayon thread-pool to asynchronously handle requests.
///
/// - `Req` is the request type
/// - `Res` is the response type
pub struct DatabaseReadService<Req, Res> {
    /// Handle to the custom `rayon` DB reader thread-pool.
    ///
    /// Requests are [`rayon::ThreadPool::spawn`]ed in this thread-pool,
    /// and responses are returned via a channel we (the caller) provide.
    pool: Arc<ThreadPool>,

    /// The function used to handle request.
    inner_handler: Arc<dyn Fn(Req) -> DbResult<Res> + Send + Sync + 'static>,
}

// Deriving [`Clone`] means `Req` & `Res` need to be `Clone`, even if they aren't.
impl<Req, Res> Clone for DatabaseReadService<Req, Res> {
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            inner_handler: Arc::clone(&self.inner_handler),
        }
    }
}

impl<Req, Res> DatabaseReadService<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    /// Creates the [`DatabaseReadService`] with the provided backing thread-pool.
    ///
    /// Should be called _once_ per actual database, although nothing bad will happen, cloning the [`DatabaseReadService`]
    /// is the correct way to get multiple handles to the database.
    #[cold]
    #[inline(never)] // Only called once.
    pub fn new(
        env: Arc<ConcreteEnv>,
        pool: Arc<ThreadPool>,
        req_handler: impl Fn(&ConcreteEnv, Req) -> DbResult<Res> + Send + Sync + 'static,
    ) -> Self {
        let inner_handler = Arc::new(move |req| req_handler(&env, req));

        Self {
            pool,
            inner_handler,
        }
    }
}

impl<Req, Res> Service<Req> for DatabaseReadService<Req, Res>
where
    Req: Send + 'static,
    Res: Send + 'static,
{
    type Response = Res;
    type Error = RuntimeError;
    type Future = InfallibleOneshotReceiver<DbResult<Self::Response>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<DbResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Req) -> Self::Future {
        // Response channel we `.await` on.
        let (response_sender, receiver) = oneshot::channel();

        let handler = Arc::clone(&self.inner_handler);
        let submitted_at = Instant::now();
        let trace_db_queue = sync_db_trace_enabled();
        let request_type = std::any::type_name::<Req>();

        // Spawn the request in the rayon DB thread-pool.
        //
        // Note that this uses `self.pool` instead of `rayon::spawn`
        // such that any `rayon` parallel code that runs within
        // the passed closure uses the same `rayon` threadpool.
        self.pool.spawn(move || {
            let queue_ms = submitted_at.elapsed().as_secs_f64() * 1000.0;
            let execution_started_at = Instant::now();
            let response = handler(req);
            let execution_ms = execution_started_at.elapsed().as_secs_f64() * 1000.0;

            if trace_db_queue {
                eprintln!(
                    "[SYNC_TRACE_DB] request_type={} queue_ms={:.3} execution_ms={:.3}",
                    request_type, queue_ms, execution_ms,
                );
            }

            drop(response_sender.send(response));
        });

        InfallibleOneshotReceiver::from(receiver)
    }
}
