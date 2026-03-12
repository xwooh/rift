use std::future::Future;
use std::io::{self, Write};
use std::time::Duration;

use tokio::time::{self, MissedTickBehavior};

pub(crate) async fn run_with_progress_dots<T, F>(label: &str, future: F) -> T
where
    F: Future<Output = T>,
{
    print!("{label}");
    let _ = io::stdout().flush();

    tokio::pin!(future);

    let mut ticker = time::interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            result = &mut future => {
                println!();
                return result;
            }
            _ = ticker.tick() => {
                print!(".");
                let _ = io::stdout().flush();
            }
        }
    }
}
