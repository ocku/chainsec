mod app;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    app::execute().await
}
