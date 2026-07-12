use blackbox::cli::Cli;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cli = Cli::parse();
        cli.execute().await
    })
}
