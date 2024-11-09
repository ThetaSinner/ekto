use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Context;
use warp::Filter;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a webapp
    Run {
        /// The .webhapp file to load
        #[arg()]
        webapp: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { webapp } => {
            println!("{}", webapp.to_str().unwrap());
            let file = std::fs::read(webapp).context("Couldn't load webhapp")?;
            let bundle = mr_bundle::Bundle::<holochain_types::web_app::WebAppManifest>::read_from_file(webapp).await?;
            // let manifest = mr_bundle::decode::<holochain_types::web_app::WebAppManifest>(&file)?;

            let name = bundle.manifest().app_name();
            println!("{}", name);

            match bundle.manifest() {
                holochain_types::web_app::WebAppManifest::V1(manifest) => {
                    match &manifest.ui.location {
                        mr_bundle::Location::Bundled(path) => {
                            println!("Bundled at {:?}", path);
                            let ui = bundle.bundled_resources().get(path);
                            println!("Found UI: {:?}", ui);
                            std::fs::write("./temp.zip", ui.unwrap().inner()).context("Couldn't write UI zip file")?;
                            use zip::HasZipMetadata;
                            let mut zip = zip::ZipArchive::new(std::fs::File::open("./temp.zip").context("Couldn't read back UI zip")?)?;

                            let out = std::path::PathBuf::from("out");
                            std::fs::create_dir_all(&out).context("Failed to create out dir")?;
                            for i in 0..zip.len() {
                                let mut file = zip.by_index(i)?;
                                println!("Filename: {}", file.name());

                                let mut out_to = out.clone();
                                out_to.push(std::path::Path::new(file.name())); // TODO security
                                std::fs::create_dir_all(&out_to.parent().unwrap())?;
                                println!("output to: {:?}", out_to);
                                std::io::copy(&mut file, &mut std::fs::File::create(out_to)?)?;
                            }
                        }
                        location => {
                            anyhow::bail!("Only bundled resources are supported, this UI is: {:?}", location);
                        }
                    }
                }
            }

            let out = warp::fs::dir("./out/");

            warp::serve(out)
                .run(([127, 0, 0, 1], 8484))
                .await;
        }
    }

    Ok(())
}
