use anyhow::Context;
use clap::{Parser, Subcommand};
use holochain_client::IssueAppAuthenticationTokenPayload;
use holochain_types::app::{AppBundleSource, InstallAppPayload, InstalledAppId};
use holochain_types::prelude::AppBundle;
use holochain_types::websocket::AllowedOrigins;
use mr_bundle::{Bundle, Location};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::http::{HeaderValue, Response, StatusCode};
use warp::Filter;

mod inject;

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
            let bundle =
                mr_bundle::Bundle::<holochain_types::web_app::WebAppManifest>::read_from_file(
                    webapp,
                )
                .await?;

            let name = bundle.manifest().app_name();
            println!("{}", name);

            match bundle.manifest() {
                holochain_types::web_app::WebAppManifest::V1(manifest) => {
                    match &manifest.ui.location {
                        mr_bundle::Location::Bundled(path) => {
                            let ui = bundle.bundled_resources().get(path);
                            println!("Found UI: {:?}", ui);
                            std::fs::write("./temp.zip", ui.unwrap().inner())
                                .context("Couldn't write UI zip file")?;
                            let mut zip = zip::ZipArchive::new(
                                std::fs::File::open("./temp.zip")
                                    .context("Couldn't read back UI zip")?,
                            )?;

                            let out = std::path::PathBuf::from("out");
                            if !out.exists() {
                                std::fs::create_dir_all(&out)
                                    .context("Failed to create out dir")?;
                                for i in 0..zip.len() {
                                    let mut file = zip.by_index(i)?;
                                    if file.is_dir() {
                                        std::fs::create_dir_all(out.join(file.name()))?;
                                        continue;
                                    }

                                    let mut out_to = out.clone();
                                    out_to.push(std::path::Path::new(file.name())); // TODO security
                                    std::io::copy(
                                        &mut file,
                                        &mut std::fs::File::create(&out_to).with_context(|| {
                                            format!("Could not create file {out_to:?}")
                                        })?,
                                    )?;
                                }

                                inject::inject_ekto_shim(out)
                                    .context("Failed to inject ekto shim")?;
                            }
                        }
                        location => {
                            anyhow::bail!(
                                "Only bundled resources are supported, this UI is: {:?}",
                                location
                            );
                        }
                    }
                }
            }

            let client = match try_connect_holochain_admin_client().await? {
                Some(c) => c,
                None => anyhow::bail!("Couldn't connect to Holochain admin interface"),
            };

            let app_location = bundle.manifest().happ_bundle_location();
            let app = match app_location {
                Location::Bundled(path) => bundle.bundled_resources().get(&path).unwrap().inner(),
                location => {
                    anyhow::bail!(
                        "Only bundled resources are supported, this hApp is: {:?}",
                        location
                    );
                }
            };

            let app_bundle = Bundle::<holochain_types::app::AppManifest>::decode(app)?;

            let name = app_bundle.manifest().app_name().to_string();
            let apps = client
                .list_apps(None)
                .await
                .map_err(|e| anyhow::anyhow!("Could not list apps: {e:?}"))?;
            if !apps.iter().any(|app| app.installed_app_id == name) {
                let agent_key = client
                    .generate_agent_pub_key()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to generate agent key: {e:?}"))?;

                client
                    .install_app(InstallAppPayload {
                        installed_app_id: None,
                        agent_key,
                        membrane_proofs: Default::default(),
                        network_seed: None,
                        source: AppBundleSource::Bundle(AppBundle::from(app_bundle)),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to install app: {e:?}"))?;
            }

            let app_port = find_or_create_holochain_app_interface(&client).await?;

            let client = Arc::new(Mutex::new(client));
            let installed_app_id = name.to_string();
            let shim = warp::path!("ekto-shim.js")
                .and(with_shim_args(client, installed_app_id))
                .and(warp::header::optional("Origin"))
                .and_then(
                    move |shim_args: ShimArgs, origin: Option<HeaderValue>| async move {
                        println!("Request from origin: {:?}", origin);

                        let token_issued = match shim_args
                            .client
                            .lock()
                            .await
                            .issue_app_auth_token(IssueAppAuthenticationTokenPayload {
                                installed_app_id: shim_args.installed_app_id.clone(),
                                expiry_seconds: 10,
                                single_use: true,
                            })
                            .await
                        {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("Failed to issue app auth token: {e:?}");
                                return Ok(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body("Failed to issue app auth token".to_string()));
                            }
                        };
                        let token = token_issued.token;

                        let installed_app_id = shim_args.installed_app_id.clone();
                        Result::<_, warp::Rejection>::Ok(
                            Response::builder()
                                .header("cache-control", "private, no-store, no-cache")
                                .header("content-type", "application/javascript")
                                .body(format!(
                                    r#"
                  window.__HC_LAUNCHER_ENV__ = {{
                    APP_INTERFACE_PORT: {app_port},
                    INSTALLED_APP_ID: "{installed_app_id}",
                    APP_INTERFACE_TOKEN: {token:?},
                  }};
                "#
                                )),
                        )
                    },
                );

            let out = warp::get().and(warp::fs::dir("./out/"));
            println!();
            warp::serve(shim.or(out)).run(([127, 0, 0, 1], 8484)).await;
        }
    }

    Ok(())
}

#[derive(Clone)]
struct ShimArgs {
    client: Arc<Mutex<holochain_client::AdminWebsocket>>,
    installed_app_id: InstalledAppId,
}

fn with_shim_args(
    client: Arc<Mutex<holochain_client::AdminWebsocket>>,
    installed_app_id: InstalledAppId,
) -> impl Filter<Extract = (ShimArgs,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || ShimArgs {
        client: client.clone(),
        installed_app_id: installed_app_id.clone(),
    })
}

async fn try_connect_holochain_admin_client(
) -> anyhow::Result<Option<holochain_client::AdminWebsocket>> {
    let mut found_ports = HashSet::new();
    let proc = proc_ctl::ProcQuery::new()
        .process_name("holochain")
        .list_processes()
        .context("Failed to query for Holochain process")?;
    for proc in proc {
        let ports = proc_ctl::PortQuery::new()
            .process_id(proc.pid)
            .tcp_only()
            .execute()
            .context("Failed to query for Holochain ports")?;
        for port in ports {
            if let proc_ctl::ProtocolPort::Tcp(port) = port {
                found_ports.insert(port);
            }
        }
    }

    for port in found_ports {
        if let Ok(client) =
            holochain_client::AdminWebsocket::connect((Ipv6Addr::LOCALHOST, port)).await
        {
            if client.list_app_interfaces().await.is_ok() {
                return Ok(Some(client));
            }
        }
    }

    Ok(None)
}

async fn find_or_create_holochain_app_interface(
    client: &holochain_client::AdminWebsocket,
) -> anyhow::Result<u16> {
    let app_interfaces = client
        .list_app_interfaces()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list app interfaces: {e:?}"))?;

    for interface in app_interfaces {
        if interface.installed_app_id.is_none() && interface.allowed_origins == AllowedOrigins::Any
        {
            return Ok(interface.port);
        }
    }

    client
        .attach_app_interface(0, AllowedOrigins::Any, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to attach app interface: {e:?}"))
}
