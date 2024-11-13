use anyhow::Context;
use clap::{Parser, Subcommand};
use holochain_client::{AgentPubKey, AuthorizeSigningCredentialsPayload, IssueAppAuthenticationTokenPayload, SigningCredentials};
use holochain_types::app::{AppBundleSource, InstallAppPayload, InstalledAppId};
use holochain_types::prelude::{AppBundle, CapAccess, CellId, GrantZomeCallCapabilityPayload, GrantedFunctions, ZomeCallCapGrant, CAP_SECRET_BYTES};
use holochain_types::websocket::AllowedOrigins;
use mr_bundle::{Bundle, Location};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::ptr::copy;
use std::sync::Arc;
use holochain_conductor_api::CellInfo;
use html5ever::tendril::fmt::Slice;
use rand::RngCore;
use rand::rngs::OsRng;
use sha3::Digest;
use tokio::sync::Mutex;
use warp::http::{HeaderValue, Response, StatusCode, Uri};
use warp::{Filter, Rejection, Reply};
use tracing_subscriber::fmt::format::FmtSpan;

mod inject;

const EKTO_LIB: &str = include_str!("../ekto-lib/dist/ekto-lib.js");

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
        webapp: PathBuf,
    },

    /// Approve access for a signing key pair (based on the public key)
    Approve {
        // The name of the app.
        //
        // This will be the same as the name of the bundled app that was installed
        #[arg(long)]
        app_id: InstalledAppId,

        key: String,
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterRequest {
    public_key: Vec<u8>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,warp=debug".to_owned());
    tracing_subscriber::fmt()
        // Use the filter we built above to determine which traces to record.
        .with_env_filter(filter)
        // Record an event when each span closes. This can be used to time our
        // routes' durations!
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let cli = Cli::parse();

    let mut hasher = sha3::Sha3_256::new();
    hasher.update(EKTO_LIB.as_bytes());
    let hash = hasher.finalize();
    let ekto_lib_hash = format!("{hash:x}");

    println!("Hash: {}", ekto_lib_hash);

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

                                inject::inject_ekto(out, EKTO_LIB, ekto_lib_hash.clone()).context("Failed to inject ekto")?;
                            } else {
                                inject::require_ekto_lib_latest(out, EKTO_LIB, ekto_lib_hash.clone()).context("Failed to update ekto lib")?;
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

                client
                    .enable_app(name.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to enable app: {e:?}"))?;
            }

            let app_port = find_or_create_holochain_app_interface(&client).await?;

            let client = Arc::new(Mutex::new(client));
            let installed_app_id = name.to_string();
            let shim = warp::path!("ekto-shim.js")
                .and(with_shim_args(client, ekto_lib_hash, installed_app_id))
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

                        let mut rng = rand::thread_rng();
                        let mut salt_bytes = [0u8; 16];
                        rng.fill_bytes(&mut salt_bytes);

                        let ekto_lib_hash = shim_args.ekto_lib_hash.clone();
                        let installed_app_id = shim_args.installed_app_id.clone();
                        Result::<_, warp::Rejection>::Ok(
                            Response::builder()
                                .header("cache-control", "private, no-store, no-cache")
                                .header("content-type", "application/javascript")
                                .body(format!(
                                    r#"
                                    import {{generateKey, zomeCallSignerFactory}} from './ekto-lib-{ekto_lib_hash}.js';

                  window.__HC_LAUNCHER_ENV__ = {{
                    APP_INTERFACE_PORT: {app_port},
                    INSTALLED_APP_ID: "{installed_app_id}",
                    APP_INTERFACE_TOKEN: {token:?},
                  }};

                  const salt = {salt_bytes:?};

                  const submitPassword = async (e) => {{
                    e.preventDefault();
                    e.stopPropagation();

                    try {{
                        const password = document.getElementById("ekto-password").value;

                        if (!password) {{
                            console.error("Password is required");
                            return false;
                        }}

                        const keyPair = await generateKey(password, Uint8Array.from(salt));

                        const signer = await zomeCallSignerFactory(keyPair);
                        window.__HC_ZOME_CALL_SIGNER__ = {{
                            signZomeCall: signer,
                        }};

                        document.getElementById("ekto-auth-container").remove();
                    }} catch (e) {{
                        console.error("Failed to get password:", e);
                    }}

                    return false;
                  }};

                  const container = document.createElement("div");
                  container.setAttribute("style", "height: 100vh; width: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center;");
                  container.setAttribute("id", "ekto-auth-container");
                  document.body.insertBefore(container, document.body.firstChild);

                  const form = document.createElement("form");
                  form.setAttribute("style", "width: 25%;");
                  form.onsubmit = submitPassword;
                  container.appendChild(form);

                  const label = document.createElement("label");
                  label.innerText = "Ekto password:";
                  label.setAttribute("for", "ekto-password");
                  form.appendChild(label);

                  const formSection = document.createElement("div");
                  formSection.setAttribute("style", "display: flex; flex-direction: row;");
                  form.appendChild(formSection);

                  const input = document.createElement("input");
                  input.setAttribute("type", "password");
                  input.setAttribute("id", "ekto-password");
                  input.setAttribute("style", "height: 3.5em; flex-grow: 3; background-color: aliceblue; margin-right: 5px; padding: 5px; border-radius: 5px;");
                  formSection.appendChild(input);

                  const button = document.createElement("button");
                  button.innerText = "Submit";
                  button.setAttribute("style", "background: azure; padding: 1em; border-radius: 5px;");
                  button.setAttribute("type", "submit");
                  formSection.appendChild(button);
                "#
                                )),
                        )
                    },
                );

            let register = warp::post()
                .and(warp::path::path("ekto-register"))
                .and(warp::path::end())
                .and(warp::body::content_length_limit(200))
                .and(warp::body::json())
                .map(|register_request: RegisterRequest| {
                    println!("A new key requires approval: {}", hex::encode(register_request.public_key));
                    Response::builder().status(StatusCode::OK).body("")
                });

            let out = warp::get().and(warp::fs::dir("./out/"));
            warp::serve(shim.or(register).or(out))
                .run(([127, 0, 0, 1], 8484))
                .await;
        }
        Commands::Approve { app_id, key } => {
            let key_bytes = hex::decode(key).context("Failed to decode key")?;
            if key_bytes.len() != 32 {
                anyhow::bail!("Key must be 32 bytes long");
            }

            let client = match try_connect_holochain_admin_client().await? {
                Some(c) => c,
                None => anyhow::bail!("Couldn't connect to Holochain admin interface"),
            };

            let app = client.list_apps(None).await.map_err(|e| {
                anyhow::anyhow!("Failed to list apps: {e:?}")
            })?.into_iter().find(|app| &app.installed_app_id == app_id).ok_or_else(|| {
                anyhow::anyhow!("App not found")
            })?;

            for cell_info in app.cell_info.values().flatten() {
                let cell_id = match cell_info {
                    CellInfo::Provisioned(cell) => cell.cell_id.clone(),
                    CellInfo::Cloned(_) => {
                        println!("Clone cells are not supported");
                        continue
                    },
                    CellInfo::Stem(_) => {
                        println!("Stem cells are not supported");
                        continue
                    }
                };

                let mut cap_secret = [0; CAP_SECRET_BYTES];
                cap_secret[..32].clone_from_slice(key_bytes.as_bytes());
                cap_secret[32..].clone_from_slice(key_bytes.as_bytes());

                let mut key_with_location = key_bytes.clone();
                key_with_location.extend(&[0, 0, 0, 0]);

                client.grant_zome_call_capability(GrantZomeCallCapabilityPayload {
                    cell_id: cell_id.clone(),
                    cap_grant: ZomeCallCapGrant {
                        tag: "zome-call-signing-key".to_string(),
                        access: CapAccess::Assigned {
                            secret: cap_secret.into(),
                            assignees: BTreeSet::from([AgentPubKey::from_raw_36(key_with_location.clone())]),
                        },
                        functions: GrantedFunctions::All,
                    },
                })
                    .await
                    .map_err(|e| anyhow::anyhow!("Conductor API error: {:?}", e))?;

                println!("Granted zome call capability for cell: {:?}", cell_id);
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
struct ShimArgs {
    client: Arc<Mutex<holochain_client::AdminWebsocket>>,
    ekto_lib_hash: String,
    installed_app_id: InstalledAppId,
}

fn with_shim_args(
    client: Arc<Mutex<holochain_client::AdminWebsocket>>,
    ekto_lib_hash: String,
    installed_app_id: InstalledAppId,
) -> impl Filter<Extract = (ShimArgs,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || ShimArgs {
        client: client.clone(),
        ekto_lib_hash: ekto_lib_hash.clone(),
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
