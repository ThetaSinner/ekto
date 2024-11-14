use crate::holochain_external::try_connect_holochain_admin_client;
use anyhow::Context;
use holochain_conductor_api::CellInfo;
use holochain_types::app::InstalledAppId;
use holochain_types::prelude::{
    AgentPubKey, CapAccess, GrantZomeCallCapabilityPayload, GrantedFunctions, ZomeCallCapGrant,
    CAP_SECRET_BYTES,
};
use std::collections::BTreeSet;

pub(crate) async fn approve_key(key: &String, app_id: &InstalledAppId) -> anyhow::Result<()> {
    let key_bytes = hex::decode(key).context("Failed to decode key")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("Key must be 32 bytes long");
    }

    let client = match try_connect_holochain_admin_client().await? {
        Some(c) => c,
        None => anyhow::bail!("Couldn't connect to Holochain admin interface"),
    };

    let app = client
        .list_apps(None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list apps: {e:?}"))?
        .into_iter()
        .find(|app| &app.installed_app_id == app_id)
        .ok_or_else(|| anyhow::anyhow!("App not found"))?;

    for cell_info in app.cell_info.values().flatten() {
        let cell_id = match cell_info {
            CellInfo::Provisioned(cell) => cell.cell_id.clone(),
            CellInfo::Cloned(_) => {
                tracing::warn!("Clone cells are not supported");
                continue;
            }
            CellInfo::Stem(_) => {
                tracing::warn!("Stem cells are not supported");
                continue;
            }
        };

        let mut cap_secret = [0; CAP_SECRET_BYTES];
        cap_secret[..32].clone_from_slice(key_bytes.as_slice());
        cap_secret[32..].clone_from_slice(key_bytes.as_slice());

        // TODO Needs to match what the UI sends as "provenance" in zome calls but really
        //      Holochain should be correcting missing or wrong location bytes because it's
        //      an internal detail and the UI shouldn't have to know about it.
        //      Equally, why is the capability not found if these location bytes don't match?
        //      It's only the 32-bit agent public key that identifies the agent, and the location
        //      bytes are meta-data.
        let mut key_with_location = key_bytes.clone();
        key_with_location.extend(&[0, 0, 0, 0]);

        client
            .grant_zome_call_capability(GrantZomeCallCapabilityPayload {
                cell_id: cell_id.clone(),
                cap_grant: ZomeCallCapGrant {
                    tag: "zome-call-signing-key".to_string(),
                    access: CapAccess::Assigned {
                        secret: cap_secret.into(),
                        assignees: BTreeSet::from([AgentPubKey::from_raw_36(
                            key_with_location.clone(),
                        )]),
                    },
                    functions: GrantedFunctions::All,
                },
            })
            .await
            .map_err(|e| anyhow::anyhow!("Conductor API error: {:?}", e))?;

        println!("Granted zome call capability for cell: {:?}", cell_id);
        tracing::info!("Granted zome call capability for cell: {:?}", cell_id);
    }

    Ok(())
}
