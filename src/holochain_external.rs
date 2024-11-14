use anyhow::Context;
use holochain_types::websocket::AllowedOrigins;
use std::collections::HashSet;
use std::net::Ipv6Addr;

pub(crate) async fn try_connect_holochain_admin_client(
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

pub(crate) async fn find_or_create_holochain_app_interface(
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
