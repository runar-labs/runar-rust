use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use log::LevelFilter;
use runar_macros_common::{log_debug, log_info};
use runar_node::network::transport::{NetworkMessage, NetworkTransport};
use runar_node::network::{QuicTransport, QuicTransportOptions};
use runar_schemas::NodeInfo;
// no-op

use runar_transport_tests::quic_interop_common::{
    build_node_info, default_label_resolver, default_logger, read_pem_certs, read_pem_key,
    CommonArgs, NoCrypto,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = CommonArgs::parse();
    // Ensure env_logger is initialized so macros route through `log` crate
    let _ = env_logger::builder()
        .is_test(false)
        .filter_level(LevelFilter::Info)
        .try_init();
    let logger = default_logger();
    let logger_for_handlers = logger.clone();
    let logger_for_one_way = logger.clone();

    // Parse bind address (required for server)
    let bind_str = args
        .bind
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--bind is required for server"))?;
    let bind_addr: SocketAddr = bind_str.parse().context("invalid --bind address")?;

    // Read certs and key
    let chain = read_pem_certs(&args.cert)?;
    let key = read_pem_key(&args.key)?;
    let _root_cas = read_pem_certs(&args.ca)?; // note: server config does not need CA for rustls/quinn, client uses SNI; we keep for parity

    // node_id for server SNI matching is the certificate DNS SAN; we accept provided --node-id
    let node_id = args.node_id.unwrap_or_else(|| "rust-server".to_string());

    // Minimal message handler (echo request -> response)
    let handler: runar_node::network::transport::MessageHandler =
        Box::new(move |msg: NetworkMessage| {
            let logger = logger_for_handlers.clone();
            Box::pin(async move {
                log_debug!(
                    logger,
                    "server received msg type={} from {}",
                    msg.message_type,
                    msg.source_node_id
                );
                if msg.message_type == runar_node::network::transport::MESSAGE_TYPE_REQUEST {
                    let reply = NetworkMessage {
                        source_node_id: msg.destination_node_id.clone(),
                        destination_node_id: msg.source_node_id.clone(),
                        message_type: runar_node::network::transport::MESSAGE_TYPE_RESPONSE,
                        payloads: msg.payloads.clone(),
                    };
                    return Ok(Some(reply));
                }
                Ok(None)
            })
        });

    // One-way event handler just logs
    let one_way: runar_node::network::transport::OneWayMessageHandler =
        Box::new(move |msg: NetworkMessage| {
            let logger = logger_for_one_way.clone();
            Box::pin(async move {
                log_info!(logger, "server received event from {}", msg.source_node_id);
                Ok(())
            })
        });

    let keystore = Arc::new(NoCrypto);
    let label_resolver = default_label_resolver();

    // Build NodeInfo; we set node_public_key bytes to node_id bytes for interop simplicity
    let node_info: NodeInfo = build_node_info(&node_id, &bind_addr);

    let opts = QuicTransportOptions::new()
        .with_certificates(chain)
        .with_private_key(key)
        .with_get_local_node_info(Arc::new(move || {
            let node_info = node_info.clone();
            Box::pin(async move { Ok(node_info) })
        }))
        .with_bind_addr(bind_addr)
        .with_message_handler(handler)
        .with_one_way_message_handler(one_way)
        .with_logger(logger.clone())
        .with_keystore(keystore)
        .with_label_resolver(label_resolver)
        .with_response_cache_ttl(Duration::from_secs(2));

    let transport = Arc::new(QuicTransport::new(opts).map_err(|e| anyhow::anyhow!("{e}"))?);
    transport.clone().start().await?;
    log_info!(
        logger,
        "quic_interop_server listening on {}",
        transport.get_local_address()
    );

    // Run until SIGINT/SIGTERM; for simplicity sleep forever
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
