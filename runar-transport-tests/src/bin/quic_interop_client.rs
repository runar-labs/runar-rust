use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::LevelFilter;
use runar_macros_common::log_info;
use runar_schemas::NodeInfo;
use runar_serializer::ArcValue;
use runar_transporter::discovery::multicast_discovery::PeerInfo;
use runar_transporter::transport::{
    MessageContext, MessageHandler, NetworkMessage, NetworkTransport,
};
use runar_transporter::transport::{OneWayMessageHandler, QuicTransport, QuicTransportOptions};

use runar_transport_tests::quic_interop_common::{
    build_node_info, default_label_resolver, default_logger, make_echo_request, read_pem_certs,
    read_pem_key, topic_echo, CommonArgs, NoCrypto,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = CommonArgs::parse();
    let _ = env_logger::builder()
        .is_test(false)
        .filter_level(LevelFilter::Info)
        .try_init();
    let logger = default_logger();

    // peer is required
    let peer = args
        .peer
        .as_deref()
        .ok_or_else(|| anyhow!("--peer is required"))?;
    let peer_addr: SocketAddr = peer.parse().context("invalid --peer address")?;

    // For client, bind ephemeral unless provided
    let bind_addr: SocketAddr = match args.bind.as_deref() {
        Some(b) => b.parse().context("invalid --bind address")?,
        None => "0.0.0.0:0".parse().unwrap(),
    };

    // Read certs and key
    let chain = read_pem_certs(&args.cert)?;
    let key = read_pem_key(&args.key)?;
    let _roots = read_pem_certs(&args.ca)?;

    let node_id = args.node_id.unwrap_or_else(|| "rust-client".to_string());

    // Simple handlers; client mostly initiates request and event
    let handler: MessageHandler =
        Box::new(move |_msg: NetworkMessage| Box::pin(async move { Ok(None) }));
    let one_way: OneWayMessageHandler =
        Box::new(move |_msg: NetworkMessage| Box::pin(async move { Ok(()) }));

    let keystore = Arc::new(NoCrypto);
    let label_resolver = default_label_resolver();

    // Build NodeInfo with node_id as bytes
    let local_info: NodeInfo = build_node_info(&node_id, &bind_addr);

    let opts = QuicTransportOptions::new()
        .with_certificates(chain)
        .with_private_key(key)
        .with_get_local_node_info(Arc::new(move || {
            let local_info = local_info.clone();
            Box::pin(async move { Ok(local_info) })
        }))
        .with_bind_addr(bind_addr)
        .with_message_handler(handler)
        .with_one_way_message_handler(one_way)
        .with_logger(logger.clone())
        .with_keystore(keystore)
        .with_label_resolver(label_resolver)
        .with_response_cache_ttl(Duration::from_secs(2));

    let transport = Arc::new(QuicTransport::new(opts).map_err(|e| anyhow!("{e}"))?);
    transport.clone().start().await?;

    // Connect to peer using its node_id DNS-safe via SNI. For interop, we derive peer node id from SNI host expectation
    // Here we synthesize PeerInfo with peer address and a dummy public key bytes representing peer id string.
    let _peer_node_id = args.peer.as_ref().unwrap().to_string();
    // In real flow, peer id is compact_id(pubkey). For interop, use provided --node-id if present for peer via env? For now, use "swift-server".
    let remote_id = "swift-server".to_string();
    let peer_info = PeerInfo {
        public_key: remote_id.as_bytes().to_vec(),
        addresses: vec![peer_addr.to_string()],
    };

    transport.clone().connect_peer(peer_info).await?;

    // Build and send request
    let topic = topic_echo();
    let payload_bytes = b"hello from rust".to_vec();
    let ctx = MessageContext {
        profile_public_key: vec![],
    };

    // We need the destination id as the peer compact id; we used remote_id above.
    let _ = make_echo_request(&node_id, &remote_id, &payload_bytes);
    // Use high-level request API by embedding payload into ArcValue and relying on transport serialization
    let av = ArcValue::new_json(serde_json::json!({ "msg": "hello" }));
    let _ = transport
        .request(&topic, Some(av), &remote_id, ctx)
        .await
        .map_err(|e| anyhow!("request failed: {e}"))?;

    // Also send a one-way event
    transport
        .publish(&topic, None, &remote_id)
        .await
        .map_err(|e| anyhow!("publish failed: {e}"))?;

    log_info!(logger, "client completed request/response and event");
    Ok(())
}
