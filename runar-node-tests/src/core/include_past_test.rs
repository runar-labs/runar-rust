use anyhow::Result;
use runar_node::node::Node;
use runar_node::services::{EventRegistrationOptions, NodeDelegate, PublishOptions};
use runar_serializer::ArcValue;
use runar_test_utils::create_node_test_config;
use tokio::sync::oneshot;
use std::time::Duration;

#[tokio::test]
async fn include_past_exact_topic_delivers_latest_retained_event() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    // Publish an event before subscribing, with retention
    let topic = "svc_exact/event_x";
    let data = Some(ArcValue::new_primitive("payload_exact".to_string()));
    let opts = PublishOptions {
        broadcast: false,
        guaranteed_delivery: false,
        retain_for: Some(Duration::from_secs(2)),
        target: None,
    };
    node.publish_with_options(topic.to_string(), data.clone(), opts).await?;

    // Wait a bit to simulate past event
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Subscribe with include_past
    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe_with_options(
            topic.to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
            EventRegistrationOptions {
                include_past: Some(Duration::from_secs(1)),
            },
        )
        .await?;

    let received = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .map_err(|_| anyhow::anyhow!("Timeout receiving include_past event"))?
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    assert!(received.is_some(), "Expected retained event to be delivered");
    let s = received.unwrap().as_type_ref::<String>()?;
    assert_eq!(*s, "payload_exact");
    Ok(())
}

#[tokio::test]
async fn include_past_window_too_small_no_delivery() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    let topic = "svc_exact/event_old";
    let data = Some(ArcValue::new_primitive("old_payload".to_string()));
    node
        .publish_with_options(
            topic.to_string(),
            data,
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(2)),
                target: None,
            },
        )
        .await?;

    // Wait long enough that lookback below will exclude it
    tokio::time::sleep(Duration::from_millis(400)).await;

    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe_with_options(
            topic.to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
            EventRegistrationOptions {
                include_past: Some(Duration::from_millis(200)),
            },
        )
        .await?;

    // Expect timeout (no immediate delivery)
    let res = tokio::time::timeout(Duration::from_millis(300), rx).await;
    assert!(res.is_err(), "Should not receive past event when lookback too small");
    Ok(())
}

#[tokio::test]
async fn include_past_picks_newest_of_same_topic() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    let topic = "svc_exact/multi";
    let older = Some(ArcValue::new_primitive("older".to_string()));
    let newer = Some(ArcValue::new_primitive("newer".to_string()));

    node
        .publish_with_options(
            topic.to_string(),
            older,
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(2)),
                target: None,
            },
        )
        .await?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    node
        .publish_with_options(
            topic.to_string(),
            newer,
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(2)),
                target: None,
            },
        )
        .await?;

    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe_with_options(
            topic.to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
            EventRegistrationOptions {
                include_past: Some(Duration::from_secs(1)),
            },
        )
        .await?;

    let received = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .map_err(|_| anyhow::anyhow!("Timeout receiving include_past event"))?
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    let s = received.unwrap().as_type_ref::<String>()?;
    assert_eq!(*s, "newer", "Should deliver the newest retained event");
    Ok(())
}

#[tokio::test]
async fn include_past_no_retention_no_delivery() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    let topic = "svc_exact/no_retain";
    let data = Some(ArcValue::new_primitive("no_retain_payload".to_string()));
    // Publish without retention
    node.publish(topic.to_string(), data).await?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe_with_options(
            topic.to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
            EventRegistrationOptions {
                include_past: Some(Duration::from_secs(1)),
            },
        )
        .await?;

    let res = tokio::time::timeout(Duration::from_millis(300), rx).await;
    assert!(res.is_err(), "Should not deliver past event when not retained");
    Ok(())
}

#[tokio::test]
async fn include_past_wildcard_picks_newest_across_topics() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    let t1 = "svc_multi/a";
    let t2 = "svc_multi/b";
    node
        .publish_with_options(
            t1.to_string(),
            Some(ArcValue::new_primitive("older".to_string())),
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(2)),
                target: None,
            },
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    node
        .publish_with_options(
            t2.to_string(),
            Some(ArcValue::new_primitive("newer".to_string())),
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(2)),
                target: None,
            },
        )
        .await?;

    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe_with_options(
            "svc_multi/*".to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
            EventRegistrationOptions {
                include_past: Some(Duration::from_secs(1)),
            },
        )
        .await?;

    let received = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .map_err(|_| anyhow::anyhow!("Timeout receiving include_past wildcard event"))?
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    let s = received.unwrap().as_type_ref::<String>()?;
    assert_eq!(*s, "newer", "Wildcard include_past should pick newest across topics");
    Ok(())
}

#[tokio::test]
async fn subscribe_without_include_past_no_immediate_delivery() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    let topic = "svc_exact/no_past";
    let data = Some(ArcValue::new_primitive("x".to_string()));
    node
        .publish_with_options(
            topic.to_string(),
            data,
            PublishOptions {
                broadcast: false,
                guaranteed_delivery: false,
                retain_for: Some(Duration::from_secs(2)),
                target: None,
            },
        )
        .await?;

    tokio::time::sleep(Duration::from_millis(150)).await;

    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe(
            topic.to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
        )
        .await?;

    let res = tokio::time::timeout(Duration::from_millis(300), rx).await;
    assert!(res.is_err(), "Subscribe without include_past should not deliver immediately");
    Ok(())
}

#[tokio::test]
async fn include_past_wildcard_delivers_latest_retained_event() -> Result<()> {
    let cfg = create_node_test_config()?;
    let node = Node::new(cfg).await?;

    let exact_topic = "svc_wild/event_x";
    let pattern = "svc_wild/*";
    let data = Some(ArcValue::new_primitive("payload_wild".to_string()));
    let opts = PublishOptions {
        broadcast: false,
        guaranteed_delivery: false,
        retain_for: Some(Duration::from_secs(2)),
        target: None,
    };
    node.publish_with_options(exact_topic.to_string(), data.clone(), opts).await?;

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let (tx, rx) = oneshot::channel::<Option<ArcValue>>();
    let _sub_id = node
        .subscribe_with_options(
            pattern.to_string(),
            std::sync::Arc::new(move |_ctx, val| {
                let tx = tx;
                Box::pin(async move {
                    let _ = tx.send(val);
                    Ok(())
                })
            }),
            EventRegistrationOptions {
                include_past: Some(Duration::from_millis(1500)),
            },
        )
        .await?;

    let received = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .map_err(|_| anyhow::anyhow!("Timeout receiving include_past wildcard event"))?
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    assert!(received.is_some(), "Expected retained event via wildcard");
    let s = received.unwrap().as_type_ref::<String>()?;
    assert_eq!(*s, "payload_wild");
    Ok(())
}

