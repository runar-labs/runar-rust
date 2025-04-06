use crate::config::NodeConfig;
use crate::db::{Database, SqliteDatabase};
use anyhow::Result;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, StatusCode,
};
use log::{error, info, warn};
use serde_urlencoded;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

#[derive(Clone)]
pub enum WebServerMode {
    SetupUI,
    NodeUI,
}

pub async fn start_web_server(
    db: Arc<SqliteDatabase>,
    setup_tx: Option<oneshot::Sender<()>>,
    config_dir: PathBuf,
    mode: WebServerMode,
) -> Result<()> {
    info!("Starting web server...");

    // Ensure config_dir is absolute
    let config_dir = if config_dir.is_absolute() {
        config_dir
    } else {
        std::env::current_dir()?.join(config_dir)
    };

    info!("Using config directory: {}", config_dir.display());

    // Determine the UI directories we need
    let node_path = std::env::current_dir().unwrap_or_else(|_| config_dir.clone());
    let web_ui_dir = match mode {
        WebServerMode::SetupUI => node_path.join("setup_ui"),
        WebServerMode::NodeUI => node_path.join("node_ui"),
    };

    info!("Web UI directory: {}", web_ui_dir.display());

    // Make sure the UI directory exists
    if !web_ui_dir.exists() {
        error!("UI directory does not exist: {}", web_ui_dir.display());
        return Err(anyhow::anyhow!(
            "UI directory does not exist: {}",
            web_ui_dir.display()
        ));
    }

    if !web_ui_dir.is_dir() {
        error!("UI path is not a directory: {}", web_ui_dir.display());
        return Err(anyhow::anyhow!(
            "UI path is not a directory: {}",
            web_ui_dir.display()
        ));
    }

    // Check for index.html
    let index_path = web_ui_dir.join("index.html");
    if !index_path.exists() {
        error!(
            "index.html not found in UI directory: {}",
            web_ui_dir.display()
        );
        return Err(anyhow::anyhow!(
            "index.html not found in UI directory: {}",
            web_ui_dir.display()
        ));
    }

    // Shared state
    let db = db.clone();
    let setup_tx_shared = Arc::new(Mutex::new(setup_tx));
    let setup_tx_shared_for_server = Arc::clone(&setup_tx_shared);

    // Define the request handler
    let make_svc = make_service_fn(move |_conn| {
        let db = db.clone();
        let setup_tx_shared = Arc::clone(&setup_tx_shared);
        let config_dir = config_dir.clone();
        let mode = mode.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let db = db.clone();
                let setup_tx_shared = Arc::clone(&setup_tx_shared);
                let config_dir = config_dir.clone();
                let mode = mode.clone();
                async move { handle_request(req, db, setup_tx_shared, config_dir, mode).await }
            }))
        }
    });

    // Try different ports if the default one is not available
    let ports = [3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009];
    let mut server_future = None;
    let mut bound_port = 0;

    // Try to bind to each port
    for port in ports {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        info!("Attempting to bind web server to address: {}", addr);

        // Try to create a TCP listener explicitly to check if port is available
        let tcp_result = std::net::TcpListener::bind(addr);
        match tcp_result {
            Ok(listener) => {
                info!("Successfully bound TCP listener to {}", addr);
                // Close the listener so hyper can use it
                drop(listener);

                // Now try to bind with hyper
                match hyper::Server::try_bind(&addr) {
                    Ok(server_builder) => {
                        info!("Successfully bound hyper server to {}", addr);
                        server_future = Some(server_builder.serve(make_svc));
                        bound_port = port;
                        break;
                    }
                    Err(e) => {
                        error!("Failed to bind hyper server to {}: {}", addr, e);
                        continue;
                    }
                }
            }
            Err(e) => {
                error!("Failed to bind TCP listener to {}: {}", addr, e);
                continue;
            }
        }
    }

    if let Some(server) = server_future {
        // Run the server in a separate task
        info!("Starting web server on port {}", bound_port);
        tokio::spawn(async move {
            info!("Web server task started on port {}", bound_port);
            match server.await {
                Ok(_) => info!("Web server completed normally"),
                Err(e) => error!("Web server error: {}", e),
            }
        });

        // Give the server a moment to start
        info!("Waiting for server to start...");
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Try to connect to the server to verify it's running
        info!("Verifying server is running on port {}", bound_port);
        let client = hyper::Client::new();
        let uri = format!("http://127.0.0.1:{}", bound_port).parse::<hyper::Uri>()?;

        match client.get(uri).await {
            Ok(_) => info!("Successfully connected to server on port {}", bound_port),
            Err(e) => warn!("Could not connect to server for verification: {}", e),
        }

        // Log the port information
        info!("Web server running on port {}", bound_port);

        // Check if we have a setup channel
        let has_setup_tx = {
            let guard = setup_tx_shared_for_server.lock().await;
            guard.is_some()
        };

        if has_setup_tx {
            info!("Setup channel is available for later use");
        } else {
            warn!("No setup channel available");
        }

        Ok(())
    } else {
        error!("Failed to bind web server to any port");
        Err(anyhow::anyhow!("Failed to bind web server to any port"))
    }
}

async fn handle_request(
    req: Request<Body>,
    db: Arc<SqliteDatabase>,
    setup_tx_shared: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    config_dir: PathBuf,
    mode: WebServerMode,
) -> Result<Response<Body>, Infallible> {
    info!("Received request: {} {}", req.method(), req.uri().path());

    match mode {
        WebServerMode::SetupUI => {
            match (req.method(), req.uri().path()) {
                (&hyper::Method::POST, "/setup_node") => {
                    info!("Handling setup_node POST request");
                    match setup_api(req, db, setup_tx_shared).await {
                        Ok(response) => {
                            info!("Setup API request successful");
                            Ok(response)
                        }
                        Err(e) => {
                            error!("Setup API error: {}", e);
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(format!("Error: {}", e)))
                                .unwrap_or_else(|_| {
                                    Response::new(Body::from("Internal Server Error"))
                                }))
                        }
                    }
                }
                (&hyper::Method::GET, "/") => {
                    info!("Serving setup UI index.html");
                    // Serve the index.html file
                    let node_path = std::env::current_dir().unwrap_or_else(|_| config_dir.clone());
                    let web_ui_dir = node_path.join("setup_ui");
                    match std::fs::read_to_string(web_ui_dir.join("index.html")) {
                        Ok(content) => {
                            info!("Successfully read index.html");
                            Ok(Response::new(Body::from(content)))
                        }
                        Err(e) => {
                            error!("Failed to read index.html: {}", e);
                            Ok(Response::new(Body::from(format!(
                                "Index file not found: {}",
                                e
                            ))))
                        }
                    }
                }
                (&hyper::Method::GET, path)
                    if path.starts_with("/css/")
                        || path.starts_with("/js/")
                        || path.starts_with("/assets/") =>
                {
                    info!("Serving static file: {}", path);
                    // Serve static files from subdirectories
                    let node_path = std::env::current_dir().unwrap_or_else(|_| config_dir.clone());
                    let web_ui_dir = node_path.join("setup_ui");
                    let file_path = web_ui_dir.join(&path[1..]); // Remove leading slash

                    match std::fs::read(&file_path) {
                        Ok(content) => {
                            info!("Successfully read static file: {}", file_path.display());

                            // Determine content type based on file extension
                            let content_type = if path.ends_with(".css") {
                                "text/css"
                            } else if path.ends_with(".js") {
                                "application/javascript"
                            } else if path.ends_with(".svg") {
                                "image/svg+xml"
                            } else if path.ends_with(".png") {
                                "image/png"
                            } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
                                "image/jpeg"
                            } else {
                                "application/octet-stream"
                            };

                            Ok(Response::builder()
                                .header("Content-Type", content_type)
                                .body(Body::from(content.clone()))
                                .unwrap_or_else(|_| Response::new(Body::from(content))))
                        }
                        Err(e) => {
                            error!("Failed to read static file {}: {}", file_path.display(), e);
                            Ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from(format!("File not found: {}", path)))
                                .unwrap_or_else(|_| Response::new(Body::from("File not found"))))
                        }
                    }
                }
                _ => {
                    info!("Not found: {} {}", req.method(), req.uri().path());
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::from("Not Found"))
                        .unwrap())
                }
            }
        }
        WebServerMode::NodeUI => node_api(req, db, config_dir).await,
    }
}

async fn setup_api(
    req: Request<Body>,
    db: Arc<SqliteDatabase>,
    setup_tx_shared: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) -> Result<Response<Body>> {
    info!("Received setup request");

    // Parse the request body
    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    let body_str = String::from_utf8(body_bytes.to_vec())?;
    info!("Request body: {}", body_str);

    let params: HashMap<String, String> = match serde_urlencoded::from_str(&body_str) {
        Ok(params) => {
            info!("Parsed parameters: {:?}", params);
            params
        }
        Err(e) => {
            error!("Failed to parse request body: {}", e);
            return Err(anyhow::anyhow!("Failed to parse request body: {}", e));
        }
    };

    let node_name = match params.get("node_name") {
        Some(name) => {
            info!("Node name parameter: {}", name);
            name
        }
        None => {
            error!("Missing node_name parameter in request");
            return Err(anyhow::anyhow!("Missing node_name parameter"));
        }
    };

    info!("Setting up node with name: {}", node_name);

    // Generate a keypair for the node
    let keypair = match NodeConfig::generate_keypair() {
        Ok(kp) => kp,
        Err(e) => {
            error!("Failed to generate keypair: {}", e);
            return Err(anyhow::anyhow!("Failed to generate keypair: {}", e));
        }
    };

    // Create the node config
    let node_config = NodeConfig {
        node_name: node_name.clone(),
        private_key: keypair,
        config_dir: PathBuf::from("."), // This will be set by the database when loading
        web_ui_port: 8383,
    };

    // Save the node config to the database
    info!("Saving node config to database");
    match db.save_node_config(&node_config).await {
        Ok(_) => info!("Node config saved to database successfully"),
        Err(e) => {
            error!("Failed to save node config to database: {:?}", e);
            return Err(anyhow::anyhow!("Failed to save node config: {}", e));
        }
    }

    // Signal that setup is complete - use a separate block to ensure mutex is released
    info!("Attempting to send setup complete signal");
    {
        let mut setup_tx_guard = setup_tx_shared.lock().await;
        if let Some(tx) = setup_tx_guard.take() {
            info!("Sending setup complete signal");

            // Create a clone of the channel for debugging
            match tx.send(()) {
                Ok(_) => {
                    info!("Setup complete signal sent successfully");
                }
                Err(_) => {
                    error!("Failed to send setup complete signal - receiver dropped");
                    // Even if we fail to send the signal, we'll continue since the config is saved
                }
            }
        } else {
            warn!("No setup channel available to signal completion");
        }
    }

    // Return a success response
    info!("Returning success response");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"status":"success"}"#))?)
}

async fn node_api(
    req: Request<Body>,
    db: Arc<SqliteDatabase>,
    config_dir: PathBuf,
) -> Result<Response<Body>, Infallible> {
    info!(
        "Received node UI request: {} {}",
        req.method(),
        req.uri().path()
    );

    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/") => {
            info!("Serving node UI index.html");
            // Serve the index.html file
            let node_path = std::env::current_dir().unwrap_or_else(|_| config_dir.clone());
            let web_ui_dir = node_path.join("node_ui");
            match std::fs::read_to_string(web_ui_dir.join("index.html")) {
                Ok(content) => {
                    info!("Successfully read index.html");
                    Ok(Response::new(Body::from(content)))
                }
                Err(e) => {
                    error!("Failed to read index.html: {}", e);
                    Ok(Response::new(Body::from(format!(
                        "Index file not found: {}",
                        e
                    ))))
                }
            }
        }
        (&hyper::Method::GET, path) if path.starts_with("/assets/") => {
            info!("Serving static file: {}", path);
            // Serve static files from subdirectories
            let node_path = std::env::current_dir().unwrap_or_else(|_| config_dir.clone());
            let web_ui_dir = node_path.join("node_ui");
            let file_path = web_ui_dir.join(&path[1..]); // Remove leading slash

            match std::fs::read(&file_path) {
                Ok(content) => {
                    info!("Successfully read static file: {}", file_path.display());

                    // Determine content type based on file extension
                    let content_type = if path.ends_with(".css") {
                        "text/css"
                    } else if path.ends_with(".js") {
                        "application/javascript"
                    } else if path.ends_with(".svg") {
                        "image/svg+xml"
                    } else if path.ends_with(".png") {
                        "image/png"
                    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
                        "image/jpeg"
                    } else {
                        "application/octet-stream"
                    };

                    Ok(Response::builder()
                        .header("Content-Type", content_type)
                        .body(Body::from(content.clone()))
                        .unwrap_or_else(|_| Response::new(Body::from(content))))
                }
                Err(e) => {
                    error!("Failed to read static file {}: {}", file_path.display(), e);
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::from(format!("File not found: {}", path)))
                        .unwrap_or_else(|_| Response::new(Body::from("File not found"))))
                }
            }
        }
        (&hyper::Method::GET, "/node_details") => {
            info!("Handling node_details API request");
            Ok(Response::new(Body::from("Node details logic executed")))
        }
        (&hyper::Method::POST, "/update_node") => {
            info!("Handling update_node API request");
            Ok(Response::new(Body::from("Update node logic executed")))
        }
        _ => {
            info!("Not found: {} {}", req.method(), req.uri().path());
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap())
        }
    }
}

pub async fn download_web_ui(web_ui_dir: &PathBuf) -> Result<()> {
    info!("Checking web UI at: {}", web_ui_dir.display());

    // Ensure web_ui_dir is absolute
    let web_ui_dir = if web_ui_dir.is_absolute() {
        web_ui_dir.clone()
    } else {
        std::env::current_dir()?.join(web_ui_dir)
    };

    info!("Absolute path for web UI: {}", web_ui_dir.display());

    // Create the directory if it doesn't exist
    if !web_ui_dir.exists() {
        info!("Creating web UI directory: {}", web_ui_dir.display());
        match fs::create_dir_all(&web_ui_dir) {
            Ok(_) => info!("Successfully created web UI directory"),
            Err(e) => {
                error!("Failed to create web UI directory: {}", e);
                return Err(anyhow::anyhow!("Failed to create web UI directory: {}", e));
            }
        }
    } else if !web_ui_dir.is_dir() {
        error!(
            "Web UI path exists but is not a directory: {}",
            web_ui_dir.display()
        );
        return Err(anyhow::anyhow!("Web UI path exists but is not a directory"));
    } else {
        info!("Web UI directory already exists");
    }

    // Check if index.html already exists
    let index_path = web_ui_dir.join("index.html");
    if index_path.exists() {
        info!("index.html already exists at: {}", index_path.display());
        return Ok(());
    }

    // Create a simple fallback index.html file for setup UI if it doesn't exist
    info!("Creating fallback index.html at: {}", index_path.display());

    let index_html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Runar Node Setup</title>
    <!-- This is a fallback UI. For the full UI, build the Svelte project -->
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 12px 20px;
            font-size: 16px;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #45a049;
        }
        button:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .success-message {
            color: #4CAF50;
            font-weight: bold;
            margin-top: 15px;
            display: none;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Runar Node Setup</h1>
        <form id="setupForm">
            <div class="form-group">
                <label for="node_name">Node Name:</label>
                <input type="text" id="node_name" name="node_name" required>
            </div>
            <button type="submit" id="setupButton">Complete Setup</button>
            <div class="success-message" id="successMessage">Setup completed successfully! The page will reload in a moment...</div>
        </form>
    </div>
    <script>
        document.getElementById('setupForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const setupButton = document.getElementById('setupButton');
            const successMessage = document.getElementById('successMessage');
            const nodeName = document.getElementById('node_name').value;
            
            setupButton.disabled = true;
            setupButton.textContent = 'Setting up...';
            
            fetch('/setup_node', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'node_name=' + encodeURIComponent(nodeName)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    successMessage.style.display = 'block';
                    setTimeout(function() {
                        window.location.reload();
                    }, 3000);
                } else {
                    alert('Error: ' + data.message);
                    setupButton.disabled = false;
                    setupButton.textContent = 'Complete Setup';
                }
            })
            .catch(error => {
                alert('Error: ' + error);
                setupButton.disabled = false;
                setupButton.textContent = 'Complete Setup';
            });
        });
    </script>
</body>
</html>"#;

    match fs::write(&index_path, index_html) {
        Ok(_) => info!("Successfully wrote fallback index.html"),
        Err(e) => {
            error!("Failed to write index.html: {}", e);
            return Err(anyhow::anyhow!("Failed to write index.html: {}", e));
        }
    }

    info!("Created fallback UI at: {}", web_ui_dir.display());
    Ok(())
} 