new crate runar-cli

The first feature of the CLI is the initialization of the node

runar -init or just runar (and the cli detects there is no config so goes into init mode)


If the user does runar -init and previos config exists.. need to confirm with the user.. if the exisint config will be discarded and replaced.

config is in the same folder as the runar binary in the .runar folder


when entering ini the node will create a new Node Key store -> let mut nodeKeys = NodeKeyManager::new(node_logger)?;

when doing this it will generate its own TLS and Storage keypairs
and generate a setup handshake token which contains the CSR request and the node public key


Then we need to generate a QR code and display in the console for the user to scan with a mobile app

let csr_setup_token = nodeKeys.generate_csr().expect("Failed to generate setup token");

//This setup token only ha the keus part.. we need to embede this i to a tnoehr obje that conttain this + the IP and post of the node cli setup mode.. so the mobile know where to send a messag back.

let full_setup_token ...

let setup_token_bytes =
    bincode::serialize(&full_setup_token).expect("Failed to serialize setup token");

// The encrypted token is then encoded (e.g., into a QR code).
let setup_token_str = hex::encode(setup_token_bytes);

//Generate and displayy the QR Code in the console. if not possible we will need to launch a web server and diplay in the user browser.

the cli will then start a TCP socket in the IP and port specified in the setup token and wait until the mobile 
send a message there. 

when the message arrives it will  continue the setup 


// Node side - receives the encrypted certificate message, decrypts, and installs it.
let decrypted_cert_msg_bytes = node
    .decrypt_message_from_mobile(&encrypted_cert_msg)
    .expect("Failed to decrypt certificate message from mobile");

let deserialized_cert_msg: NodeCertificateMessage =
    bincode::deserialize(&decrypted_cert_msg_bytes)
        .expect("Failed to deserialize certificate message");

// 4 - (node side) - received the certificate message, validates it, and stores it
nodeKeys.install_certificate(deserialized_cert_msg)
    .expect("Failed to install certificate");


at this stage the node has the initial basic setup.. its own keus,, its own certs validate and signed by the user mobile app.. and can connect over QUIC..

so we need to save the credentials to the OS key store

let node_state = nodeKeys.export_state();
  
let serialized_node_state =
        bincode::serialize(&node_state).expect("Failed to serialize node state");


//geneate the keys_name -> -runnar_{unique UUID}  to be used to store the keys in the OS key store and save the keys_name in a config file in the .runar folder   


It will then compelte the the current  CLI init flow and involke the cli start flow


The cli start flow ill load the confid from .runar  folder and createa a new Node() instance with this config.. and use keys_name to load the serialize Keyhe key store.. so the node can then load them from key store and hydrate the NodeKeyManager with the secretrd from the OS key store. 
let node_hydrated = NodeKeyManager::from_state(deserialized_node_state, node_logger_2)?;
