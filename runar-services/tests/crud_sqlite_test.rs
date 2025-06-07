use anyhow::Result;
use runar_common::logging::{Component, Logger};
use runar_common::types::ArcValueType;
use runar_common::vmap; // Added for vmap!

use runar_node::Node;

use runar_node::{
    config::{LogLevel, LoggingConfig},
    NodeConfig,
};

use std::collections::HashMap;
use std::sync::Arc; // For downcasting

// Assuming crud_sqlite.rs and sqlite.rs are part of the same crate (rust_services)
use runar_services::crud_sqlite::{
    CrudSqliteService, FindOneRequest, FindOneResponse, InsertOneRequest, InsertOneResponse,
};
use runar_services::sqlite::{
    ColumnDefinition, DataType, Schema as SqliteSchema, SqliteConfig, SqliteService,
    TableDefinition,
};

const SQLITE_SERVICE_NAME: &str = "test_sqlite_for_crud";
const SQLITE_SERVICE_PATH: &str = "internal_db";
const CRUD_SERVICE_NAME: &str = "test_crud_service";
const CRUD_SERVICE_PATH: &str = "crud_db";

async fn setup_node_with_services() -> Result<Node> {
    let logging_config = LoggingConfig::new().with_default_level(LogLevel::Debug);
    let node_config =
        NodeConfig::new("crud-test-node", "test_network_crud").with_logging_config(logging_config);
    let mut node = Node::new(node_config).await?;

    let _logger_arc = Arc::new(Logger::new_root(
        Component::Custom("crud_sqlite_test"),
        "test_node_crud",
    ));

    // Define the schema
    let app_schema = Arc::new(SqliteSchema {
        tables: vec![
            TableDefinition {
                name: "users".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "name".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "email".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "age".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
            TableDefinition {
                name: "orders".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "product_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "quantity".to_string(),
                        data_type: DataType::Integer,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "total_price".to_string(),
                        data_type: DataType::Real,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
            TableDefinition {
                name: "products".to_string(),
                columns: vec![
                    ColumnDefinition {
                        name: "_id".to_string(),
                        data_type: DataType::Text,
                        primary_key: true,
                        autoincrement: false,
                        not_null: true,
                    },
                    ColumnDefinition {
                        name: "name".to_string(),
                        data_type: DataType::Text,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "price".to_string(),
                        data_type: DataType::Real,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                    ColumnDefinition {
                        name: "in_stock".to_string(),
                        data_type: DataType::Boolean,
                        primary_key: false,
                        autoincrement: false,
                        not_null: false,
                    },
                ],
            },
        ],
        indexes: vec![], // No indexes for now
    });

    // Setup SqliteService (in-memory)
    let sqlite_config = SqliteConfig {
        db_path: ":memory:".to_string(),
        schema: (*app_schema).clone(), // SqliteService takes ownership of the schema for table creation
    };
    let sqlite_service = SqliteService::new(
        SQLITE_SERVICE_NAME.to_string(),
        SQLITE_SERVICE_PATH.to_string(),
        sqlite_config,
    );
    node.add_service(sqlite_service).await?;

    // Setup CrudSqliteService
    let crud_service = CrudSqliteService::new(
        CRUD_SERVICE_NAME.to_string(),
        CRUD_SERVICE_PATH.to_string(),
        SQLITE_SERVICE_PATH.to_string(), // store_path should be the *path* of the sqlite service
        (*app_schema).clone(),           // schema (SqliteSchemaDef, cloned from Arc)
    );
    node.add_service(crud_service).await?;

    node.start().await?;
    Ok(node)
}

#[tokio::test]
async fn test_insert_one_and_find_one_basic() -> Result<()> {
    let node = setup_node_with_services()
        .await
        .expect("Failed to setup node with services");

    let collection_name = "users".to_string();

    // 1. Insert a document (ID will be auto-generated)
    let mut user_doc_arc_value_map = vmap! {
        "name" => "Alice".to_string(),
        "email" => "alice@example.com".to_string(),
        "age" => 30i64
    };
    // Convert ArcValueType::Map back to HashMap for InsertOneRequest
    let user_doc_auto_id_map: HashMap<String, ArcValueType> = user_doc_arc_value_map
        .as_type::<HashMap<String, ArcValueType>>()
        .expect("vmap! should produce a valid map");

    let insert_req_auto = InsertOneRequest {
        collection: collection_name.clone(),
        document: user_doc_auto_id_map.clone(),
    };
    let arc_insert_req_auto = ArcValueType::from_struct(insert_req_auto);

    let insert_resp_av: InsertOneResponse = node
        .request(
            &format!("{}/insertOne", CRUD_SERVICE_PATH),
            Some(arc_insert_req_auto),
        )
        .await?;

    let insert_response_auto = insert_resp_av; // Made mutable
    let generated_id = insert_response_auto.inserted_id.clone(); // inserted_id is already a String
    assert!(!generated_id.is_empty(), "Generated ID should not be empty");
    println!("Inserted document with auto-generated ID: {}", generated_id);

    // 2. Find the inserted document by its generated ID
    let mut filter_auto_id_map: HashMap<String, ArcValueType> = HashMap::new();
    filter_auto_id_map.insert(
        "_id".to_string(),
        ArcValueType::new_primitive(generated_id.clone()),
    );
    let find_req_auto = FindOneRequest {
        collection: collection_name.clone(),
        filter: filter_auto_id_map,
    };
    let arc_find_req_auto = ArcValueType::from_struct(find_req_auto);

    let find_resp_av: FindOneResponse = node
        .request(
            &format!("{}/findOne", CRUD_SERVICE_PATH),
            Some(arc_find_req_auto),
        )
        .await?;
    let find_response_auto = find_resp_av; // Made mutable

    let found_doc_auto = find_response_auto
        .document
        .expect("Document with auto_id should be found");
    let mut id_av = found_doc_auto.get("_id").unwrap().clone();
    let id_str_arc = id_av.as_type_ref::<String>()?;
    assert_eq!(*id_str_arc, generated_id);
    let mut name_av = found_doc_auto.get("name").unwrap().clone();
    let name_str_arc = name_av.as_type_ref::<String>()?;
    assert_eq!(*name_str_arc, "Alice");
    let mut email_av = found_doc_auto.get("email").unwrap().clone();
    let email_str_arc = email_av.as_type_ref::<String>()?;
    assert_eq!(*email_str_arc, "alice@example.com");
    let mut age_av = found_doc_auto.get("age").unwrap().clone();
    let age_val_arc = age_av.as_type_ref::<i64>()?;
    assert_eq!(*age_val_arc, 30i64);
    println!(
        "Successfully found document by auto-generated ID: {:?}",
        found_doc_auto
    );

    // 3. Insert a document with a predefined ID
    let predefined_id = "user-bob-001".to_string();
    let mut user_doc_pre_id_map: HashMap<String, ArcValueType> = HashMap::new();
    user_doc_pre_id_map.insert(
        "_id".to_string(),
        ArcValueType::new_primitive(predefined_id.clone()),
    );
    user_doc_pre_id_map.insert(
        "name".to_string(),
        ArcValueType::new_primitive("Bob".to_string()),
    );
    user_doc_pre_id_map.insert(
        "email".to_string(),
        ArcValueType::new_primitive("bob@example.com".to_string()),
    );
    // Note: "city" field removed as it's not in the 'users' schema

    let insert_req_pre = InsertOneRequest {
        collection: collection_name.clone(),
        document: user_doc_pre_id_map.clone(),
    };
    let arc_insert_req_pre = ArcValueType::from_struct(insert_req_pre);

    let insert_resp_pre_av: InsertOneResponse = node
        .request(
            &format!("{}/insertOne", CRUD_SERVICE_PATH),
            Some(arc_insert_req_pre),
        )
        .await?;
    let insert_response_pre = insert_resp_pre_av;
    assert_eq!(insert_response_pre.inserted_id, predefined_id);
    println!("Inserted document with predefined ID: {}", predefined_id);

    // 4. Find the document with the predefined ID
    let mut filter_pre_id_map: HashMap<String, ArcValueType> = HashMap::new();
    filter_pre_id_map.insert(
        "_id".to_string(),
        ArcValueType::new_primitive(predefined_id.clone()),
    );
    let find_req_pre = FindOneRequest {
        collection: collection_name.clone(),
        filter: filter_pre_id_map,
    };
    let arc_find_req_pre = ArcValueType::from_struct(find_req_pre);

    let find_resp_pre_av: FindOneResponse = node
        .request(
            &format!("{}/findOne", CRUD_SERVICE_PATH),
            Some(arc_find_req_pre),
        )
        .await?;

    let found_doc_pre = find_resp_pre_av
        .document
        .expect("Document with pre_id should be found");
    let mut id_av_pre = found_doc_pre.get("_id").unwrap().clone();
    let id_str_arc_pre = id_av_pre.as_type_ref::<String>()?;
    assert_eq!(*id_str_arc_pre, predefined_id);
    let mut name_av_pre = found_doc_pre.get("name").unwrap().clone();
    let name_str_arc_pre = name_av_pre.as_type_ref::<String>()?;
    assert_eq!(*name_str_arc_pre, "Bob");
    let mut email_av_pre = found_doc_pre.get("email").unwrap().clone();
    let email_str_arc_pre = email_av_pre.as_type_ref::<String>()?;
    assert_eq!(*email_str_arc_pre, "bob@example.com");
    println!(
        "Successfully found document by predefined ID: {:?}",
        found_doc_pre
    );

    // 5. Attempt to find a non-existent document
    let non_existent_id = "user-does-not-exist-404".to_string();
    let mut filter_non_existent_map: HashMap<String, ArcValueType> = HashMap::new();
    filter_non_existent_map.insert(
        "_id".to_string(),
        ArcValueType::new_primitive(non_existent_id.clone()),
    );
    let find_req_non_existent = FindOneRequest {
        collection: collection_name.clone(),
        filter: filter_non_existent_map,
    };
    let arc_find_req_non_existent = ArcValueType::from_struct(find_req_non_existent);

    let find_response_non_existent: FindOneResponse = node
        .request(
            &format!("{}/findOne", CRUD_SERVICE_PATH),
            Some(arc_find_req_non_existent),
        )
        .await?;

    assert!(
        find_response_non_existent.document.is_none(),
        "Document with non_existent_id should not be found"
    );
    println!(
        "Correctly found no document for non-existent ID: {}",
        non_existent_id
    );

    Ok(())
}

#[tokio::test]
async fn test_insert_into_different_collections() -> Result<()> {
    let node = setup_node_with_services()
        .await
        .expect("Failed to setup node with services");

    // Insert into 'orders' collection
    let mut order_doc_map: HashMap<String, ArcValueType> = HashMap::new();
    order_doc_map.insert(
        "product_id".to_string(),
        ArcValueType::new_primitive("prod_123".to_string()),
    );
    order_doc_map.insert("quantity".to_string(), ArcValueType::new_primitive(2i64));
    order_doc_map.insert(
        "total_price".to_string(),
        ArcValueType::new_primitive(50.99f64),
    );

    let insert_order_req = InsertOneRequest {
        collection: "orders".to_string(),
        document: order_doc_map.clone(),
    };
    let arc_insert_order_req = ArcValueType::from_struct(insert_order_req);
    let order_resp_av: InsertOneResponse = node
        .request(
            &format!("{}/insertOne", CRUD_SERVICE_PATH),
            Some(arc_insert_order_req),
        )
        .await?;
    let order_insert_resp = order_resp_av;
    let order_id = order_insert_resp.inserted_id.clone();
    println!("Inserted order with ID: {}", order_id);

    // Insert into 'products' collection
    let mut product_doc_map: HashMap<String, ArcValueType> = HashMap::new();
    product_doc_map.insert(
        "name".to_string(),
        ArcValueType::new_primitive("Super Widget".to_string()),
    );
    product_doc_map.insert("price".to_string(), ArcValueType::new_primitive(25.49f64));
    product_doc_map.insert("in_stock".to_string(), ArcValueType::new_primitive(true));

    let insert_product_req = InsertOneRequest {
        collection: "products".to_string(),
        document: product_doc_map.clone(),
    };
    let arc_insert_product_req = ArcValueType::from_struct(insert_product_req);
    let product_resp_av: InsertOneResponse = node
        .request(
            &format!("{}/insertOne", CRUD_SERVICE_PATH),
            Some(arc_insert_product_req),
        )
        .await?;
    let product_insert_resp = product_resp_av;

    let product_id = product_insert_resp.inserted_id.clone();
    println!("Inserted product with ID: {}", product_id);

    // Find the order
    let mut filter_order_map: HashMap<String, ArcValueType> = HashMap::new();
    filter_order_map.insert(
        "_id".to_string(),
        ArcValueType::new_primitive(order_id.clone()),
    );
    let find_order_req = FindOneRequest {
        collection: "orders".to_string(),
        filter: filter_order_map,
    };
    let arc_find_order_req = ArcValueType::from_struct(find_order_req);
    let find_order_resp_av: FindOneResponse = node
        .request(
            &format!("{}/findOne", CRUD_SERVICE_PATH),
            Some(arc_find_order_req),
        )
        .await?;
    let find_order_resp = find_order_resp_av;
    let found_order = find_order_resp.document.expect("Order should be found");
    let mut order_product_id_av = found_order.get("product_id").unwrap().clone();
    let order_product_id_arc = order_product_id_av.as_type_ref::<String>()?;
    assert_eq!(*order_product_id_arc, "prod_123");
    let mut order_quantity_av = found_order.get("quantity").unwrap().clone();
    let order_quantity_arc = order_quantity_av.as_type_ref::<i64>()?;
    assert_eq!(*order_quantity_arc, 2i64);
    let mut order_total_price_av = found_order.get("total_price").unwrap().clone();
    let order_total_price_arc = order_total_price_av.as_type_ref::<f64>()?;
    assert_eq!(*order_total_price_arc, 50.99f64);

    // Find the product
    let mut filter_product_map: HashMap<String, ArcValueType> = HashMap::new();
    filter_product_map.insert(
        "_id".to_string(),
        ArcValueType::new_primitive(product_id.clone()),
    );
    let find_product_req = FindOneRequest {
        collection: "products".to_string(),
        filter: filter_product_map,
    };
    let arc_find_product_req = ArcValueType::from_struct(find_product_req);
    let find_product_resp_av: FindOneResponse = node
        .request(
            &format!("{}/findOne", CRUD_SERVICE_PATH),
            Some(arc_find_product_req),
        )
        .await?;
    let find_product_resp = find_product_resp_av;
    let found_product = find_product_resp.document.expect("Product should be found");
    let mut product_name_av = found_product.get("name").unwrap().clone();
    let product_name_arc = product_name_av.as_type_ref::<String>()?;
    assert_eq!(*product_name_arc, "Super Widget");
    let mut product_price_av = found_product.get("price").unwrap().clone();
    let product_price_arc = product_price_av.as_type_ref::<f64>()?;
    assert_eq!(*product_price_arc, 25.49f64);
    let mut product_in_stock_av = found_product.get("in_stock").unwrap().clone();
    let product_in_stock_arc = product_in_stock_av.as_type_ref::<bool>()?;
    assert!(*product_in_stock_arc);

    Ok(())
}
