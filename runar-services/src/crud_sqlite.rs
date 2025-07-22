use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use runar_node::services::{LifecycleContext, RequestContext, ServiceFuture};
use runar_node::AbstractService;
use runar_serializer::{ArcValue, ValueCategory};

use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::sqlite::{
    DataType, Params as SqlParams, Schema as SqliteSchemaDef, SqlQuery, Value as SqliteValue,
};
use prost::Message;
use runar_serializer_macros::Serializable;

/// Represents a request to insert a single document into a collection.
///
/// Intention: To provide a structured way to specify the collection and document for an insert operation.
/// The document is represented as a map of field names to ArcValue values.
#[derive(Debug, Serialize, Deserialize, Clone, Plain)] // Clone for potential re-use if request fails and retries
pub struct InsertOneRequest {
    pub collection: String,
    pub document: HashMap<String, ArcValue>,
}

/// Represents the response from an insert_one operation.
///
/// Intention: To confirm the ID of the inserted document.
#[derive(Debug, Serialize, Deserialize, Clone, Plain)]
pub struct InsertOneResponse {
    pub inserted_id: String, // The ID is a string (e.g., UUID)
}

/// Represents a request to find a single document in a collection.
///
/// Intention: To specify the collection and filter criteria for a find operation.
/// The filter is a map, typically `{"_id": ArcValue::Text("some-uuid")}`.
#[derive(Debug, Serialize, Deserialize, Clone, Plain)]
pub struct FindOneRequest {
    pub collection: String,
    pub filter: HashMap<String, ArcValue>,
}

/// Represents the response from a find_one operation.
///
/// Intention: To return the found document (as a map), if any.
#[derive(Debug, Serialize, Deserialize, Clone, Plain)]
pub struct FindOneResponse {
    pub document: Option<HashMap<String, ArcValue>>,
}

/// A service that provides a MongoDB-like CRUD API on top of an SqliteService.
///
/// Intention: To abstract SQL interactions for common document-oriented operations (insert, find).
/// Collections are mapped to SQLite tables. Each field in a document maps to a column in the table,
/// as defined by the provided schema. An '_id' column (TEXT PRIMARY KEY) is standard.
pub struct CrudSqliteService {
    name: String,
    path: String,
    version: String,
    network_id: Option<String>,
    description: String,
    store_path: String,           // Path to the backing SqliteService instance
    schema: Arc<SqliteSchemaDef>, // Schema defining tables and columns
}

impl CrudSqliteService {
    /// Creates a new `CrudSqliteService`.
    ///
    /// # Arguments
    /// * `name` - The unique name of this service instance.
    /// * `path` - The path under which this service will be registered (e.g., "crud_db").
    /// * `store_path` - The service path of the backing `SqliteService` (e.g., "internal_sqlite").
    /// * `schema` - The schema defining the structure of collections (tables) and their columns.
    /// * `logger` - Logger instance for this service.
    pub fn new(
        name: String,
        path: String,
        store_path: String,
        schema: SqliteSchemaDef, // Note: Taking ownership, then wrapping in Arc
    ) -> Self {
        Self {
            name,
            path,
            version: "0.0.1".to_string(),
            network_id: None,
            description: "CRUD Service".to_string(),
            store_path,
            schema: Arc::new(schema),
        }
    }

    // Helper to convert row values based on schema, e.g., SQLite INTEGER to Boolean
    fn schema_aware_convert_row_values(
        &self,
        collection_name: &str,
        row_map: Arc<HashMap<String, ArcValue>>,
        context: &RequestContext, // For logging
    ) -> Result<Arc<HashMap<String, ArcValue>>> {
        let table_schema = self
            .schema
            .tables
            .iter()
            .find(|t| t.name == collection_name)
            .ok_or_else(|| {
                anyhow!(
                    "Schema not found for collection '{}' during row value conversion",
                    collection_name
                )
            })?;

        let mut updates = row_map.as_ref().clone();
        for (field_name, arc_value) in updates.iter_mut() {
            if let Some(col_def) = table_schema.columns.iter().find(|c| c.name == *field_name) {
                if col_def.data_type == DataType::Boolean {
                    match arc_value.category {
                        ValueCategory::Primitive => {
                            if let Ok(int_val_ref) = arc_value.as_type_ref::<i64>() {
                                let bool_val = *int_val_ref != 0;
                                context.debug(format!(
                                    "Converting field '{}' (i64: {}) to bool: {} for collection '{}' based on schema",
                                    field_name, *int_val_ref, bool_val, collection_name
                                ));
                                *arc_value = ArcValue::new_primitive(bool_val);
                            } else if arc_value.as_type_ref::<bool>().is_ok() {
                                // Already a bool, do nothing
                            } else {
                                context.warn(format!(
                                    "Field '{field_name}' in collection '{collection_name}' is schema type Boolean, but ArcValue is Primitive but not i64 or bool: {arc_value:?}. Leaving as is.",
                                ));
                            }
                        }
                        ValueCategory::Null => {
                            // Null is acceptable for a boolean field (if not NOT NULL)
                        }
                        _ => {
                            context.warn(format!(
                                "Field '{field_name}' in collection '{collection_name}' is schema type Boolean, but ArcValue is not Primitive or Null: {arc_value:?}. Leaving as is.",
                            ));
                        }
                    }
                }
            }
        }
        Ok(Arc::new(updates))
    }

    fn sqlite_action_path(&self, action: &str) -> String {
        format!("{}/{}", self.store_path, action)
    }

    // Helper function to convert ArcValue to SqliteValue
    // This could potentially be moved to src/sqlite.rs if generally useful
    fn arc_value_to_sqlite_value(av: &mut ArcValue) -> Result<SqliteValue> {
        match av.category {
            ValueCategory::Null => Ok(SqliteValue::Null),
            ValueCategory::Primitive => {
                if let Ok(s_val_arc) = av.as_type_ref::<String>() {
                    Ok(SqliteValue::Text(s_val_arc.as_ref().clone()))
                } else if let Ok(i_val_arc) = av.as_type_ref::<i64>() {
                    Ok(SqliteValue::Integer(*i_val_arc))
                } else if let Ok(f_val_arc) = av.as_type_ref::<f64>() {
                    Ok(SqliteValue::Real(*f_val_arc))
                } else if let Ok(b_val_arc) = av.as_type_ref::<bool>() {
                    Ok(SqliteValue::Integer(if *b_val_arc { 1 } else { 0 })) // SQLite uses 0 and 1 for booleans
                } else {
                    Err(anyhow!(
                        "Unsupported primitive type '{}' within ArcValue for SQLite conversion.",
                        av.value.as_ref().map_or_else(
                            || "[value was None, inconsistent for Primitive category]".to_string(),
                            |v| v.type_name().to_string()
                        )
                    ))
                }
            }
            ValueCategory::Bytes => {
                let bytes_vec_arc = av.as_type_ref::<Vec<u8>>()?;
                Ok(SqliteValue::Blob(bytes_vec_arc.as_ref().clone()))
            }
            _ => Err(anyhow!(
                "Unsupported ArcValue category {:?} for direct SQLite conversion",
                av.category
            )),
        }
    }

    async fn handle_insert_one(
        self: Arc<Self>,
        context: RequestContext,
        request_payload: Option<ArcValue>,
    ) -> Result<ArcValue> {
        context.debug(format!(
            "Handling insertOne request for CrudSqliteService '{}'",
            self.name
        ));

        let payload =
            request_payload.ok_or_else(|| anyhow!("Request payload is missing for insertOne"))?;
        let req: Arc<InsertOneRequest> = payload
            .as_type_ref::<InsertOneRequest>()
            .with_context(|| "Failed to deserialize InsertOneRequest from payload")?;

        context.info(format!(
            "Attempting to insert into collection: {}",
            req.collection
        ));

        let table_def = self
            .schema
            .tables
            .iter()
            .find(|t| t.name == req.collection)
            .ok_or_else(|| {
                let err_msg = format!("Collection '{}' not found in schema.", req.collection);
                context.error(&err_msg);
                anyhow!(err_msg)
            })?;

        let mut doc_to_insert = req.document.clone();
        let id_field_name = "_id".to_string();
        let inserted_id_av = match doc_to_insert.get(&id_field_name) {
            Some(id_val) => id_val.clone(), // Use provided _id
            None => {
                let new_id = Uuid::new_v4().to_string();
                let new_id_av = ArcValue::new_primitive(new_id);
                doc_to_insert.insert(id_field_name.clone(), new_id_av.clone());
                new_id_av
            }
        };
        // Ensure inserted_id is a string for the response
        let inserted_id_av = inserted_id_av.clone(); // Clone to make mutable for as_type
        let inserted_id = inserted_id_av
            .as_type_ref::<String>()
            .with_context(|| "Inserted _id must be a string")?;

        let mut column_names: Vec<String> = Vec::new();
        let mut value_params: Vec<SqliteValue> = Vec::new();

        for (field_name, arc_value) in &mut doc_to_insert {
            // Validate field against schema
            if !table_def.columns.iter().any(|c| &c.name == field_name) {
                let err_msg = format!(
                    "Field '{}' not defined in schema for collection '{}'.",
                    field_name, req.collection
                );
                context.error(&err_msg);
                return Err(anyhow!(err_msg));
            }
            // Type validation against schema column type
            let column_def = table_def
                .columns
                .iter()
                .find(|c| &c.name == field_name)
                .unwrap(); // Assume column exists
            let expected_db_type = &column_def.data_type;
            let provided_category = arc_value.category; // Access as a field

            let type_match = match (expected_db_type, provided_category) {
                (DataType::Integer, ValueCategory::Primitive) => arc_value
                    .value
                    .as_ref()
                    .is_some_and(|v| v.type_name() == "i64"),
                (DataType::Real, ValueCategory::Primitive) => arc_value
                    .value
                    .as_ref()
                    .is_some_and(|v| v.type_name() == "f64"),
                (DataType::Text, ValueCategory::Primitive) => {
                    arc_value.value.as_ref().is_some_and(|v| {
                        let tn = v.type_name();
                        tn == "String" || tn == "alloc::string::String"
                    })
                }
                (DataType::Boolean, ValueCategory::Primitive) => arc_value
                    .value
                    .as_ref()
                    .is_some_and(|v| v.type_name() == "bool"),
                (DataType::Blob, ValueCategory::Bytes) => arc_value.value.is_some(), // Ensure value exists for Bytes category
                (_, ValueCategory::Null) => arc_value.value.is_none(), // Ensure value is None for Null category
                _ => false, // All other combinations are mismatches or inconsistent states
            };

            if !type_match {
                let provided_type_name_for_error = arc_value.value.as_ref().map_or_else(
                    || format!("N/A (value is None, category: {provided_category:?})"),
                    |v| v.type_name().to_string(),
                );
                let error_message = format!(
                    "Type mismatch or inconsistent state for field '{field_name}': schema expects DB type {expected_db_type:?}. Received category {provided_category:?} with specific type '{provided_type_name_for_error}'.",
                );
                context.error(&error_message);
                return Err(anyhow!(error_message));
            }

            column_names.push(format!("\"{field_name}\"")); // Quote column names
            let sqlite_val = Self::arc_value_to_sqlite_value(arc_value).with_context(|| {
                format!("Failed to convert field '{field_name}' to SqliteValue")
            })?;
            value_params.push(sqlite_val);
        }

        if column_names.is_empty() {
            return Err(anyhow!("Cannot insert an empty document."));
        }

        let column_names_sql = column_names.join(", ");
        let placeholders_sql = (0..column_names.len())
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            req.collection, column_names_sql, placeholders_sql
        );

        context.debug(format!(
            "Executing INSERT SQL: {sql} with params: {value_params:?}",
        ));

        let sql_query = SqlQuery {
            statement: sql,
            params: SqlParams {
                values: value_params,
            },
        };

        let action_path = self.sqlite_action_path("execute_query");

        let rows_affected: Arc<i64> = context
            .request(action_path, Some(ArcValue::new_struct(sql_query)))
            .await
            .expect("Failed to execute INSERT statement")
            .as_type_ref()?;

        // Check response from execute_query (expecting number of rows affected)
        // rows_affected is now directly i64
        match rows_affected.as_ref() {
            1 => {
                context.info(format!(
                    "Successfully inserted document with id '{}' into collection '{}'.",
                    inserted_id, req.collection
                ));
                let response_struct = InsertOneResponse {
                    inserted_id: inserted_id.as_ref().clone(),
                };
                let final_response_av = ArcValue::new_struct(response_struct);
                Ok(final_response_av)
            }
            other_rows_affected => {
                let err_msg = format!(
                    "INSERT statement affected {} rows, expected 1, for id '{}' in collection '{}'.",
                    other_rows_affected, inserted_id, req.collection
                );
                context.error(&err_msg);
                Err(anyhow!(err_msg))
            }
        }
    }

    async fn handle_find_one(
        self: Arc<Self>,
        context: RequestContext,
        request_payload: Option<ArcValue>,
    ) -> Result<ArcValue> {
        context.debug(format!(
            "Handling findOne request for CrudSqliteService '{}'",
            self.name
        ));
        let payload =
            request_payload.ok_or_else(|| anyhow!("Request payload is missing for findOne"))?;
        let req: Arc<FindOneRequest> = payload
            .as_type_ref::<FindOneRequest>()
            .context("Failed to deserialize FindOneRequest from payload")?;

        context.info(format!(
            "Attempting to find_one in collection: '{}' with filter: {:?}",
            req.collection, req.filter
        ));

        let table_def = self
            .schema
            .tables
            .iter()
            .find(|t| t.name == req.collection)
            .ok_or_else(|| {
                let err_msg = format!("Collection '{}' not found in schema.", req.collection);
                context.error(&err_msg);
                anyhow!(err_msg)
            })?;

        if req.filter.is_empty() {
            context.warn(format!(
                "Filter is empty for findOne on collection '{}'. This will match the first document.",
                req.collection
            ));
            return Err(anyhow!("Filter cannot be empty for findOne operation."));
        }

        let mut where_clauses: Vec<String> = Vec::new();
        let mut value_params: Vec<SqliteValue> = Vec::new();

        for (field_name, arc_value) in req.filter.clone().iter_mut() {
            if !table_def.columns.iter().any(|c| &c.name == field_name) {
                let err_msg = format!(
                    "Filter field '{}' not defined in schema for collection '{}'.",
                    field_name, req.collection
                );
                context.error(&err_msg);
                return Err(anyhow!(err_msg));
            }
            where_clauses.push(format!("\"{field_name}\" = ?"));
            let sqlite_val = Self::arc_value_to_sqlite_value(arc_value).with_context(|| {
                format!("Failed to convert filter field '{field_name}' to SqliteValue",)
            })?;
            value_params.push(sqlite_val);
        }

        let where_sql = where_clauses.join(" AND ");
        let sql = format!(
            "SELECT * FROM \"{}\" WHERE {} LIMIT 1",
            req.collection, where_sql
        );

        context.debug(format!(
            "Constructed SQL for findOne on '{}': \"{}\" with params {:?}",
            req.collection, sql, &value_params
        ));

        let sql_query_struct = SqlQuery {
            statement: sql,
            params: SqlParams {
                values: value_params,
            },
        };

        let action_path = self.sqlite_action_path("execute_query");

        // Construct the payload for SqliteService's 'execute_query' action
        // The SqliteService expects an ArcValue wrapping an SqlQuery struct.
        let sql_for_logging = sql_query_struct.statement.clone(); // Clone for logging before move
        let request_payload_for_sqlite = ArcValue::new_struct(sql_query_struct);

        context.debug(format!(
            "Sending request to SqliteService at '{action_path}' with payload for SQL: {sql_for_logging}",
        ));

        // Make the actual request to SqliteService
        let rows: Arc<Vec<ArcValue>> = context
            .request(action_path.clone(), Some(request_payload_for_sqlite))
            .await
            .with_context(|| {
                format!(
                    "Failed to execute SELECT statement for collection '{}' (SQL: '{}') via SqliteService at '{}'",
                    req.collection, sql_for_logging, action_path
                )
            })?
            .as_type_ref::<Vec<ArcValue>>()?;

        if !rows.is_empty() {
            // Found a document, take the first one
            let document_arc_value_map = rows.first().unwrap(); // Get the first element
            context.info(format!(
                "Found document in collection '{}' with filter {:?}: {:?}",
                req.collection, req.filter, document_arc_value_map
            ));
            match document_arc_value_map.as_type_ref::<HashMap<String, ArcValue>>() {
                Ok(map_data) => {
                    match self.schema_aware_convert_row_values(&req.collection, map_data, &context)
                    {
                        Ok(converted_map_data) => {
                            let response_struct = FindOneResponse {
                                document: Some(converted_map_data.as_ref().clone()),
                            };
                            Ok(ArcValue::new_struct(response_struct))
                        }
                        Err(e) => {
                            context.error(format!(
                                "Failed schema-aware conversion for findOne on collection '{}': {}. Original map: {:?}",
                                req.collection, e, document_arc_value_map // Log the original map before conversion attempt
                            ));
                            Err(anyhow!("Failed schema-aware conversion for findOne: {}", e))
                        }
                    }
                }
                Err(e) => {
                    context.error(format!(
                "Failed to convert found document ArcValue to map for FindOneResponse: {e}. Doc AV: {document_arc_value_map:?}",
            ));
                    Err(anyhow!(
                        "Failed to convert document ArcValue to map for FindOneResponse: {}",
                        e
                    ))
                }
            }
        } else {
            // Query executed, but no document found (empty list)
            context.info(format!(
                "No document found in collection '{}' for filter {:?}. SQL: {}",
                req.collection, req.filter, sql_for_logging
            ));
            let response_struct = FindOneResponse { document: None };
            Ok(ArcValue::new_struct(response_struct))
        }
    }
}

#[async_trait]
impl AbstractService for CrudSqliteService {
    fn name(&self) -> &str {
        &self.name
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn network_id(&self) -> Option<String> {
        self.network_id.clone()
    }
    fn set_network_id(&mut self, network_id: String) {
        self.network_id = Some(network_id);
    }

    fn description(&self) -> &str {
        &self.description
    }

    async fn init(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!(
            "Initializing CrudSqliteService '{}', store_path: '{}'",
            self.name, self.store_path
        ));

        let service_arc = Arc::new(self.clone_arc_safe().await?);
        let service_arc_for_insert_capture = Arc::clone(&service_arc); // Clone original arc for this handler
        let insert_one_handler =
            Arc::new(move |payload: Option<ArcValue>, req_ctx: RequestContext| {
                // service_arc_for_insert_capture is moved into this closure
                let service_for_async = Arc::clone(&service_arc_for_insert_capture); // Clone for the async block
                Box::pin(async move { service_for_async.handle_insert_one(req_ctx, payload).await })
                    as ServiceFuture
            });
        context
            .register_action("insertOne", insert_one_handler)
            .await?;
        context.info(format!(
            "Action 'insertOne' registered for service '{}'",
            self.name
        ));

        let service_arc_for_find_one = Arc::clone(&service_arc); // Clone for the second handler
        let find_one_handler =
            Arc::new(move |payload: Option<ArcValue>, req_ctx: RequestContext| {
                // service_arc_for_find_one is moved into this closure
                let service_for_async = Arc::clone(&service_arc_for_find_one); // Clone for the async block
                Box::pin(async move { service_for_async.handle_find_one(req_ctx, payload).await })
                    as ServiceFuture
            });
        context.register_action("findOne", find_one_handler).await?;
        context.info(format!(
            "Action 'findOne' registered for service '{}'",
            self.name
        ));

        Ok(())
    }

    async fn start(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("CrudSqliteService '{}' started.", self.name));
        Ok(())
    }

    async fn stop(&self, context: LifecycleContext) -> Result<()> {
        context.info(format!("CrudSqliteService '{}' stopped.", self.name));
        Ok(())
    }
}

// For now, let's assume we might need a way to get an Arc<Self> if not directly available.
// Update: LifecycleContext and RequestContext usually provide ways to get service Arc if needed,
// or the macro used for service definition handles it. For manual impl, this might be needed.
// Let's rely on the context.register_action pattern which often handles Arc cloning.

// The `clone_arc_safe` method is a placeholder concept if `AbstractService`
// methods don't provide an `Arc<Self>` directly or if the registration macros
// don't handle it. In many frameworks, this is handled for you.
// For `runar_node`, `context.register_action` takes a closure that captures `Arc<Self>`,
// so direct `clone_arc_safe` on `self` in `initialize` might not be standard.
// Instead, we create `Arc::new(self.clone_arc_safe().await?)` where `clone_arc_safe` would be a method on `Self`.
// Let's assume `AbstractService` requires `Self: Clone` or provides a way to get `Arc<Self>`
// For now, `Arc::new(self.clone_arc_safe().await?)` is a bit of a circular dependency if `clone_arc_safe` needs `self`.
// The typical pattern is `let service_arc = Arc::new(Self { /* fields cloned from self */ });`
// if `Self` is `Clone`, or if `initialize` is called on an `Arc<Self>` to begin with.

// Given the structure of runar_node, AbstractService methods like initialize are called on `&self`.
// To use `Arc<Self>` in async closures for actions, we need to create an `Arc` of the service.
// This is often done by ensuring `Self` is `Clone` and then creating `Arc::new(self.clone())`.
// Or, if `Self` is not `Clone` due to non-Clone fields (like a Mutex), then more careful Arc construction is needed.
// Here, `CrudSqliteService` can be `Clone` if `config` and `logger` are `Arc` (which they are).

impl CrudSqliteService {
    // Helper to get an Arc<Self> for action registration, assuming Self is Clone.
    // This is a common pattern if the service itself needs to be Clone.
    // If AbstractService methods were on Arc<Self>, this wouldn't be needed.
    async fn clone_arc_safe(&self) -> Result<Self>
    where
        Self: Clone,
    {
        // This method implies Self must be Clone. Let's make CrudSqliteService Clone.
        Ok(self.clone())
    }
}

impl Clone for CrudSqliteService {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            path: self.path.clone(),
            version: self.version.clone(),
            network_id: self.network_id.clone(),
            description: self.description.clone(),
            store_path: self.store_path.clone(),
            schema: Arc::clone(&self.schema),
        }
    }
}
