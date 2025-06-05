use runar_macros::{action, gateway, init, main, rest_api, service};
use runar_node::{
    anyhow::{self, Result},
    async_trait::async_trait,
    node::NodeConfig,
    Node,
};
use runar_gateway::GatewayConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// Define a simple invoice service
#[service(name = "invoice_service")]
pub struct InvoiceService {
    invoices: Arc<RwLock<HashMap<Uuid, Invoice>>>,
}

#[init]
impl InvoiceService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            invoices: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: Uuid,
    pub customer_id: String,
    pub amount: f64,
    pub paid: bool,
    pub due_date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInvoiceRequest {
    pub customer_id: String,
    pub amount: f64,
    pub due_date: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateInvoiceRequest {
    pub amount: Option<f64>,
    pub paid: Option<bool>,
    pub due_date: Option<String>,
}

#[async_trait]
impl InvoiceService {
    #[action]
    pub async fn get_invoices(&self) -> Result<Vec<Invoice>> {
        let invoices = self.invoices.read().await;
        Ok(invoices.values().cloned().collect())
    }
    
    #[action]
    pub async fn get_invoice(&self, id: Uuid) -> Result<Invoice> {
        let invoices = self.invoices.read().await;
        invoices
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Invoice not found"))
    }
    
    #[action]
    pub async fn create_invoice(&self, req: CreateInvoiceRequest) -> Result<Invoice> {
        let invoice = Invoice {
            id: Uuid::new_v4(),
            customer_id: req.customer_id,
            amount: req.amount,
            paid: false,
            due_date: req.due_date,
        };
        
        let mut invoices = self.invoices.write().await;
        invoices.insert(invoice.id, invoice.clone());
        
        Ok(invoice)
    }
    
    #[action]
    pub async fn update_invoice(&self, id: Uuid, req: UpdateInvoiceRequest) -> Result<Invoice> {
        let mut invoices = self.invoices.write().await;
        
        let invoice = invoices
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("Invoice not found"))?;
        
        if let Some(amount) = req.amount {
            invoice.amount = amount;
        }
        
        if let Some(paid) = req.paid {
            invoice.paid = paid;
        }
        
        if let Some(due_date) = req.due_date {
            invoice.due_date = due_date;
        }
        
        Ok(invoice.clone())
    }
    
    #[action]
    pub async fn delete_invoice(&self, id: Uuid) -> Result<()> {
        let mut invoices = self.invoices.write().await;
        
        if invoices.remove(&id).is_none() {
            return Err(anyhow::anyhow!("Invoice not found"));
        }
        
        Ok(())
    }
}

// Define a simple customer service
#[service(name = "customer_service")]
pub struct CustomerService {
    customers: Arc<RwLock<HashMap<String, Customer>>>,
}

#[init]
impl CustomerService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            customers: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCustomerRequest {
    pub name: String,
    pub email: String,
}

#[async_trait]
impl CustomerService {
    #[action]
    pub async fn get_customers(&self) -> Result<Vec<Customer>> {
        let customers = self.customers.read().await;
        Ok(customers.values().cloned().collect())
    }
    
    #[action]
    pub async fn get_customer(&self, id: String) -> Result<Customer> {
        let customers = self.customers.read().await;
        customers
            .get(&id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Customer not found"))
    }
    
    #[action]
    pub async fn create_customer(&self, req: CreateCustomerRequest) -> Result<Customer> {
        let id = format!("cust_{}", Uuid::new_v4().to_string().split('-').next().unwrap());
        
        let customer = Customer {
            id: id.clone(),
            name: req.name,
            email: req.email,
        };
        
        let mut customers = self.customers.write().await;
        customers.insert(id, customer.clone());
        
        Ok(customer)
    }
}

// Define the API gateway with REST API mappings
#[service]
#[gateway(
    host = "0.0.0.0",
    port = 8080,
    services = [InvoiceService, CustomerService]
)]
pub struct ApiGateway;

#[init]
impl ApiGateway {
    pub async fn new() -> Result<Self> {
        Ok(Self {})
    }
}

// Map invoice service operations to REST endpoints
#[rest_api(
    prefix = "/api/v1",
    service = "invoice_service"
)]
impl ApiGateway {
    #[action(GET, "/invoices")]
    async fn get_invoices(&self) -> Result<Vec<Invoice>> {
        // This maps to invoice_service.get_invoices()
        self.context.request("invoice_service", "get_invoices", {}).await
    }
    
    #[action(GET, "/invoices/:id")]
    async fn get_invoice(&self, id: Uuid) -> Result<Invoice> {
        // This maps to invoice_service.get_invoice(id)
        self.context.request("invoice_service", "get_invoice", { id }).await
    }
    
    #[action(POST, "/invoices")]
    async fn create_invoice(&self, req: CreateInvoiceRequest) -> Result<Invoice> {
        // This maps to invoice_service.create_invoice(req)
        self.context.request("invoice_service", "create_invoice", { req }).await
    }
    
    #[action(PUT, "/invoices/:id")]
    async fn update_invoice(&self, id: Uuid, req: UpdateInvoiceRequest) -> Result<Invoice> {
        // This maps to invoice_service.update_invoice(id, req)
        self.context.request("invoice_service", "update_invoice", { id, req }).await
    }
    
    #[action(DELETE, "/invoices/:id")]
    async fn delete_invoice(&self, id: Uuid) -> Result<()> {
        // This maps to invoice_service.delete_invoice(id)
        self.context.request("invoice_service", "delete_invoice", { id }).await
    }
}

// Map customer service operations to REST endpoints
#[rest_api(
    prefix = "/api/v1",
    service = "customer_service"
)]
impl ApiGateway {
    #[action(GET, "/customers")]
    async fn get_customers(&self) -> Result<Vec<Customer>> {
        // This maps to customer_service.get_customers()
        self.context.request("customer_service", "get_customers", {}).await
    }
    
    #[action(GET, "/customers/:id")]
    async fn get_customer(&self, id: String) -> Result<Customer> {
        // This maps to customer_service.get_customer(id)
        self.context.request("customer_service", "get_customer", { id }).await
    }
    
    #[action(POST, "/customers")]
    async fn create_customer(&self, req: CreateCustomerRequest) -> Result<Customer> {
        // This maps to customer_service.create_customer(req)
        self.context.request("customer_service", "create_customer", { req }).await
    }
}

// Main application entry point
#[main]
async fn main() -> Result<()> {
    // Create and initialize node
    let mut node = Node::new(NodeConfig {
        node_id: "api_node".to_string(),
        data_dir: "./data".to_string(),
        db_path: "./data/db".to_string(),
        p2p_config: None, // Configure if P2P is needed
    }).await?;
    
    // Initialize services
    let invoice_service = InvoiceService::new().await?;
    let customer_service = CustomerService::new().await?;
    let api_gateway = ApiGateway::new().await?;
    
    // Register services with the node using the proper add_service method
    node.add_service(invoice_service).await?;
    node.add_service(customer_service).await?;
    node.add_service(api_gateway).await?;
    
    // Start the node which will manage all services
    node.start().await?;
    
    // Wait for the node to complete (typically runs until interrupted)
    node.wait_for_shutdown().await?;
    
    Ok(())
} 