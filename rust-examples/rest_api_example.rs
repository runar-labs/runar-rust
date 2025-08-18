use runar_macros::{action, service, service_impl};
use runar_node::{
    anyhow::{self, Result},
    async_trait::async_trait,
    Node,
};
use runar_gateway::GatwayService;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use runar_common::logging::{Component, Logger};
use runar_node::services::RequestContext;

// Define a simple invoice service
#[service(name = "invoice_service", path="invoice_service")]
pub struct InvoiceService {
    invoices: Arc<RwLock<HashMap<Uuid, Invoice>>>,
}

#[service_impl]
impl InvoiceService {
    pub fn new() -> Self {
        Self {
            invoices: Arc::new(RwLock::new(HashMap::new())),
        }
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
        
        invoices
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("Invoice not found"))?;
        
        Ok(())
    }
}

// Define a customer service
#[service(name = "customer_service", path="customer_service")]
pub struct CustomerService {
    customers: Arc<RwLock<HashMap<String, Customer>>>,
}

#[service_impl]
impl CustomerService {
    pub fn new() -> Self {
        Self {
            customers: Arc::new(RwLock::new(HashMap::new())),
        }
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
        let customer = Customer {
            id: Uuid::new_v4().to_string(),
            name: req.name,
            email: req.email,
        };
        
        let mut customers = self.customers.write().await;
        customers.insert(customer.id.clone(), customer.clone());
        
        Ok(customer)
    }
}

// Define an API gateway service
#[service(name = "api_gateway", path="api")]
pub struct ApiGateway;

#[service_impl]
impl ApiGateway {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ApiGateway {
    // Invoice endpoints
    #[action]
    async fn get_invoices(&self) -> Result<Vec<Invoice>> {
        // This would typically make a request to the invoice service
        Ok(vec![])
    }
    
    #[action]
    async fn get_invoice(&self, id: Uuid) -> Result<Invoice> {
        // This would typically make a request to the invoice service
        Ok(Invoice {
            id,
            customer_id: "customer123".to_string(),
            amount: 100.0,
            paid: false,
            due_date: "2024-12-31".to_string(),
        })
    }
    
    #[action]
    async fn create_invoice(&self, req: CreateInvoiceRequest) -> Result<Invoice> {
        // This would typically make a request to the invoice service
        Ok(Invoice {
            id: Uuid::new_v4(),
            customer_id: req.customer_id,
            amount: req.amount,
            paid: false,
            due_date: req.due_date,
        })
    }
    
    #[action]
    async fn update_invoice(&self, id: Uuid, req: UpdateInvoiceRequest) -> Result<Invoice> {
        // This would typically make a request to the invoice service
        Ok(Invoice {
            id,
            customer_id: "customer123".to_string(),
            amount: req.amount.unwrap_or(100.0),
            paid: req.paid.unwrap_or(false),
            due_date: req.due_date.unwrap_or_else(|| "2024-12-31".to_string()),
        })
    }
    
    #[action]
    async fn delete_invoice(&self, id: Uuid) -> Result<()> {
        // This would typically make a request to the invoice service
        Ok(())
    }
}

#[async_trait]
impl ApiGateway {
    // Customer endpoints
    #[action]
    async fn get_customers(&self) -> Result<Vec<Customer>> {
        // This would typically make a request to the customer service
        Ok(vec![])
    }
    
    #[action]
    async fn get_customer(&self, id: String) -> Result<Customer> {
        // This would typically make a request to the customer service
        Ok(Customer {
            id,
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
        })
    }
    
    #[action]
    async fn create_customer(&self, req: CreateCustomerRequest) -> Result<Customer> {
        // This would typically make a request to the customer service
        Ok(Customer {
            id: Uuid::new_v4().to_string(),
            name: req.name,
            email: req.email,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    let logger = Arc::new(Logger::new_root(Component::System, "rest-api-example"));
    
    logger.info("🚀 Starting REST API Example");
    
    // Create a node
    let  node = runar_node::Node::new(runar_node::NodeConfig::default()).await?;
    
    // Create and register services
    let invoice_service = InvoiceService::new();
    let customer_service = CustomerService::new();
    let api_gateway = ApiGateway::new();
    
    node.add_service(invoice_service).await?;
    node.add_service(customer_service).await?;
    node.add_service(api_gateway).await?;
    
    // Create and register the HTTP gateway
    let http_gateway = GatwayService::new("REST API Gateway", "gateway");
    node.add_service(http_gateway).await?;
    
    // Start the node
    node.start().await?;
    
    logger.info("✅ REST API example started successfully!");
    logger.info("🌐 HTTP gateway should be available at http://localhost:3000");
    logger.info("📡 Services registered:");
    logger.info("   - invoice_service");
    logger.info("   - customer_service");
    logger.info("   - api_gateway");
    logger.info("   - REST API gateway");
    logger.info("📋 Available endpoints:");
    logger.info("   - GET /invoice_service/get_invoices");
    logger.info("   - GET /invoice_service/get_invoice/{id}");
    logger.info("   - POST /invoice_service/create_invoice");
    logger.info("   - PUT /invoice_service/update_invoice/{id}");
    logger.info("   - DELETE /invoice_service/delete_invoice/{id}");
    logger.info("   - GET /customer_service/get_customers");
    logger.info("   - GET /customer_service/get_customer/{id}");
    logger.info("   - POST /customer_service/create_customer");
    
    // Keep the node running
    tokio::signal::ctrl_c().await?;
    logger.info("🛑 Shutting down...");
    
    Ok(())
} 