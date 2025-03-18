# Invoice App Specification

## Overview
The Invoice App enables users to create, manage, and track invoices, with client and product management and basic reporting. This specification details the functionality, screens, and components used in the application.

## Common Components Used
The app leverages the following common components:

1. **Authentication Module**: For user authentication and registration
2. **User Profile Component**: For user profile management
3. **Data List Component**: For displaying invoices, clients, and products
4. **Form Component**: For structured data entry in forms
5. **Navigation Component**: For app navigation
6. **Search Component**: For searching across data
7. **Modal Component**: For confirmations and dialogs

## Functional Requirements

### Core Features
- Authentication via Authentication Module
- Profile Management via User Profile Component
- Invoice Management:
  - Create, view, edit, delete invoices
  - Mark invoices as sent/paid
  - Auto-generate invoice numbers
- Client Management:
  - Add, view, edit, delete clients
- Product/Service Management:
  - Add, view, edit, delete products/services
- Reporting:
  - Total sales
  - Outstanding payments with date filters

## Screen Specifications

### 1. Authentication Screens
- Login Screen (via Authentication Module)
- Registration Screen (via Authentication Module)
- Profile Edit Screen (via User Profile Component)

### 2. Dashboard
**Purpose**: Main landing page showing overview and quick access
- Components:
  - Summary section:
    - Recent invoices
    - Total sales
    - Outstanding payments
  - Quick Links:
    - Invoices
    - Clients
    - Products
    - Reports
    - Profile
  - Navigation Component for menu

### 3. Invoice List Screen
**Purpose**: Display and manage invoices
- Components:
  - Data List Component with:
    - Columns:
      - Invoice Number
      - Client Name
      - Date
      - Amount
      - Status (Draft, Sent, Paid)
    - Filters:
      - Status
      - Date Range
    - Actions:
      - View
      - Edit
      - Delete (with Modal Component)
  - Search Component

### 4. Invoice Creation/Edit Screen
**Purpose**: Create or modify invoices
- Components:
  - Form Component with dynamic items table
  - Fields:
    - Client (dropdown)
    - Date (date picker, default: today)
    - Due Date (date picker, default: +30 days)
    - Items table:
      - Product/Service (dropdown)
      - Quantity (number)
      - Price (number)
      - Tax (number)
      - Total (calculated)
    - Notes (text area)
    - Total (calculated)
  - Buttons:
    - Save
    - Cancel

### 5. Client List Screen
**Purpose**: Manage client information
- Components:
  - Data List Component with:
    - Columns:
      - Name
      - Email
      - Phone
    - Actions:
      - Add
      - Edit
      - Delete (Modal Component if invoices exist)
  - Search Component

### 6. Client Form Screen
**Purpose**: Add or edit client details
- Components:
  - Form Component with fields:
    - Name
    - Email
    - Address
    - Phone
  - Buttons:
    - Save
    - Cancel

### 7. Product/Service List Screen
**Purpose**: Manage products and services
- Components:
  - Data List Component with:
    - Columns:
      - Name
      - Price
      - Tax Rate
    - Actions:
      - Add
      - Edit
      - Delete

### 8. Product/Service Form Screen
**Purpose**: Add or edit product/service details
- Components:
  - Form Component with fields:
    - Name
    - Description
    - Price
    - Tax Rate
  - Buttons:
    - Save
    - Cancel

### 9. Reports Screen
**Purpose**: View financial reports and analytics
- Components:
  - Filters:
    - Date Range (start/end date pickers)
  - Content:
    - Charts (sales over time)
    - Tables (totals, outstanding)
  - Custom Reports Component

## Application Flow
1. User logs in through Authentication Module
2. Lands on Dashboard with Navigation Component
3. Can navigate to:
   - Invoice List: Manage invoices
   - Client List: Manage clients
   - Product List: Manage products
   - Reports: View summaries
   - Profile: Edit profile

## Business Rules
1. Invoice Management:
   - Invoices become uneditable once marked as Paid
   - Invoice numbers auto-increment per user
   - Total calculation: Σ(Quantity * Price * (1 + Tax))

2. Client Management:
   - Client deletion requires confirmation if linked to invoices
   - Client information must be unique per user

3. Product Management:
   - Products can be reused across multiple invoices
   - Price and tax rates must be non-negative

## Technical Notes
- All forms should implement real-time validation
- Data should be cached locally for offline access
- Reports should be generated server-side for large datasets
- Implement proper error handling and loading states 