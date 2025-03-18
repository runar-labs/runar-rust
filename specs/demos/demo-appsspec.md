Introduction
This specification defines two demo applications—Invoice App and Note-taking App—as part of an app development framework. Alongside these apps, a set of reusable common components is established, including Authentication Module and User Profile Component, each with UI and backend microservices. These components are designed for modularity and reuse across the two apps and future applications. The spec assumes a UI library provides pre-built UI elements, so the focus is on functionality, configuration, and integration.
Functionality: Detailed requirements for apps and components.

Component Architecture: Specifies UI and backend microservices, where they’re used.

Detail: Flows, screens, fields, and rules for developers/AI agents.

Common Components Specification

1. Authentication Module
   Purpose: Manages user authentication with UI screens and a backend microservice for secure access.
   UI Component
   Screens:
   Login Screen:
   Fields: Email/Username (text input), Password (password input).

Buttons: Login (submits to backend), Register (links to Registration), Forgot Password (links to Password Reset).

UI Library: Uses text inputs, buttons, and links.

Registration Screen:
Fields: Email (text input), Username (text input), Password (password input), Confirm Password (password input).

Buttons: Register (submits to backend), Login (links to Login).

UI Library: Uses text inputs, buttons, and links.

Password Reset Screen:
Fields: Email (text input), (Post-link) New Password (password input), Confirm New Password (password input).

Buttons: Send Reset Link, Submit (new password).

UI Library: Uses text inputs, buttons, and modal for reset flow.

Functionality: Submits data to backend API, displays validation errors.

Backend Microservice
API Endpoints:
POST /auth/register: Creates a user (input: email, username, password; output: user ID, token).

POST /auth/login: Authenticates user (input: email/username, password; output: token).

POST /auth/reset-password: Sends reset email (input: email; output: success message).

POST /auth/reset-password/confirm: Updates password (input: token, new password; output: success message).

Data: Stores users (ID, email, username, hashed password) in a database.

Business Rules:
Email and username are unique.

Passwords must be ≥8 characters, hashed before storage.

Tokens expire (e.g., 24 hours).

Usage: Both apps use this for user login and registration. 2. User Profile Component
Purpose: Allows users to edit their profile information with a UI screen and backend microservice.
UI Component
Screen: Profile Edit Screen
Fields:
Username (text input, pre-filled)

Email (text input, pre-filled)

Full Name (text input, optional)

Phone (text input, optional)

Buttons: Save (submits to backend), Cancel (discards changes).

UI Library: Uses text inputs, buttons, and form layout.

Functionality: Loads current user data, submits updates to backend, shows validation errors.

Backend Microservice
API Endpoints:
GET /profile: Retrieves user profile (output: { username, email, fullName, phone }).

PUT /profile: Updates user profile (input: { username, email, fullName, phone }; output: updated profile).

Data: Updates user record in the database (linked to Authentication Module’s user table).

Business Rules:
Username and email must remain unique.

Email format must be valid.

Updates require authenticated user token.

Usage: Both apps use this for profile management. 3. Data List Component
Purpose: Displays tabular or list-based data with configurable options.
UI Component
Functionality:
Renders a table/list with sorting, filtering, pagination.

Row actions: view, edit, delete.

Configuration:
Columns (e.g., { name: "Title", type: "text" }).

Data (array of items).

Filters (e.g., dropdowns, text).

Actions (callbacks for view/edit/delete).

UI Library: Uses table/grid, buttons, dropdowns.

Business Rules:
Sorting toggles ascending/descending.

Filters apply instantly.

Usage: Invoice App (invoices, clients, products); Note-taking App (notes). 4. Form Component
Purpose: Generic form builder for structured data entry.
UI Component
Functionality:
Renders fields with validation.

Handles submission.

Supports dynamic fields (e.g., adding rows).

Configuration:
Fields (e.g., { type: "text", label: "Name", required: true }).

Validation (e.g., required, min length).

Submit callback.

UI Library: Uses inputs, buttons, dynamic table for multi-row inputs.

Business Rules:
Required fields block submission if empty.

Errors shown inline.

Usage: Invoice App (invoice, client, product forms); Note-taking App (folder/tag forms). 5. Navigation Component
Purpose: App navigation via menu or sidebar.
UI Component
Functionality:
Displays navigation items.

Highlights active section.

Supports nesting.

Configuration:
Items (e.g., { label: "Invoices", destination: "invoices" }).

Style (sidebar/top menu).

UI Library: Uses menu or sidebar layout.

Business Rules:
Updates based on current screen.

Usage: Both apps for main navigation. 6. Search Component
Purpose: Full-text or filtered search across data.
UI Component
Functionality:
Text input for queries.

Optional filters.

Returns results for Data List Component.

Configuration:
Searchable fields.

Filter options.

UI Library: Uses text input, dropdowns.

Business Rules:
Case-insensitive search.

Debounced updates.

Usage: Invoice App (invoices, clients); Note-taking App (notes). 7. Modal Component
Purpose: Displays dialogs for confirmations or input.
UI Component
Functionality:
Renders customizable content.

Supports buttons.

Configuration:
Content (text or form).

Buttons (e.g., { label: "Confirm", action: callback }).

UI Library: Uses modal dialog.

Business Rules:
Closes only via button action.

Usage: Both apps for confirmations.
Invoice App Specification
Overview
The Invoice App enables users to create, manage, and track invoices, with client and product management and basic reporting.
Functional Requirements
Authentication: Via Authentication Module.

Profile Management: Via User Profile Component.

Invoice Management: Create, view, edit, delete invoices; mark as sent/paid; auto-generate invoice numbers.

Client Management: Add, view, edit, delete clients.

Product/Service Management: Add, view, edit, delete products/services.

Reporting: Total sales, outstanding payments with date filters.

Screens
Login Screen: Authentication Module’s Login Screen.

Registration Screen: Authentication Module’s Registration Screen.

Profile Edit Screen: User Profile Component’s Profile Edit Screen.

Dashboard:
Summary: Recent invoices, total sales, outstanding payments.

Quick Links: Invoices, Clients, Products, Reports, Profile.

Navigation Component for menu.

Invoice List Screen:
Data List Component.

Columns: Invoice Number, Client Name, Date, Amount, Status (Draft, Sent, Paid).

Filters: Status, Date Range.

Actions: View, Edit, Delete (Modal Component).

Search Component.

Invoice Creation/Edit Screen:
Form Component (dynamic items table).

Fields: Client (dropdown), Date (date picker, default: today), Due Date (date picker, default: +30 days), Items (table: Product/Service (dropdown), Quantity (number), Price (number), Tax (number), Total (calculated)), Notes (text area), Total (calculated).

Buttons: Save, Cancel.

Client List Screen:
Data List Component.

Columns: Name, Email, Phone.

Actions: Add, Edit, Delete (Modal Component if invoices exist).

Search Component.

Client Form Screen:
Form Component.

Fields: Name, Email, Address, Phone.

Buttons: Save, Cancel.

Product/Service List Screen:
Data List Component.

Columns: Name, Price, Tax Rate.

Actions: Add, Edit, Delete.

Product/Service Form Screen:
Form Component.

Fields: Name, Description, Price, Tax Rate.

Buttons: Save, Cancel.

Reports Screen:
Filters: Date Range (start/end date pickers).

Content: Charts (sales over time), Tables (totals, outstanding).

Custom Reports Component.

App Flow
User logs in (Authentication Module).

Lands on Dashboard (Navigation Component).

Navigates to:
Invoice List: Manages invoices (Data List, Form, Modal Components).

Client List: Manages clients (Data List, Form Components).

Product List: Manages products (Data List, Form Components).

Reports: Views summaries (Reports Component).

Profile: Edits profile (User Profile Component).

Business Rules
Invoices uneditable once Paid.

Client deletion requires confirmation if linked to invoices.

Invoice numbers auto-increment per user.

Total = Σ(Quantity _ Price _ (1 + Tax)).

Components Used
Common: Authentication Module, User Profile Component, Data List Component, Form Component, Navigation Component, Search Component, Modal Component.

Specific: Reports Component.

Note-taking App Specification
Overview
The Note-taking App allows users to create, organize, and search notes with rich text, canvas drawing, and hyperbolic tree diagrams for linked data.
Functional Requirements
Authentication: Via Authentication Module.

Profile Management: Via User Profile Component.

Note Management: Create, view, edit, delete notes with rich text/drawings; organize with folders/tags; search by text/tags.

Canvas Drawing: Freehand and shapes within notes, saved with note content.

Diagram Creation: Hyperbolic tree diagrams to visualize linked data, with nodes linking to notes.

Screens
Login Screen: Authentication Module’s Login Screen.

Registration Screen: Authentication Module’s Registration Screen.

Profile Edit Screen: User Profile Component’s Profile Edit Screen.

Note List Screen:
Data List Component (list/grid view).

Columns: Title, Preview, Tags, Date.

Sidebar: Folder/Tag navigation (Navigation Component).

Search Component.

Actions: View, Edit, Delete (Modal Component).

Note Editor Screen:
Custom Note Editor Component.

Features: Title (text input), Content (rich text: bold, italic, lists), Canvas (pen, eraser, shapes, colors), Tags (text input, comma-separated), Folder (dropdown), Diagram Insert (links to Diagram Screen).

Buttons: Save, Cancel, Delete (Modal Component).

Diagram Screen:
Custom Diagram Component.

Features: Canvas for nodes/links, Hyperbolic tree layout (zoom/pan, focus), Node Properties (Label, Link to note), Tools (add node, link, edit, delete).

Buttons: Save, Cancel.

Folder/Tag Management Screen:
Data List Component.

Columns: Name.

Actions: Add, Edit, Delete (Modal Component).

Form Component for add/edit: Name (text), Save, Cancel.

App Flow
User logs in (Authentication Module).

Lands on Note List (Navigation Component).

From Note List:
Creates/edits notes (Note Editor Component).

Searches notes (Search Component).

Organizes notes (Folder/Tag Management).

Creates diagrams (Diagram Component).

Edits profile (User Profile Component).

Business Rules
Note title required; content optional.

Drawings/diagrams saved with notes.

Diagram nodes can link to notes; clicking opens the note.

Notes private per user.

Search covers titles, content, tags.

Components Used
Common: Authentication Module, User Profile Component, Data List Component, Navigation Component, Search Component, Modal Component, (Form Component partially for Folder/Tag).

Specific: Note Editor Component, Diagram Component.

Notes for AI Agents
Microservices: Authentication Module and User Profile Component have separate backend APIs and UI parts. Deploy as independent services with database access.

UI Library: Use pre-built components (e.g., text inputs, buttons, modals) from a library; configure them per spec.

Hyperbolic Trees: Diagram Component visualizes linked data in hyperbolic space (focus on a node with contextual zoom/pan).

Modularity: Common components are reusable with configuration (e.g., Data List with columns, Form with fields).

Flow: Start with Authentication Module and User Profile Component, then common components, then app-specific features.
