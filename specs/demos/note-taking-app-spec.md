# Note-taking App Specification

## Overview
The Note-taking App allows users to create, organize, and search notes with rich text, canvas drawing, and hyperbolic tree diagrams for linked data. This specification details the functionality, screens, and components used in the application.

## Common Components Used
The app leverages the following common components:

1. **Authentication Module**: For user authentication and registration
2. **User Profile Component**: For user profile management
3. **Data List Component**: For displaying notes in list/grid view
4. **Navigation Component**: For app navigation and folder structure
5. **Search Component**: For searching notes
6. **Modal Component**: For confirmations and dialogs
7. **Form Component**: For folder/tag management

## App-Specific Components

### 1. Note Editor Component
**Purpose**: Rich text and canvas editing
- Features:
  - Rich text formatting (bold, italic, lists)
  - Canvas drawing tools
  - Tag management
  - Folder organization
  - Diagram integration

### 2. Diagram Component
**Purpose**: Create and manage hyperbolic tree diagrams
- Features:
  - Node/link creation and editing
  - Hyperbolic tree layout
  - Zoom/pan functionality
  - Note linking
  - Interactive visualization

## Functional Requirements

### Core Features
- Authentication via Authentication Module
- Profile Management via User Profile Component
- Note Management:
  - Create, view, edit, delete notes
  - Rich text editing
  - Canvas drawing
  - Folder organization
  - Tag management
- Diagram Creation:
  - Hyperbolic tree diagrams
  - Node linking to notes
  - Interactive visualization
- Search:
  - Full-text search across notes
  - Tag-based filtering
  - Folder navigation

## Screen Specifications

### 1. Authentication Screens
- Login Screen (via Authentication Module)
- Registration Screen (via Authentication Module)
- Profile Edit Screen (via User Profile Component)

### 2. Note List Screen
**Purpose**: Main view for browsing and managing notes
- Components:
  - Data List Component with:
    - Views:
      - List view
      - Grid view
    - Columns:
      - Title
      - Preview
      - Tags
      - Date Modified
    - Actions:
      - View
      - Edit
      - Delete (with Modal Component)
  - Sidebar:
    - Folder navigation
    - Tag filters
  - Search Component

### 3. Note Editor Screen
**Purpose**: Create and edit notes
- Components:
  - Note Editor Component with:
    - Title field
    - Rich text editor:
      - Text formatting
      - Lists
      - Links
    - Canvas tools:
      - Pen tool
      - Eraser
      - Shapes
      - Color picker
    - Tag input field
    - Folder selector
    - Diagram insertion tool
  - Buttons:
    - Save
    - Cancel
    - Delete (with Modal Component)

### 4. Diagram Screen
**Purpose**: Create and edit hyperbolic tree diagrams
- Components:
  - Diagram Component with:
    - Canvas area
    - Tools:
      - Add node
      - Add link
      - Edit properties
      - Delete
    - Node properties:
      - Label
      - Note link
    - Navigation:
      - Zoom
      - Pan
      - Focus
  - Buttons:
    - Save
    - Cancel

### 5. Folder/Tag Management Screen
**Purpose**: Organize notes with folders and tags
- Components:
  - Data List Component with:
    - Columns:
      - Name
      - Item Count
    - Actions:
      - Add
      - Edit
      - Delete (with Modal Component)
  - Form Component for add/edit:
    - Name field
    - Description (optional)
    - Parent folder (for folders only)
    - Buttons:
      - Save
      - Cancel

## Application Flow
1. User logs in through Authentication Module
2. Lands on Note List Screen
3. Can:
   - Create/edit notes using Note Editor
   - Search notes using Search Component
   - Organize notes with folders/tags
   - Create diagrams using Diagram Component
   - Edit profile via User Profile Component

## Business Rules

### 1. Note Management
- Notes must have a title
- Content (text/drawing) is optional
- Notes are private to each user
- Autosave enabled during editing
- Support offline editing

### 2. Diagram Rules
- Nodes can link to existing notes
- Clicking a linked node opens the note
- Diagrams are saved with notes
- Support zoom levels and focus points

### 3. Organization Rules
- Notes can be in multiple tags
- Notes can only be in one folder
- Deleting a folder requires confirmation
- Tags are global per user

### 4. Search Rules
- Search covers:
  - Note titles
  - Note content
  - Tags
  - Diagram node labels
- Results update in real-time
- Case-insensitive matching

## Technical Notes
- Implement efficient data structures for hyperbolic tree visualization
- Use WebGL/Canvas for diagram rendering
- Implement proper caching for offline access
- Optimize search for large note collections
- Support real-time collaboration (future feature)
- Implement proper error handling and loading states 