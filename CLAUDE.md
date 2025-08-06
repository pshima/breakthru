<!--- # ref and credit to https://github.com/coleam00/context-engineering-intro] -->
## General
### Project Awareness & Context
- **Always read `OVERVIEW.md`** at the start of a new conversation to understand the project's architecture, goals, style, and constraints.
- **Check `TASK.md`** before starting a new task. If the task isn't listed, add it with a brief description and today's date.

### Code Structure & Modularity
- **Never create a file longer than 500 lines of code.** If a file approaches this limit, refactor by splitting it into modules or helper files.
- **Organize code into clearly separated modules**, grouped by feature or responsibility.
- **Use clear, consistent imports** (prefer relative imports within packages).

### Task Completion
- **Mark completed tasks in `TASK.md`** immediately after finishing them.
- Add new sub-tasks or TODOs discovered during development to `TASK.md` under a "Discovered During Work" section.

### AI Behavior Rules
- **Never assume missing context. Ask questions if uncertain.**
- **If I tell you something, it is the law and not to be broken or worked around.** Never assume you know better than what I have told you**
- **Always ask clarifying questions before making any changes**
- **Never hallucinate libraries or functions** – only use known, verified packages.
- **Always confirm file paths and module names** exist before referencing them in code or tests.

## Best Practices

### General
- This application will not use docker, never try and create any docker configuration or include any docker documentation
- This appliaction will never run as a service, do not include any documentation about how to run it as a service
- Linux is not currently supported, do not add it to any code or README files

### Error Handling and Debugging
- Debugging is a critical part of software development, always create the necessary basic debugging abilities
- Logging should be enabled in the beginning of development and use clear and concise error codes.
- Each error should be assigned a unique code in a incrementing numerical format.  Where there is the need for multiple error codes in using the same integer, use increasing alphabet codes such as A, B, C.  
- Implement proper error handling and provide feedback to the user
- When developing a front end, create a debuggable admin page in unison with the product.  Do not create a mess of code from admin and product pages, keep them separate with shared re-usable components or libraries.

### API Development
- No need to add OpenAPI documentation for this app, as it has no APIs
- Use appropriate HTTP status codes and error messages
- Validate all input parameters before processing
- Return consistent response formats

### Code Organization
- Follow clean architecture principles - handlers → services → models
- Keep business logic in services, not handlers
- Use dependency injection for testability
- Separate concerns into appropriate packages

### Code Guidelines
- Add code comments for all exported functions (1-3 lines)
- Use meaningful variable and function names
- Keep functions small and focused (< 50 lines preferred)
- Handle errors explicitly, don't ignore them
- Use early returns to reduce nesting

### Testing
- Write unit tests for all new functions and update for existing functions as necessary.
- Maintain code coverage above 80%
- Use table-driven tests for multiple scenarios
- Mock external dependencies in unit tests
- Write integration tests for complete workflows

### Security
- Validate and sanitize all user input
- Use parameterized queries (if adding database)
- Never log sensitive information
- Keep dependencies updated
- Run security scans before committing
- Use security best practices where it makes sense, always confirm when you make critical security decisions
- Use thread safe operations when appropriate

### Performance
- Use read/write mutexes appropriately
- Avoid unnecessary allocations in hot paths
- Profile code for performance bottlenecks
- Use buffered channels where appropriate
- Consider caching for expensive operations

### Documentation
- Update README.md for user-facing features
- Update CLAUDE.md for development changes
- Keep OpenAPI spec in sync with code
- Document complex algorithms inline
- Update SECURITY.md for security changes
- All functions or major code definitions should have code comments that are 1-3 lines that describe what it does in plain english as well as why it is needed

### Development Workflow
- After making any changes make sure to run the tests and improve them if you can