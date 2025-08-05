## WHAT ARE WE BUILDING?
We are developing a new application called breakthru.  This application is a man-in-the-middle proxy that will be used for inspecting http and wbesocket traffic for video games.  The application is written in golang and should be cross compiled for Mac and Windows of arm and x64.  When running the application is will override the operating system's networking capabilities to reroute all HTTPS traffic only through this application and it should work similarly to https://github.com/mitmproxy/mitmproxy.  This appplication will read all traffic and output it in plan text in the log file for the session.  The application will have configurable certificates it cna use, it should terminate the SSL connection to read everything in plain text and then proxy the connection to its destination.

## PROBLEM WE WANT TO SOLVE
It can be hard to understand what a video game is doing when it comes to back end calls.  We want to make it easier to understand what calls are being made and with what information.

## GOALS
- Single binary easy to run and use application.  UX for the application is important.  It needs to "just work" out of the box with only a configuration file or command line parameters.
- Simple, single use application.  This is designed to view video game traffic only.

## NON GOALS
- None at the moment

## BACKGROUND
See https://github.com/mitmproxy/mitmproxy for inspiration

## FEATURES:
- Run the application with a file configuration or command line parameters
- Comprehensive logging and debugging information.  Easy to debug issues and great error handling.
- Output entire http payloads from request to response including headers
- Terminates and reinitiates https connections to read encrypted information in plain text
- Ability to provide your own certificate for use in https connections
- Ability to run in non https mode, where a load balancer in front of the application terminates the https.

## DOCUMENTATION:

- https://github.com/mitmproxy/mitmproxy

## OTHER CONSIDERATIONS:

- Unknown how to override the native OS networking to filter traffic through the proxy.  Mitm proxy does this but it is unknown if golang can provide the same functionality.