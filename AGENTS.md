# AGENTS.md

## Style guidelines
- Use `gofmt` to format all written code

## Building the project
```
cd cmd/tasks-server && go build
```
The binary `tasks-server` or `tasks-server.exe` is created.

## Project structure
- Keep cmd/tasks-server/main.go minimal
- Most code goes in packages in `pkg`
- Can save reports or artefacts in `docs`

Summary of project structure can be found in `docs/structure.md` and the initial blueprint is in `docs/overview.md`.
