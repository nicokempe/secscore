# Contributing to Dashio Website

Please follow the guidelines below to keep the codebase clean, secure, and maintainable.

## Getting Started

* Clone the repository and install dependencies using [pnpm](https://pnpm.io/).
* After installing, run `pnpm run lint:fix` to automatically resolve lint issues.
* Always work off the latest `main` branch.

**Commands**

* `pnpm lint` — Lint
* `pnpm test:unit` — Run unit tests
* `pnpm build` — Production build
* `pnpm dev` — Start development server
* `nuxi typecheck` — Run Nuxt type checking

## Branch Workflow

* **Never push directly to `main`.**
* Create feature branches from `main` using the format `type/short-topic`:
  * `feat/user-profile`
  * `fix/login-bug`
  * `refactor/auth-flow`
  * `docs/readme-commit-policy`
  * `ci/pipeline-lint`
  * `chore/deps-2025-08`
* Keep branches small and focused to simplify reviews.

## Commit Messages

* Follow [Conventional Commits](https://www.conventionalcommits.org/):
  ```
  type(scope): summary in present tense
  ```
* **Types**: `feat`, `fix`, `docs`, `refactor`, `style`, `test`, `ci`, `chore`
* **Scope**: single word describing the affected area (e.g., `auth`, `api`, `deploy`, `domains`, `contact`)
* **Summary**: lowercase, imperative present tense, no trailing period
* Use additional bullet points in the commit body when needed to describe changes.
* **All commits must be GPG-signed.** Set up commit signing using the [GitHub guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

**Examples**

* `feat(domains): add required child element to template tag`
* `fix(deploy): remove wazuh and fix ufw config`
* `docs(api): update api documentation for new endpoints`
* `style(formatter): apply consistent code formatting`
* `refactor(contact): prevent xss attack using v-html directive`
* `test(auth): add tests for token expiration`
* `ci(deploy): update pipeline to include lint`
* `chore(deps): update packages to latest versions`

**Larger Changes**

```
feat(auth): add email otp reauthentication flow

- introduce verify-otp endpoint in nitro
- handle otp expiration and resend limits
- add ui notifications for success and failure
```

## Code Style and Documentation

* Write **strict TypeScript** (`strict: true`, `noImplicitAny: true`)
* **Never use `any`**; use explicit types, unions, generics, or discriminated unions.
* Use descriptive variable and function names; avoid single-letter names.
* Add [TSDoc](https://tsdoc.org/) comments for functions, classes, and modules.
* **Validation logic**:
  * Centralize in `~/utils/validators.ts`.
  * Never inline regex or ad-hoc validation inside components.
* **Formatting logic**:
  * Centralize in `~/utils/formatters.ts`.
  * All reusable formatters (dates, roles, console output, remote display) must live here.
* Ensure all UI changes are **fully responsive**.

### Server Responses & Errors

* Success:
  * Default 200 → `return { ... }`.
  * Non-200 (201, 204, etc.) → use `setResponseStatus(event, CODE)` + `return { ... }`.
* Errors:
  * Always **`throw createError({ statusCode, statusMessage, data? })`**.
  * Never `return createError(...)`.
  * Never use `sendError` unless working in very low-level streaming code.
* Don’t add `{ status: 200 }` in payloads.
* Only use `new Response(...)` for binary, streaming, or proxy responses. Set headers explicitly.

## Project Structure

* **Backend**: Built with **Nitro**, lives in `server/**`.
  * API endpoints are in `server/api`.
  * Every API endpoint must include a `defineRouteMeta({ openAPI: { ... } })` block at the bottom.
* **Frontend**:
  * Types: `app/types/**`
  * Utilities: `app/utils/**`
  * Composables: `app/composables/**`
  * Formatters: `app/utils/formatters.ts`
  * Components: `components/`
  * Static files: `public/`, `assets/`

## Testing and Quality Gates

* Run all relevant tests with `pnpm test:unit` before pushing.
* Linting must pass with **no warnings or errors** using `pnpm lint`.
* Run `nuxi typecheck` to ensure no TypeScript errors.
* Only push code that has passed linting, type checks, and tests.

## Pull Requests

* Open a Pull Request targeting `main` and use the PR template automatically provided.
* Ensure the PR description is clear and references any related issues.
* Check off all items in the PR checklist before requesting review.
* Request review from the appropriate team members.

## Best Practices

* Keep changes small and atomic. Large features should be split into multiple PRs.
* Break big problems into smaller steps.
* Use clear, specific names for files, variables, and branches.
* Prefer the most specific commit scope possible.
* Update documentation and tests alongside code changes.
* Run `pnpm lint`, `nuxi typecheck`, and `pnpm test:unit` before opening a PR.
* Review `AGENTS.md` and `README.md` for repository structure and conventions.

## References

* [Conventional Commits](https://www.conventionalcommits.org/)
* [Semantic Commit Messages](https://seesparkbox.com/foundry/semantic_commit_messages)
* [Karma Git Commit Msg](http://karma-runner.github.io/1.0/dev/git-commit-msg.html)
