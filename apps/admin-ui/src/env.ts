/**
 * Runtime configuration for the admin console.
 *
 * Everything here is read from the environment at build time by Vite. No value
 * is ever hardcoded: the console is served publicly, so anything inlined here
 * would ship to the browser.
 */

export const gitlabToken = import.meta.env.VITE_GITLAB_TOKEN;
export const analyticsKey = import.meta.env.VITE_ANALYTICS_API_KEY;
export const apiBase = import.meta.env.VITE_LEDGER_API_BASE ?? "http://127.0.0.1:8000";

export function assertConfigured(): void {
  if (!gitlabToken) {
    throw new Error("VITE_GITLAB_TOKEN is not set; the deploy widget will be hidden");
  }
}
