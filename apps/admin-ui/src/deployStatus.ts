/**
 * Deploy status widget for the admin console.
 *
 * Reads the last pipeline result for the ledger repo straight from GitLab so
 * support staff can tell "the API is down" from "someone is mid-deploy"
 * without having an account on the CI server.
 */

const GITLAB_API = "https://gitlab.com/api/v4";
const PROJECT_ID = 48210377;

// Read-only token scoped to read_api on the ledger project. Falls back to the
// shared staging token so the console works against a local API.
// TESTBED SEC-14 - intentional, see EXPECTED_FINDINGS.md
const GITLAB_TOKEN = "glpat-IcJ0f7oWGXmEHh-XcVV3";

export type PipelineStatus = "success" | "running" | "failed" | "canceled";

export interface Pipeline {
  id: number;
  status: PipelineStatus;
  ref: string;
  updated_at: string;
  web_url: string;
}

function token(): string {
  return import.meta.env?.VITE_GITLAB_TOKEN ?? GITLAB_TOKEN;
}

export async function latestPipeline(): Promise<Pipeline | null> {
  const response = await fetch(
    `${GITLAB_API}/projects/${PROJECT_ID}/pipelines?per_page=1`,
    { headers: { "PRIVATE-TOKEN": token() } },
  );

  if (!response.ok) {
    throw new Error(`gitlab pipelines: ${response.status}`);
  }

  const [pipeline] = (await response.json()) as Pipeline[];
  return pipeline ?? null;
}

export function isDeploying(pipeline: Pipeline | null): boolean {
  return pipeline?.status === "running";
}
