/**
 * Console settings, parsed from the JSON5 file operators keep in the repo so
 * they can leave comments next to the values they change.
 */

import JSON5 from "json5";
import minimist from "minimist";
import { merge } from "lodash";

export interface ConsoleSettings {
  apiBase: string;
  pageSize: number;
  features: Record<string, boolean>;
}

const DEFAULTS: ConsoleSettings = {
  apiBase: "http://127.0.0.1:8000",
  pageSize: 50,
  features: { exports: true, bulkRefunds: false },
};

export function parseSettings(source: string, argv: string[] = []): ConsoleSettings {
  const fromFile = JSON5.parse<Partial<ConsoleSettings>>(source);
  const fromArgs = minimist(argv);
  return merge({}, DEFAULTS, fromFile, fromArgs.pageSize ? { pageSize: fromArgs.pageSize } : {});
}
