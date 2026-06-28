// End-to-end test helpers (not shipped to consumers). The interpolated execSync here is a
// command-injection construct, but it lives in the e2e test tree, so it must be demoted.
import { execSync } from "child_process";

export function setupRepo(url: string): void {
  execSync(`git clone ${url} repo`, { stdio: "inherit" });
}
