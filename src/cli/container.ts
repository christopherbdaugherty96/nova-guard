/**
 * OpenClaw's container detection (src/infra/container-environment.ts at
 * b8324c64): Fly.io machine variables, a container sentinel file, or a
 * container cgroup for PID 1. It describes the host nova-guard runs on.
 */
export function detectContainer(
  env: NodeJS.ProcessEnv,
  files: { exists(file: string): boolean; read(file: string): string | undefined },
): boolean {
  if (env.FLY_MACHINE_ID?.trim() && env.FLY_APP_NAME?.trim()) return true;
  for (const sentinel of ["/.dockerenv", "/run/.containerenv", "/var/run/.containerenv"]) {
    if (files.exists(sentinel)) return true;
  }
  const cgroup = files.read("/proc/1/cgroup");
  return (
    cgroup !== undefined &&
    /\/docker\/|cri-containerd-[0-9a-f]|containerd\/[0-9a-f]{64}|\/kubepods[/.]|\blxc\b/.test(cgroup)
  );
}
