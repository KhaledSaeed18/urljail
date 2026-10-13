import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

// Settings come from the environment (~/.config/urljail/control-plane.env, 0600; ADR 0019).
export interface Config {
  host: string;
  port: number;
  token: string;
  databaseUrl: string;
  redisUrl: string;
  daemonSocket: string;
  runsDir: string;
  protoDir: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const need = (k: string): string => {
    const v = env[k];
    if (!v) throw new Error(`${k} is not set (see control-plane/scripts/setup.sh)`);
    return v;
  };
  const token = need('URLJAIL_API_TOKEN');
  if (token.length < 32) throw new Error('URLJAIL_API_TOKEN is too short (32+ characters)');
  return {
    host: env.URLJAIL_API_HOST ?? '127.0.0.1',
    port: Number(env.URLJAIL_API_PORT ?? 7801),
    token,
    databaseUrl: need('DATABASE_URL'),
    redisUrl: need('REDIS_URL'),
    daemonSocket: env.URLJAIL_SOCKET ?? '/run/urljail/urljaild.sock',
    runsDir: resolve(env.URLJAIL_RUNS_DIR ?? join(homedir(), '.local/share/urljail/runs')),
    protoDir: resolve(env.URLJAIL_PROTO_DIR ?? join(__dirname, '../../../api/proto')),
  };
}
