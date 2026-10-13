// gRPC client for urljaild over its Unix socket, as the CLI uses it (ADR 0019). The .proto is
// loaded at runtime from the repo's api/proto, so the contract has one source.
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { join } from 'node:path';

export interface VersionInfo {
  urljail: string;
  firecracker: string;
  guestKernel: string;
  egressMode: string;
  profiles: string[];
  maxVms: number;
}

export interface Progress {
  state: string; // RUN_STATE_*
  message: string;
  runDir: string;
  error: string;
}

export class DaemonClient {
  private readonly client: any;

  constructor(socket: string, protoDir: string) {
    const def = protoLoader.loadSync(join(protoDir, 'urljail/daemon/v1/daemon.proto'), {
      includeDirs: [protoDir],
      keepCase: false,
      longs: Number,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    const pkg: any = grpc.loadPackageDefinition(def);
    this.client = new pkg.urljail.daemon.v1.DaemonService(`unix://${socket}`, grpc.credentials.createInsecure());
  }

  version(): Promise<VersionInfo> {
    return new Promise((ok, fail) => {
      this.client.Version({}, { deadline: Date.now() + 5000 }, (err: Error | null, v: any) => {
        if (err) return fail(err);
        ok({
          urljail: v.urljail, firecracker: v.firecracker, guestKernel: v.guestKernel, egressMode: v.egressMode,
          profiles: v.profiles ?? [], maxVms: Number(v.maxVms ?? 1),
        });
      });
    });
  }

  // detonate streams a run's progress until it ends; the last message has state DONE or FAILED.
  detonate(url: string, profile: string, onProgress: (p: Progress) => void, signal?: AbortSignal): Promise<Progress> {
    return new Promise((ok, fail) => {
      const call = this.client.Detonate({ url, profile });
      let last: Progress | undefined;
      signal?.addEventListener('abort', () => call.cancel());
      call.on('data', (m: any) => {
        last = { state: m.state, message: m.message ?? '', runDir: m.runDir ?? '', error: m.error ?? '' };
        onProgress(last);
      });
      call.on('error', (err: Error) => fail(err));
      call.on('end', () => (last ? ok(last) : fail(new Error('stream ended without a final state'))));
    });
  }
}
