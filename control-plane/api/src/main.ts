// urljail control plane API (P7, ADR 0019). Unprivileged; talks to urljaild over its socket.
import 'reflect-metadata';
import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { APP_GUARD, NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { loadConfig } from './config';
import { DaemonClient } from './daemon';
import { Db } from './db';
import { ApiController, CONFIG, LocalOnly, QUEUE_TOKEN, TokenGuard } from './http';
import { makeQueue, startWorker } from './worker';
import { importRuns } from './importer';

async function bootstrap() {
  const cfg = loadConfig();
  const db = new Db(cfg.databaseUrl);
  await db.migrate();
  const stale = await db.failStale();
  if (stale) console.log(`marked ${stale} runs interrupted by a previous stop as failed`);
  const daemon = new DaemonClient(cfg.daemonSocket, cfg.protoDir);
  let slots = 1;
  try {
    slots = Math.max(1, (await daemon.version()).maxVms);
  } catch (e) {
    console.warn(`urljaild not reachable yet (${(e as Error).message}); worker concurrency 1`);
  }
  // Runs from the CLI and feeds appear in the dashboard too: now, then every minute.
  const sync = () => importRuns(cfg, db).then((n) => n && console.log(`indexed or refreshed ${n} runs from ${cfg.runsDir}`)).catch((e) => console.warn(`indexing runs: ${e.message}`));
  await sync();
  const syncTimer = setInterval(sync, 60_000);
  const queue = makeQueue(cfg);
  const worker = startWorker(cfg, db, daemon, slots);

  @Module({
    controllers: [ApiController],
    providers: [
      { provide: CONFIG, useValue: cfg },
      { provide: Db, useValue: db },
      { provide: DaemonClient, useValue: daemon },
      { provide: QUEUE_TOKEN, useValue: queue },
      { provide: APP_GUARD, useClass: TokenGuard },
    ],
  })
  class AppModule implements NestModule {
    configure(c: MiddlewareConsumer) {
      c.apply(LocalOnly).forRoutes('*');
    }
  }

  const app = await NestFactory.create<NestExpressApplication>(AppModule, { logger: ['error', 'warn', 'log'] });
  app.getHttpAdapter().getInstance().disable('x-powered-by');
  app.useBodyParser('json', { limit: '16kb' });
  app.enableShutdownHooks();
  const close = async () => {
    clearInterval(syncTimer);
    await worker.close();
    await queue.close();
    await db.pool.end();
  };
  process.once('SIGTERM', () => void close().then(() => app.close()));
  await app.listen(cfg.port, cfg.host);
  console.log(`urljail API on http://${cfg.host}:${cfg.port} (worker concurrency ${slots})`);
}

bootstrap().catch((e) => {
  console.error(e);
  process.exit(1);
});
