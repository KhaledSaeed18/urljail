// The HTTP API (ADR 0019): localhost only, bearer token on every request, strict headers.
import { All, Body, Controller, Get, HttpException, HttpStatus, Inject, Injectable, Param, Post, Query, Res, CanActivate, ExecutionContext, NestMiddleware } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { Queue } from 'bullmq';
import { readFile } from 'node:fs/promises';
import { timingSafeEqual, createHash } from 'node:crypto';
import { Config } from './config';
import { DaemonClient } from './daemon';
import { Db } from './db';
import { insideDir, isPng, isRunId, validateSubmission } from './untrusted';

export const CONFIG = Symbol('config');
export const QUEUE_TOKEN = Symbol('queue');

const digest = (s: string) => createHash('sha256').update(s).digest();

@Injectable()
export class TokenGuard implements CanActivate {
  private readonly want: Buffer;
  constructor(@Inject(CONFIG) cfg: Config) {
    this.want = digest(cfg.token);
  }
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const h = req.headers.authorization ?? '';
    const got = digest(h.startsWith('Bearer ') ? h.slice(7) : '');
    if (!timingSafeEqual(got, this.want)) throw new HttpException('missing or wrong token', HttpStatus.UNAUTHORIZED);
    return true;
  }
}

// Only requests addressed to localhost: a DNS-rebinding page would send its own Host.
@Injectable()
export class LocalOnly implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction): void {
    const host = (req.headers.host ?? '').replace(/:\d+$/, '');
    if (host !== '127.0.0.1' && host !== 'localhost') {
      res.status(421).json({ error: 'requests must be addressed to localhost' });
      return;
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

@Controller('api')
export class ApiController {
  constructor(
    @Inject(CONFIG) private readonly cfg: Config,
    private readonly db: Db,
    private readonly daemon: DaemonClient,
    @Inject(QUEUE_TOKEN) private readonly queue: Queue,
  ) {}

  @Get('status')
  async status() {
    const counts = await this.queue.getJobCounts('waiting', 'active', 'completed', 'failed');
    try {
      return { daemon: await this.daemon.version(), queue: counts };
    } catch (e) {
      return { daemon: null, daemonError: (e as Error).message, queue: counts };
    }
  }

  @Post('runs')
  async submit(@Body() body: unknown) {
    let sub;
    try {
      sub = validateSubmission(body);
    } catch (e) {
      throw new HttpException((e as Error).message, HttpStatus.BAD_REQUEST);
    }
    const id = await this.db.create(sub.url, sub.profile);
    await this.queue.add('detonate', { id }, { jobId: id });
    return { id };
  }

  @Get('runs')
  async list(@Query('limit') limit?: string, @Query('before') before?: string) {
    const n = Math.min(Math.max(Number(limit) || 50, 1), 200);
    const b = before && !Number.isNaN(Date.parse(before)) ? new Date(before) : undefined;
    return { runs: await this.db.list(n, b) };
  }

  @Get('runs/:id')
  async get(@Param('id') id: string) {
    if (!UUID.test(id)) throw new HttpException('bad id', HttpStatus.BAD_REQUEST);
    const row = await this.db.get(id);
    if (!row) throw new HttpException('no such run', HttpStatus.NOT_FOUND);
    return row;
  }

  // Runs whose screenshots look like this one's (64-bit pHash; 6 is visual.DefaultMaxDistance).
  @Get('runs/:id/similar')
  async similar(@Param('id') id: string, @Query('max') max?: string) {
    if (!UUID.test(id)) throw new HttpException('bad id', HttpStatus.BAD_REQUEST);
    const d = Math.min(Math.max(Number.parseInt(max ?? '6', 10) || 6, 0), 16);
    return { maxDistance: d, runs: await this.db.similar(id, d, 50) };
  }

  // The screenshot, only if it really is a PNG, served as one.
  @Get('runs/:id/screenshot')
  async screenshot(@Param('id') id: string, @Res() res: Response) {
    if (!UUID.test(id)) throw new HttpException('bad id', HttpStatus.BAD_REQUEST);
    const row = await this.db.get(id);
    if (!row?.runId || !isRunId(row.runId)) throw new HttpException('no screenshot', HttpStatus.NOT_FOUND);
    let buf: Buffer;
    try {
      buf = await readFile(insideDir(this.cfg.runsDir, row.runId, 'guest/screenshot.png'));
    } catch {
      throw new HttpException('no screenshot', HttpStatus.NOT_FOUND);
    }
    if (!isPng(buf) || buf.length > 32 << 20) throw new HttpException('screenshot is not a PNG', HttpStatus.UNPROCESSABLE_ENTITY);
    res.setHeader('Content-Type', 'image/png');
    res.send(buf);
  }

  @All('*path')
  notFound() {
    throw new HttpException('not found', HttpStatus.NOT_FOUND);
  }
}
