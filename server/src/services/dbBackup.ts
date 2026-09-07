import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getDb } from '../db/index.js';

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
const ALGORITHM = 'aes-256-gcm';
const MAGIC = Buffer.from('FREEAPI-BACKUP-V1\n', 'utf8');
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.resolve(__dirname, '../../data/freeapi.db');

function config() {
  const accessKeyId = process.env.FILEBASE_ACCESS_KEY?.trim();
  const secretAccessKey = process.env.FILEBASE_SECRET_KEY?.trim();
  const bucket = process.env.FILEBASE_BUCKET?.trim();
  const keyHex = process.env.FREEAPI_DB_BACKUP_KEY?.trim();
  if (!accessKeyId || !secretAccessKey || !bucket || !keyHex) return null;
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error('Invalid FREEAPI_DB_BACKUP_KEY: expected exactly 64 hex chars (32 bytes).');
  }
  const interval = Number(process.env.FREEAPI_DB_BACKUP_INTERVAL_MS ?? 300000);
  return {
    bucket,
    objectKey: process.env.FILEBASE_OBJECT_KEY?.trim() || 'freeapi/freeapi.db.enc.gz',
    key: Buffer.from(keyHex, 'hex'),
    intervalMs: Number.isFinite(interval) && interval >= 60000 ? interval : 300000,
    client: new S3Client({
      region: process.env.FILEBASE_REGION?.trim() || 'us-east-1',
      endpoint: process.env.FILEBASE_ENDPOINT?.trim() || 'https://s3.filebase.io',
      forcePathStyle: true,
      credentials: { accessKeyId, secretAccessKey },
    }),
  };
}

type BackupConfig = NonNullable<ReturnType<typeof config>>;

async function encryptBackup(data: Buffer, key: Buffer): Promise<Buffer> {
  const compressed = await gzip(data, { level: 9 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(compressed), cipher.final()]);
  return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), encrypted]);
}

async function decryptBackup(data: Buffer, key: Buffer): Promise<Buffer> {
  const headerLength = MAGIC.length + 12 + 16;
  if (data.length <= headerLength || !data.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('Invalid or unsupported database backup format.');
  }
  const ivStart = MAGIC.length;
  const tagStart = ivStart + 12;
  const encryptedStart = tagStart + 16;
  const decipher = crypto.createDecipheriv(ALGORITHM, key, data.subarray(ivStart, tagStart));
  decipher.setAuthTag(data.subarray(tagStart, encryptedStart));
  const compressed = Buffer.concat([
    decipher.update(data.subarray(encryptedStart)),
    decipher.final(),
  ]);
  return gunzip(compressed);
}

async function bodyToBuffer(body: unknown): Promise<Buffer> {
  if (!body) throw new Error('Backup object has an empty body.');
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof body === 'object' && body !== null && 'transformToByteArray' in body) {
    const bytes = await (body as { transformToByteArray: () => Promise<Uint8Array> }).transformToByteArray();
    return Buffer.from(bytes);
  }
  const chunks: Buffer[] = [];
  for await (const chunk of body as AsyncIterable<Uint8Array>) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function downloadBackup(cfg: BackupConfig): Promise<Buffer | null> {
  try {
    const response = await cfg.client.send(new GetObjectCommand({
      Bucket: cfg.bucket,
      Key: cfg.objectKey,
    }));
    return bodyToBuffer(response.Body);
  } catch (error) {
    const status = (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    const name = (error as { name?: string }).name;
    if (status === 404 || name === 'NoSuchKey' || name === 'NotFound') return null;
    throw error;
  }
}

async function uploadBackup(cfg: BackupConfig, payload: Buffer): Promise<void> {
  await cfg.client.send(new PutObjectCommand({
    Bucket: cfg.bucket,
    Key: cfg.objectKey,
    Body: payload,
    ContentType: 'application/octet-stream',
  }));
}

export async function restoreDbBackup(): Promise<void> {
  const cfg = config();
  if (!cfg) return;

  const backup = await downloadBackup(cfg);
  if (!backup) {
    console.log('[db-backup] No remote backup found; starting with local DB.');
    return;
  }

  await fs.mkdir(path.dirname(DB_PATH), { recursive: true });
  const tempPath = `${DB_PATH}.restore-${process.pid}`;
  try {
    await fs.writeFile(tempPath, await decryptBackup(backup, cfg.key), { mode: 0o600 });
    await fs.rename(tempPath, DB_PATH);
    console.log('[db-backup] Restored database from Filebase.');
  } catch (error) {
    await fs.rm(tempPath, { force: true }).catch(() => undefined);
    throw new Error(`[db-backup] Restore failed; refusing to start with an unverified database: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function createAndUploadBackup(): Promise<void> {
  const cfg = config();
  if (!cfg) return;
  const tempPath = `${DB_PATH}.backup-${process.pid}`;
  try {
    const db = getDb() as typeof getDb extends () => infer T ? T & { backup(path: string): Promise<unknown> } : never;
    if (typeof db.backup !== 'function') {
      throw new Error('Database driver does not support SQLite backup().');
    }
    await db.backup(tempPath);
    const sqliteFile = await fs.readFile(tempPath);
    await uploadBackup(cfg, await encryptBackup(sqliteFile, cfg.key));
    console.log('[db-backup] Filebase backup uploaded.');
  } catch (error) {
    console.error('[db-backup] Backup failed:', error);
  } finally {
    await fs.rm(tempPath, { force: true }).catch(() => undefined);
  }
}

export function startDbBackup(): void {
  const cfg = config();
  if (!cfg) {
    console.log('[db-backup] Filebase persistence disabled (Filebase + backup env vars not configured).');
    return;
  }
  setTimeout(() => void createAndUploadBackup(), 5000);
  const timer = setInterval(() => void createAndUploadBackup(), cfg.intervalMs);
  timer.unref?.();
  const shutdown = () => void createAndUploadBackup();
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
