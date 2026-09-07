import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { gzipSync, gunzipSync } from 'node:zlib';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type Database from 'better-sqlite3';
import { getDb } from '../db/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DB_PATH = path.resolve(__dirname, '../../data/freellmapi.db');
const BACKUP_MAGIC = Buffer.from('FREEAPI-BACKUP-V1\n', 'utf8');

function key(): Buffer {
  const value = process.env.FREEAPI_DB_BACKUP_KEY || process.env.ENCRYPTION_KEY;
  if (!value) throw new Error('FREEAPI_DB_BACKUP_KEY or ENCRYPTION_KEY is required for DB backup');
  return /^[0-9a-fA-F]{64}$/.test(value) ? Buffer.from(value, 'hex') : createHash('sha256').update(value).digest();
}

function backupPath(): string {
  return process.env.FREEAPI_DB_BACKUP_PATH?.trim() || path.resolve(path.dirname(dbPath()), 'freellmapi.db.backup');
}

function dbPath(): string {
  return process.env.FREEAPI_DB_PATH?.trim() || DEFAULT_DB_PATH;
}

function encrypt(data: Buffer): Buffer {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), nonce);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([BACKUP_MAGIC, nonce, cipher.getAuthTag(), ciphertext]);
}

function decrypt(data: Buffer): Buffer {
  if (!data.subarray(0, BACKUP_MAGIC.length).equals(BACKUP_MAGIC)) throw new Error('Invalid backup format');
  const offset = BACKUP_MAGIC.length;
  const nonce = data.subarray(offset, offset + 12);
  const tag = data.subarray(offset + 12, offset + 28);
  const ciphertext = data.subarray(offset + 28);
  const decipher = createDecipheriv('aes-256-gcm', key(), nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function objectKey(): string { return process.env.FILEBASE_OBJECT_KEY?.trim() || 'freellmapi.db.backup'; }

function s3Client(): S3Client {
  const endpoint = process.env.FILEBASE_ENDPOINT?.trim();
  const region = process.env.FILEBASE_REGION?.trim() || 'us-east-1';
  return new S3Client({
    region,
    endpoint,
    forcePathStyle: true,
    credentials: {
      accessKeyId: process.env.FILEBASE_ACCESS_KEY || '',
      secretAccessKey: process.env.FILEBASE_SECRET_KEY || '',
    },
  });
}

function filebaseConfigured(): boolean {
  return Boolean(process.env.FILEBASE_ACCESS_KEY && process.env.FILEBASE_SECRET_KEY && process.env.FILEBASE_BUCKET);
}

async function downloadBackup(): Promise<Buffer | null> {
  if (filebaseConfigured()) {
    const response = await s3Client().send(new GetObjectCommand({ Bucket: process.env.FILEBASE_BUCKET, Key: objectKey() }));
    if (!response.Body) return null;
    return Buffer.from(await response.Body.transformToByteArray());
  }
  const target = backupPath();
  if (!fs.existsSync(target)) return null;
  return fs.readFileSync(target);
}

async function uploadBackup(payload: Buffer): Promise<void> {
  if (filebaseConfigured()) {
    await s3Client().send(new PutObjectCommand({
      Bucket: process.env.FILEBASE_BUCKET,
      Key: objectKey(),
      Body: payload,
      ContentType: 'application/octet-stream',
    }));
    return;
  }
  fs.mkdirSync(path.dirname(backupPath()), { recursive: true });
  fs.writeFileSync(backupPath(), payload, { mode: 0o600 });
}

export async function restoreDbBackup(): Promise<void> {
  if (fs.existsSync(dbPath())) return;
  try {
    const encrypted = await downloadBackup();
    if (!encrypted) return;
    const plain = gunzipSync(decrypt(encrypted));
    fs.mkdirSync(path.dirname(dbPath()), { recursive: true });
    fs.writeFileSync(dbPath(), plain, { mode: 0o600 });
    console.log('Database restored from backup');
  } catch (error) {
    console.warn('Database backup restore skipped:', error);
  }
}

export async function backupDb(): Promise<void> {
  try {
    const db: Database.Database = getDb();
    const temp = `${dbPath()}.backup.tmp`;
    await db.backup(temp);
    const plain = fs.readFileSync(temp);
    fs.rmSync(temp, { force: true });
    await uploadBackup(encrypt(gzipSync(plain)));
    console.log('Database backup uploaded');
  } catch (error) {
    console.warn('Database backup failed:', error);
  }
}

export function startDbBackup(): void {
  const interval = Number(process.env.FREEAPI_DB_BACKUP_INTERVAL_MS || 300000);
  if (!Number.isFinite(interval) || interval <= 0) return;
  void backupDb();
  const timer = setInterval(() => void backupDb(), interval);
  timer.unref?.();
}
