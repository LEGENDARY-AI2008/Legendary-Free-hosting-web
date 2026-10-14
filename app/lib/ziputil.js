'use strict';

/*
 * Minimal, strict ZIP extractor (no dependencies).
 *
 * It reads the central directory, validates every entry BEFORE writing
 * anything, and refuses anything unusual: encryption, ZIP64, symlinks,
 * special files, absolute paths, "..", backslashes, duplicate names,
 * oversized or too many files, and inflated sizes that differ from the
 * declared size (zip bombs).
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

class ZipError extends Error {}

const SIG_EOCD = 0x06054b50;
const SIG_CEN = 0x02014b50;
const SIG_LOC = 0x04034b50;

const DEFAULT_LIMITS = {
  maxFiles: 2000,
  maxTotalBytes: 100 * 1024 * 1024,
  maxFileBytes: 50 * 1024 * 1024,
  maxPathLength: 240,
  maxDepth: 20
};

const SKIP_TOP_LEVEL = new Set(['__MACOSX', '.git']);

function findEocd(buf) {
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

function cleanName(raw, limits) {
  if (raw.length === 0 || raw.length > limits.maxPathLength) {
    throw new ZipError('The ZIP contains a file name that is empty or too long.');
  }
  if (raw.includes('\0') || raw.includes('\\')) {
    throw new ZipError('The ZIP contains an unsafe file name.');
  }
  if (raw.startsWith('/') || /^[a-zA-Z]:/.test(raw)) {
    throw new ZipError('The ZIP contains an absolute path, which is not allowed.');
  }

  const isDir = raw.endsWith('/');
  const parts = [];
  for (const part of raw.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      throw new ZipError('The ZIP contains a path that tries to leave its folder.');
    }
    parts.push(part);
  }
  if (parts.length > limits.maxDepth) {
    throw new ZipError('The ZIP has folders nested too deeply.');
  }
  return { parts, isDir };
}

function extractZip(buffer, destDir, userLimits) {
  const limits = Object.assign({}, DEFAULT_LIMITS, userLimits || {});

  if (!Buffer.isBuffer(buffer) || buffer.length < 22) {
    throw new ZipError('That does not look like a ZIP file.');
  }

  const eocd = findEocd(buffer);
  if (eocd < 0) throw new ZipError('That does not look like a valid ZIP file.');

  const totalEntries = buffer.readUInt16LE(eocd + 10);
  const cdSize = buffer.readUInt32LE(eocd + 12);
  const cdOffset = buffer.readUInt32LE(eocd + 16);

  if (totalEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    throw new ZipError('ZIP64 archives are not supported.');
  }
  if (totalEntries === 0) throw new ZipError('The ZIP is empty.');
  if (totalEntries > limits.maxFiles) {
    throw new ZipError('The ZIP contains too many files (limit ' + limits.maxFiles + ').');
  }
  if (cdOffset + cdSize > eocd) throw new ZipError('The ZIP is damaged.');

  // ---- Pass 1: read and validate every entry; write nothing yet. ----
  const entries = [];
  const seen = new Set();
  let declaredTotal = 0;
  let pos = cdOffset;

  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > buffer.length || buffer.readUInt32LE(pos) !== SIG_CEN) {
      throw new ZipError('The ZIP is damaged.');
    }

    const versionMadeBy = buffer.readUInt16LE(pos + 4);
    const flags = buffer.readUInt16LE(pos + 8);
    const method = buffer.readUInt16LE(pos + 10);
    const crc = buffer.readUInt32LE(pos + 16);
    const compSize = buffer.readUInt32LE(pos + 20);
    const uncompSize = buffer.readUInt32LE(pos + 24);
    const nameLen = buffer.readUInt16LE(pos + 28);
    const extraLen = buffer.readUInt16LE(pos + 30);
    const commentLen = buffer.readUInt16LE(pos + 32);
    const externalAttrs = buffer.readUInt32LE(pos + 38);
    const localOffset = buffer.readUInt32LE(pos + 42);

    const nameEnd = pos + 46 + nameLen;
    if (nameEnd > buffer.length) throw new ZipError('The ZIP is damaged.');
    const rawName = buffer.toString('utf8', pos + 46, nameEnd);
    pos = nameEnd + extraLen + commentLen;

    if (flags & 0x1) throw new ZipError('Encrypted ZIP files are not supported.');
    if (compSize === 0xffffffff || uncompSize === 0xffffffff || localOffset === 0xffffffff) {
      throw new ZipError('ZIP64 archives are not supported.');
    }

    const { parts, isDir } = cleanName(rawName, limits);
    if (parts.length === 0) continue;
    if (SKIP_TOP_LEVEL.has(parts[0])) continue;

    // Unix file type lives in the high 16 bits when the archive came from Unix.
    if ((versionMadeBy >> 8) === 3) {
      const mode = externalAttrs >>> 16;
      const type = mode & 0o170000;
      if (type !== 0 && type !== 0o100000 && type !== 0o040000) {
        throw new ZipError('The ZIP contains links or special files, which are not allowed.');
      }
    }

    if (!isDir) {
      if (method !== 0 && method !== 8) {
        throw new ZipError('The ZIP uses an unsupported compression method.');
      }
      if (uncompSize > limits.maxFileBytes) {
        throw new ZipError('A file in the ZIP is too large.');
      }
      declaredTotal += uncompSize;
      if (declaredTotal > limits.maxTotalBytes) {
        throw new ZipError('The ZIP expands to more than ' +
          Math.round(limits.maxTotalBytes / 1024 / 1024) + ' MB.');
      }
    }

    const key = parts.join('/');
    if (seen.has(key)) throw new ZipError('The ZIP contains duplicate file names.');
    seen.add(key);

    entries.push({ parts, isDir, method, crc, compSize, uncompSize, localOffset });
  }

  if (entries.length === 0) throw new ZipError('The ZIP has no usable files.');

  // A file and a folder with the same prefix would collide on disk.
  for (const e of entries) {
    for (let n = 1; n < e.parts.length; n++) {
      const prefix = e.parts.slice(0, n).join('/');
      const clash = entries.find(o => !o.isDir && o.parts.join('/') === prefix);
      if (clash) throw new ZipError('The ZIP has a file and a folder with the same name.');
    }
  }

  // ---- Pass 2: extract. ----
  const root = path.resolve(destDir);
  fs.mkdirSync(root, { recursive: true });

  let fileCount = 0;
  let byteCount = 0;

  for (const e of entries) {
    const target = path.resolve(root, ...e.parts);
    if (target !== root && !target.startsWith(root + path.sep)) {
      throw new ZipError('The ZIP contains a path that tries to leave its folder.');
    }

    if (e.isDir) {
      fs.mkdirSync(target, { recursive: true });
      continue;
    }

    const lo = e.localOffset;
    if (lo + 30 > buffer.length || buffer.readUInt32LE(lo) !== SIG_LOC) {
      throw new ZipError('The ZIP is damaged.');
    }
    const lNameLen = buffer.readUInt16LE(lo + 26);
    const lExtraLen = buffer.readUInt16LE(lo + 28);
    const start = lo + 30 + lNameLen + lExtraLen;
    const end = start + e.compSize;
    if (end > buffer.length) throw new ZipError('The ZIP is damaged.');

    const comp = buffer.subarray(start, end);
    let data;
    if (e.method === 0) {
      data = Buffer.from(comp);
    } else {
      try {
        data = zlib.inflateRawSync(comp, { maxOutputLength: Math.max(1, e.uncompSize) });
      } catch (err) {
        throw new ZipError('A file in the ZIP is damaged or larger than it claims.');
      }
    }

    if (data.length !== e.uncompSize) {
      throw new ZipError('A file in the ZIP does not match its declared size.');
    }
    if (typeof zlib.crc32 === 'function' && (zlib.crc32(data) >>> 0) !== (e.crc >>> 0)) {
      throw new ZipError('A file in the ZIP failed its integrity check.');
    }

    byteCount += data.length;
    if (byteCount > limits.maxTotalBytes) {
      throw new ZipError('The ZIP expands to more than ' +
        Math.round(limits.maxTotalBytes / 1024 / 1024) + ' MB.');
    }

    fs.mkdirSync(path.dirname(target), { recursive: true });
    // 'wx' refuses to overwrite or follow an existing path.
    fs.writeFileSync(target, data, { flag: 'wx', mode: 0o644 });
    fileCount++;
  }

  return { files: fileCount, bytes: byteCount };
}

module.exports = { extractZip, ZipError, DEFAULT_LIMITS };
