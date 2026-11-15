"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload. An explicit `crc` may be
// passed to build an entry whose checksum matches its real decompressed output.
function craftBomb(declaredSize, method, content, crcValue) {
    const name = Buffer.from("a");
    const crc = crcValue || 0; // deliberately wrong by default: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Regression tests for GHSA-c6fg-446q-cg94:
// the synchronous getData() path caps inflation at the entry's declared
// uncompressed size (zlib maxOutputLength), but getDataAsync() streamed through
// zlib.createInflateRaw(), which ignores maxOutputLength, and returned the full
// output. A crafted entry holding a highly compressible payload whose declared
// size was rewritten to a tiny value (or 0) was inflated without limit, so
// callers that vet the declared size before reading had no protection.
describe("decompression bomb (async size cap) - GHSA-c6fg-446q-cg94", () => {
    const zlib = require("zlib");
    const Utils = require("../util");
    const nodeMajor = +process.versions.node.split(".")[0] || 0;

    // ~4 MiB of zeros deflates to a few KiB, so zlib emits many output chunks
    // while the entry claims to be tiny.
    const BOMB = Buffer.alloc(4 * 1024 * 1024);
    let bombDeflated;
    let bombCrc;

    before(() => {
        bombDeflated = zlib.deflateRawSync(BOMB);
        // a valid crc: the unpatched async path would hand back the full payload
        // with no error at all, exactly as in the advisory's proof of concept
        bombCrc = Utils.crc32(BOMB);
    });

    const lyingZip = (declaredSize) => new Zip(craftBomb(declaredSize, 8 /* DEFLATED */, bombDeflated, bombCrc));

    const check = (done, fn) => {
        try {
            fn();
            done();
        } catch (e) {
            done(e);
        }
    };

    const expectCapError = (data, err) => {
        expect(err, "async path must enforce the declared-size cap").to.be.an("error");
        expect(err.message).to.match(/exceeds the declared uncompressed size/);
        expect(data.length, "no decompressed output may be returned").to.equal(0);
    };

    it("getDataAsync fails when output exceeds a tiny declared size", (done) => {
        const entry = lyingZip(1).getEntries()[0];
        entry.getDataAsync((data, err) => check(done, () => expectCapError(data, err)));
    });

    it("getDataAsync fails when an entry declares size 0 but inflates to data", (done) => {
        const entry = lyingZip(0).getEntries()[0];
        entry.getDataAsync((data, err) => check(done, () => expectCapError(data, err)));
    });

    it("readFileAsync fails on an entry exceeding its declared size", (done) => {
        lyingZip(1).readFileAsync("a", (data, err) => check(done, () => expectCapError(data, err)));
    });

    it("readAsTextAsync fails on an entry exceeding its declared size", (done) => {
        lyingZip(1).readAsTextAsync("a", (data, err) => check(done, () => expectCapError(data, err)));
    });

    it("getData fails when an entry declares size 0 but inflates to data", function () {
        // the synchronous cap relies on zlib's maxOutputLength, available from Node 15
        if (nodeMajor < 15) this.skip();
        const entry = lyingZip(0).getEntries()[0];
        expect(() => entry.getData()).to.throw(RangeError);
    });

    it("getDataAsync still returns a legitimate multi-chunk DEFLATED entry", (done) => {
        const zip = new Zip();
        // larger than zlib's 16 KiB output chunk, and exactly at the declared size
        const payload = Buffer.from("hello world ".repeat(50000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        round.getEntry("d.txt").getDataAsync((data, err) =>
            check(done, () => {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
            })
        );
    });

    it("still reads an empty DEFLATED entry declaring size 0", (done) => {
        // crc32 of an empty buffer is 0
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.alloc(0)), 0));
        const entry = zip.getEntries()[0];
        expect(entry.getData().length).to.equal(0);
        entry.getDataAsync((data, err) =>
            check(done, () => {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
            })
        );
    });
});
