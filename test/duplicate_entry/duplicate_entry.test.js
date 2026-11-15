"use strict";

// GHSA-p634-w6r4-rjp2: a ZIP archive can declare the same entry name twice.
// adm-zip kept both entries in its entry list but only the last one in its
// name lookup table, so getEntry()/readFile() (table) and extractAllTo() (list)
// resolved one name to different content: an application validating a named
// entry before extracting could approve one file while another lands on disk.
// Such archives are now rejected when the central directory is read.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

// Builds an archive holding "a.txt" ("FIRST") and "b.txt" ("SECOND"), then
// rewrites the raw name bytes of "a.txt" to "b.txt" (local header + central
// directory record), so the archive declares "b.txt" twice with different
// content - the advisory's proof of concept.
function duplicateNameArchive() {
    const zip = new Zip();
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const buf = Buffer.from(zip.toBuffer());
    const from = Buffer.from("a.txt");
    const to = Buffer.from("b.txt");
    let replaced = 0;
    for (let idx = buf.indexOf(from); idx !== -1; idx = buf.indexOf(from, idx + to.length)) {
        to.copy(buf, idx);
        replaced++;
    }
    assert.strictEqual(replaced, 2);
    return buf;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    let destination;

    beforeEach(() => {
        destination = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-dup-"));
    });

    afterEach(() => {
        rimraf.sync(destination);
    });

    it("getEntry(), readFile() and getEntries() reject an archive declaring a name twice", () => {
        assert.throws(() => new Zip(duplicateNameArchive(), { noSort: true }).getEntry("b.txt"), /Duplicate entry name/);
        assert.throws(() => new Zip(duplicateNameArchive(), { noSort: true }).readFile("b.txt"), /Duplicate entry name/);
        assert.throws(() => new Zip(duplicateNameArchive()).getEntries(), /Duplicate entry name/);
    });

    it("rejects the archive at construction when entries are read eagerly", () => {
        assert.throws(() => new Zip(duplicateNameArchive(), { readEntries: true }), /Duplicate entry name/);
    });

    it("validate-then-extract cannot approve one content while another lands on disk", () => {
        const zip = new Zip(duplicateNameArchive(), { noSort: true });
        assert.throws(() => {
            // application checks the named entry, then extracts the whole archive
            const approved = zip.readFile("b.txt");
            if (approved && approved.toString() === "SECOND") {
                zip.extractAllTo(destination, false);
            }
        }, /Duplicate entry name/);
        assert.strictEqual(fs.existsSync(pth.join(destination, "b.txt")), false);
    });

    it("extractAllTo() rejects the archive and writes nothing", () => {
        const zip = new Zip(duplicateNameArchive(), { noSort: true });
        assert.throws(() => zip.extractAllTo(destination, false), /Duplicate entry name/);
        assert.deepStrictEqual(fs.readdirSync(destination), []);
    });

    it("extractAllToAsync() rejects the archive and writes nothing", async () => {
        const zip = new Zip(duplicateNameArchive(), { noSort: true });
        await assert.rejects(zip.extractAllToAsync(destination, false), /Duplicate entry name/);
        assert.deepStrictEqual(fs.readdirSync(destination), []);
    });

    it("still reads distinct names that collide with Object.prototype keys", () => {
        const names = ["__proto__", "constructor", "hasOwnProperty", "toString", "valueOf", "a.txt"];
        const zip = new Zip();
        names.forEach((name) => zip.addFile(name, Buffer.from(name)));
        const reopened = new Zip(zip.toBuffer());
        assert.strictEqual(reopened.getEntries().length, names.length);
        names.forEach((name) => {
            assert.strictEqual(reopened.readFile(name).toString(), name);
        });
    });
});
