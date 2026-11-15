"use strict";

// CVE-2026-76845: extraction only sanitized the entry name textually, so a
// symlink that already existed inside the target directory was followed by
// open()/mkdir() and the archive content landed outside the target. Every
// extraction path now rejects a target whose path below the root crosses a
// symbolic link (or, on Windows, a directory junction).

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

// Creating links can be refused by the platform (e.g. file symlinks on Windows
// without the required privilege); such tests are skipped instead of failing.
function tryLink(target, path, type) {
    try {
        fs.symlinkSync(target, path, type);
        return true;
    } catch (e) {
        if (["EPERM", "EACCES", "ENOSYS", "UNKNOWN"].indexOf(e.code) !== -1) return false;
        throw e;
    }
}

// directory links use a junction on Windows (no privilege needed); the type is
// ignored on other platforms, where a plain symlink is created
const linkDir = (target, path) => tryLink(target, path, "junction");
const linkFile = (target, path) => tryLink(target, path, "file");

function archive(entries) {
    const zip = new Zip();
    entries.forEach((e) => zip.addFile(e[0], e[1] === null ? null : Buffer.from(e[1])));
    return new Zip(zip.toBuffer());
}

describe("ADM-ZIP - extraction through pre-existing symlinks (CVE-2026-76845)", () => {
    let base, root, outside;

    beforeEach(() => {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        root = pth.join(base, "extract");
        outside = pth.join(base, "outside");
        fs.mkdirSync(root);
        fs.mkdirSync(outside);
    });

    afterEach(() => {
        rimraf.sync(base);
    });

    it("extractAllTo() refuses to write a file through a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([["evil/pwned.txt", "PWNED"]]);

        assert.throws(() => zip.extractAllTo(root, true), /There is a file in the way/);
        assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
    });

    it("extractAllTo() refuses to create a directory through a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([["evil/sub/", null]]);

        assert.throws(() => zip.extractAllTo(root, true), /There is a file in the way/);
        assert.strictEqual(fs.existsSync(pth.join(outside, "sub")), false);
    });

    it("extractAllTo() refuses to overwrite a file symlink pointing outside the target", function () {
        const victim = pth.join(outside, "victim.txt");
        fs.writeFileSync(victim, "ORIGINAL");
        if (!linkFile(victim, pth.join(root, "victim.txt"))) this.skip();
        const zip = archive([["victim.txt", "PWNED"]]);

        assert.throws(() => zip.extractAllTo(root, true), /There is a file in the way/);
        assert.strictEqual(fs.readFileSync(victim, "utf8"), "ORIGINAL");
    });

    it("extractAllTo() refuses to write through a dangling file symlink", function () {
        const created = pth.join(outside, "created.txt");
        if (!linkFile(created, pth.join(root, "dangling.txt"))) this.skip();
        const zip = archive([["dangling.txt", "PWNED"]]);

        assert.throws(() => zip.extractAllTo(root, false), /There is a file in the way/);
        assert.strictEqual(fs.existsSync(created), false);
    });

    it("extractEntryTo() refuses to write a file entry through a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([["evil/pwned.txt", "PWNED"]]);

        assert.throws(() => zip.extractEntryTo("evil/pwned.txt", root, true, true), /There is a file in the way/);
        assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
    });

    it("extractEntryTo() refuses an outFileName that crosses a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([["a.txt", "PWNED"]]);

        assert.throws(() => zip.extractEntryTo("a.txt", root, false, true, false, "evil/renamed.txt"), /There is a file in the way/);
        assert.strictEqual(fs.existsSync(pth.join(outside, "renamed.txt")), false);
    });

    it("extractEntryTo() refuses directory children written through a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([
            ["evil/", null],
            ["evil/pwned.txt", "PWNED"]
        ]);

        assert.throws(() => zip.extractEntryTo("evil/", root, true, true), /There is a file in the way/);
        assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
    });

    // this.skip() is called synchronously, before any promise is created
    it("extractAllToAsync() refuses to write a file through a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([["evil/pwned.txt", "PWNED"]]);

        return assert.rejects(zip.extractAllToAsync(root, true), /There is a file in the way/).then(() => {
            assert.strictEqual(fs.existsSync(pth.join(outside, "pwned.txt")), false);
        });
    });

    it("extractAllToAsync() refuses to create a directory through a symlinked directory", function () {
        if (!linkDir(outside, pth.join(root, "evil"))) this.skip();
        const zip = archive([["evil/sub/", null]]);

        return assert.rejects(zip.extractAllToAsync(root, true), /Unable to create folder/).then(() => {
            assert.strictEqual(fs.existsSync(pth.join(outside, "sub")), false);
        });
    });

    it("extractAllToAsync() refuses to overwrite a file symlink pointing outside the target", function () {
        const victim = pth.join(outside, "victim.txt");
        fs.writeFileSync(victim, "ORIGINAL");
        if (!linkFile(victim, pth.join(root, "victim.txt"))) this.skip();
        const zip = archive([["victim.txt", "PWNED"]]);

        return assert.rejects(zip.extractAllToAsync(root, true), /There is a file in the way/).then(() => {
            assert.strictEqual(fs.readFileSync(victim, "utf8"), "ORIGINAL");
        });
    });

    it("still extracts when the target directory itself is reached through a symlink", function () {
        const linkedRoot = pth.join(base, "linked-root");
        if (!linkDir(root, linkedRoot)) this.skip();
        const zip = archive([
            ["dir/", null],
            ["dir/a.txt", "content"],
            ["b.txt", "content"]
        ]);

        zip.extractAllTo(linkedRoot, true);
        assert.strictEqual(fs.readFileSync(pth.join(root, "dir", "a.txt"), "utf8"), "content");
        assert.strictEqual(fs.readFileSync(pth.join(root, "b.txt"), "utf8"), "content");
    });

    it("still extracts next to an unrelated symlink inside the target", function () {
        if (!linkDir(outside, pth.join(root, "other"))) this.skip();
        const zip = archive([
            ["safe/", null],
            ["safe/a.txt", "content"]
        ]);

        zip.extractAllTo(root, true);
        assert.strictEqual(fs.readFileSync(pth.join(root, "safe", "a.txt"), "utf8"), "content");
        rimraf.sync(pth.join(root, "safe"));
        return zip.extractAllToAsync(root, true).then(() => {
            assert.strictEqual(fs.readFileSync(pth.join(root, "safe", "a.txt"), "utf8"), "content");
            assert.deepStrictEqual(fs.readdirSync(outside), []);
        });
    });
});
