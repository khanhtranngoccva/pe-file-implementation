const {ArgumentParser} = require("argparse");
const parser = new ArgumentParser();
parser.add_argument("--input", {
    help: "Input file",
    type: "string",
    required: true,
});
parser.add_argument("--output", {
    help: "Output file",
    type: "string",
    required: true,
});
parser.add_argument("--rel-jump-filename", {
    help: "File containing a number for relative jump. ",
    type: "string",
    required: false,
});
parser.add_argument("--architecture", {
    help: "Architecture (x64 or x86)",
    choices: ["x64", "x86"],
    required: true,
});
const args = parser.parse_args();

const fs = require("fs").promises;

class Segment {
    type;
    data;

    constructor(type, data) {
        this.type = type;
        this.data = data;
    }

    toString() {
        return `${this.type}\tSEGMENT\r\n${this.data}\r\n${this.type}\tENDS`
    }
}

function parseSimpleSegment(lines) {
    let currentSegment = null;
    let currentLines = [];
    let res = [];

    function push() {
        if (!currentLines.length) return;
        if (!currentSegment) res.push(currentLines.join("\r\n"));
        else {
            res.push(new Segment(currentSegment, currentLines.join("\r\n")))
        }
        currentLines = [];
        currentSegment = null;
    }

    const startRgx = /^(\w+)\tSEGMENT(\s+;.*)?/;
    const endRgx = /^(\w+)\tENDS(\s+;.*)?/;

    for (let line of lines) {
        const startMatches = line.match(startRgx);
        const endMatches = line.match(endRgx);
        if (!startMatches && !endMatches) {
            currentLines.push(line);
            continue;
        }
        let segmentName;
        if (!currentSegment) {
            segmentName = startMatches?.[1];
            if (!segmentName) {
                throw new Error("Parsing failure")
            }
            push();
            currentSegment = segmentName;
        } else {
            segmentName = endMatches?.[1];
            if (!segmentName || segmentName !== currentSegment) {
                throw new Error("Parsing failure - segment end name mismatch.")
            }
            push();
        }
    }
    push();
    return res;
}

function getAlignRSP(architecture) {
    const ALIGN_RSP_64 = `AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP`;
    const ALIGN_RSP_86 = `AlignRSP PROC
    push esi ; Preserve RSI since we're stomping on it
    mov esi, esp ; Save the value of RSP so it can be restored
    and esp, 0FFFFFF0h ; Align RSP to 16 bytes
    sub esp, 020h ; Allocate homing space for ExecutePayload
    call _main ; Call the entry point of the payload
    mov esp, esi ; Restore the original value of RSP
    pop esi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP`;
    return architecture === "x86" ? ALIGN_RSP_86 : ALIGN_RSP_64;
}

async function getRelJumpLength(filename) {
    const string = (await fs.readFile(filename)).toString();
    return Number(string);
}

async function getRelJumpCode(architecture, filename) {
    if (architecture === "x86") {
        return `
    lea eax, AlignRSP
    sub eax, ${filename ? await getRelJumpLength(filename) : 0xDEADBEEF}
    push eax
    xor eax, eax
    ret\t0`;
    } else {
        return `
    lea rax, AlignRSP
    sub rax, ${filename ? await getRelJumpLength(filename) : 0xDEADBEEF}
    push rax
    xor rax, rax
    ret\t0`;
    }
}

async function patch(filename, output, architecture, relJumpFilename) {
    const data = (await fs.readFile(filename)).toString().split(/\r\n/);
    const stage1 = data.filter(l => !/^INCLUDELIB .*$/.test(l));
    const stage2 = stage1.join("\r\n")
        .replace("mov\trax, QWORD PTR gs:96", "mov\trax, QWORD PTR gs:[96]")
        .replace("mov\teax, DWORD PTR fs:48", "ASSUME FS:NOTHING\r\n" +
            "    mov\teax, DWORD PTR fs:[48]\r\n" +
            "    ASSUME FS:ERROR")
        .split("\r\n");
    const stage3 = parseSimpleSegment(stage2).filter(token => {
        if (typeof token === "string") return true;
        const segmentsToRemove = ["pdata", "xdata"];
        return !segmentsToRemove.includes(token.type.toLowerCase());
    });
    const firstTextSeg = stage3.find(s => s instanceof Segment && s.type === "_TEXT");
    if (!firstTextSeg) {
        throw new Error("First text segment not found.");
    }
    firstTextSeg.data = getAlignRSP(architecture) + "\r\n" + firstTextSeg.data;

    const firstTextSegLines = firstTextSeg.data.split("\r\n");
    const endp = firstTextSegLines.findIndex(l => {
        return l === "main\tENDP" || l === "_main\tENDP";
    });
    if (endp === -1) {
        throw new Error("Endproc not found!");
    }
    firstTextSegLines[endp - 1] = await getRelJumpCode(architecture, relJumpFilename);
    firstTextSeg.data = firstTextSegLines.join("\r\n");

    const final = stage3.join("\r\n");
    await fs.writeFile(output, final);
}

const input = args.input;
const output = args.output;
const relJumpFilename = args.rel_jump_filename;
const architecture = args.architecture;

patch(input, output, architecture, relJumpFilename).then();
