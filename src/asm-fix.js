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

const ALIGN_RSP = `; https://github.com/mattifestation/PIC_Bindshell/blob/master/PIC_Bindshell/AdjustStack.asm

; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload. This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment. When amd64
; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers (which require 16-byte)
; alignment.

AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP`

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


async function patch(filename, output) {
    const data = (await fs.readFile(filename)).toString().split(/\r\n/);
    const stage1 = data.filter(l => !/^INCLUDELIB .*$/.test(l));
    const stage2 = stage1.join("\r\n").replace("mov\trax, QWORD PTR gs:96", "mov\trax, QWORD PTR gs:[96]").split("\r\n");
    const stage3 = parseSimpleSegment(stage2).filter(token => {
        if (typeof token === "string") return true;
        const segmentsToRemove = ["pdata", "xdata"];
        return !segmentsToRemove.includes(token.type.toLowerCase());
    });
    const firstTextSeg = stage3.find(s => s instanceof Segment && s.type === "_TEXT");
    if (!firstTextSeg) {
        throw new Error("First text segment not found.");
    }
    firstTextSeg.data = ALIGN_RSP + "\r\n" + firstTextSeg.data;
    const final = stage3.join("\r\n");
    await fs.writeFile(output, final);
}

patch(process.argv[2], process.argv[3])