function convert(str) {
    return "{" + [...str].map(c => `'${c}'`).join(", ") + "};"
}


console.log(convert(process.argv[2]))