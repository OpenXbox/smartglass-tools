var SMARTGLASSCORE_LIB = "Microsoft.Xbox.SmartGlass.dll";
var libSmartGlassCoreBaseAddr = 0;
var ShiftBy = 0xC00;
var kdfInterop = 0x1A76B0;
var libSmartGlassCoreBaseAddr = Module.findBaseAddress(SMARTGLASSCORE_LIB);

function bytesToString(bytes) {
	var array = new Uint8Array(bytes);
	var str = "";
	for (var i=0; i<array.length; i++){
		var tmp = array[i].toString(16);
		if (tmp.length < 2){
			tmp = "0" + tmp;
		}
		str += tmp;
	}
	return str;
}

var toHook = libSmartGlassCoreBaseAddr.add(kdfInterop + ShiftBy);
Interceptor.attach(toHook, {
	onEnter: function(args){
		this.dst = args[1];
		this.size = args[2].toInt32();
	},
	onLeave: function(retval){
		var data = Memory.readByteArray(this.dst, this.size);
		var hexbytes = bytesToString(data);
		console.log("SharedSecret: " + hexbytes);
	}
});