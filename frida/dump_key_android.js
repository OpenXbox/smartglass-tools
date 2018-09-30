var SMARTGLASSCORE_LIB = "libSmartGlassCore.so";
var xCryptKDFInterop = "xCryptLibKDF_Interop";

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

/*########################## 
 *## CORE - SHARED SECRET ##
 ###########################*/

// Core Protocol - Shared key
Interceptor.attach(Module.findExportByName(SMARTGLASSCORE_LIB, xCryptKDFInterop), {
	onEnter: function (args) {
        this.dst = args[1];
        this.size = args[2].toInt32();
	},
	onLeave: function (retval) {
		var data = Memory.readByteArray(this.dst, this.size);
		var hexbytes = bytesToString(data);
		console.log("Shared Secret: " + hexbytes);
	}
});