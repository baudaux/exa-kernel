#include "lfs_block.h"

#include <emscripten.h>

EM_JS(int, lfs_blk_read, (const struct lfs_config * c, lfs_block_t block,
			 lfs_off_t off, void * buffer, lfs_size_t size), {
  
	return Asyncify.handleSleep(function (wakeUp) {

	    window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    //console.log("*** lfs_blk_read: "+block);

	    let do_read = () => {

	      let store = Module.lfsDB.transaction(["blocks"]).objectStore("blocks");
	      
	      var request = store.get(block);
	      
	      request.onerror = function(event) {

		//console.log("*** lfs_blk_read: error");

		const buf3 = new Uint8Array(size);
		buf3.fill(0xFF);
		
		Module.HEAPU8.set(buf3, buffer);
		
		wakeUp(0);
	      };
	      
	      request.onsuccess = function(event) {

		//console.log(request.result);

		if (request.result) {

		  Module.HEAPU8.set(request.result.data, buffer);
		}

		wakeUp(0);
		
	      };
	    };

	    if (!Module.lfsDB) {
	      
	      let request = window.indexedDB.open("LocalFS", 1);

	      request.onerror = function(event) {

		//console.log("*** Error while opening indexedDB of LocalFS");

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		//console.log("*** Upgrade indexedDB of LocalFS");

		let db = event.target.result;

		db.createObjectStore("blocks", { keyPath: "block" });
	      };
	      
	      request.onsuccess = function(event) {

		//console.log("*** indexedDB of LocalFS opened");
		
		Module.lfsDB = event.target.result;

		do_read();
		
	      };
	    }
	    else {

	      do_read();
	    }

	  });
});

EM_JS(int, lfs_blk_prog, (const struct lfs_config * c, lfs_block_t block,
			  lfs_off_t off, const void * buffer, lfs_size_t size), {

	return Asyncify.handleSleep(function (wakeUp) {

	    if (!window.indexedDB)
	      return -1;

	    let do_prog = () => {

	      let store = Module.lfsDB.transaction(["blocks"], "readwrite").objectStore("blocks");

	      let request = store.put({block: block, data: Module.HEAPU8.subarray(buffer, buffer+size)});
	      
	      request.onerror = function(event) {

		//console.log("*** lfs_blk_erase: error");
		
		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		wakeUp(0);
	      };

	    };

	    if (!Module.lfsDB) {
	      
	      let request = window.indexedDB.open("LocalFS", 1);

	      request.onerror = function(event) {

		//console.log("*** Error while opening indexedDB of LocalFS");

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		//console.log("*** Upgrade indexedDB of LocalFS");

		let db = event.target.result;

		db.createObjectStore("blocks", { keyPath: "block" });
	      };
	      
	      request.onsuccess = function(event) {

		//console.log("*** indexedDB of LocalFS opened");
		
		Module.lfsDB = event.target.result;

		do_prog();
		
	      };
	    }
	    else {

	      do_prog();
	    }

	  }); 
});

EM_JS(int, lfs_blk_erase, (const struct lfs_config * c, lfs_block_t block), {

    return Asyncify.handleSleep(function (wakeUp) {

	if (!window.indexedDB)
	  return -1;

	//console.log("*** lfs_blk_erase: "+block);

	let do_erase = () => {

	  let store = Module.lfsDB.transaction(["blocks"], "readwrite").objectStore("blocks");

	  const buf3 = new Uint8Array(4096);
	  buf3.fill(0xFF);

	  let request = store.put({block: block, data: buf3});
	      
	  request.onerror = function(event) {

	    //console.log("*** lfs_blk_erase: error");
		
	    wakeUp(-1);
	  };
	      
	  request.onsuccess = function(event) {

	    wakeUp(0);
	  };

	};

	if (!Module.lfsDB) {
	      
	      let request = window.indexedDB.open("LocalFS", 1);

	      request.onerror = function(event) {

		//console.log("*** Error while opening indexedDB of LocalFS");

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		//console.log("*** Upgrade indexedDB of LocalFS");

		let db = event.target.result;

		db.createObjectStore("blocks", { keyPath: "block" });
	      };
	      
	      request.onsuccess = function(event) {

		//console.log("*** indexedDB of LocalFS opened");
		
		Module.lfsDB = event.target.result;

		do_erase();
		
	      };
	    }
	    else {

	      do_erase();
	    }
	
    });
  
});

int lfs_blk_sync(const struct lfs_config *c) {

  //emscripten_log(EM_LOG_CONSOLE,"*** lfs_blk_sync");
  
  return 0;
}
