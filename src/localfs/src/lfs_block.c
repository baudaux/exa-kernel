#include "lfs_block.h"

#include <emscripten.h>

EM_JS(int, lfs_blk_read, (const struct lfs_config * c, lfs_block_t block,
			 lfs_off_t off, void * buffer, lfs_size_t size), {

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;
  
	return Asyncify.handleSleep(function (wakeUp) {

	    //console.log("*** lfs_blk_read: "+block);

	    let do_read = () => {

	      let store = Module.lfsDB.transaction(["blocks"]).objectStore("blocks");
	      
	      var request = store.get(block);
	      
	      request.onerror = function(event) {

		//console.log("*** lfs_blk_read: error");
		
		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		//console.log(request.result);

		if (request.result) {

		  Module.HEAPU8.set(request.result.data.slice(off, off+size), buffer);
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


	if (!window.indexedDB)
	  return -1;

	return Asyncify.handleSleep(function (wakeUp) {

	    //console.log("*** lfs_blk_prog: "+block);

	    let store = Module.lfsDB.transaction(["blocks"], "readwrite").objectStore("blocks");

	    let request = store.get(block);
	      
	    request.onerror = function(event) {

	      //console.log("*** lfs_blk_prog: error");
		
	      wakeUp(-1);
	    };
	      
	    request.onsuccess = function(event) {

	      if (request.result) {

		request.result.data.set(Module.HEAPU8.slice(buffer, buffer+size), off);

		let requestUpdate = store.put(request.result);
		
		  requestUpdate.onerror = function(event) {

		  wakeUp(-1);
		  };
		
		  requestUpdate.onsuccess = function(event) {

		  wakeUp(0);
		  };
	      }
	      else {

		let data = new Uint8Array(4096);

		data.set(Module.HEAPU8.slice(buffer, buffer+size), off);

		let requestUpdate = store.add({block: block, data: data});
		
		requestUpdate.onerror = function(event) {

		  wakeUp(-1);
		};
		
		requestUpdate.onsuccess = function(event) {

		  wakeUp(0);
		};
	      }
	    };
	  });
});

EM_JS(int, lfs_blk_erase, (const struct lfs_config * c, lfs_block_t block), {

    if (!window.indexedDB)
      return -1;

    return Asyncify.handleSleep(function (wakeUp) {

	//console.log("*** lfs_blk_erase: "+block);

	let store = Module.lfsDB.transaction(["blocks"], "readwrite").objectStore("blocks");

	let request = store.get(block);
	      
	request.onerror = function(event) {

	  //console.log("*** lfs_blk_erase: error");
		
	  wakeUp(-1);
	};
	      
	request.onsuccess = function(event) {

	  if (request.result) {

	    request.result.data = new Uint8Array(4096);

	    let requestUpdate = store.put(request.result);
		
	    requestUpdate.onerror = function(event) {

	      wakeUp(-1);
	    };
		
	    requestUpdate.onsuccess = function(event) {

	      wakeUp(0);
	      };
	  }
	  else {

	    let requestUpdate = store.add({block: block, data: new Uint8Array(4096)});
		
	    requestUpdate.onerror = function(event) {

	      wakeUp(-1);
	    };
		
	    requestUpdate.onsuccess = function(event) {

	      wakeUp(0);
	    };
	  }
	};
      });
  
  });

int lfs_blk_sync(const struct lfs_config *c) {

  //emscripten_log(EM_LOG_CONSOLE,"*** lfs_blk_sync");
  
  return 0;
}
