/*
 * Copyright (C) 2025 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#include <emscripten.h>

#include "lfs_block.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#else
#define emscripten_log(...)
#endif


EM_JS(int, lfs_local_read, (int view_id, int cluster, void * buffer, int size), {
  
    return Asyncify.handleSleep(function (wakeUp) {

	const view = window.views[view_id];

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_read = (db) => {

	      let store = db.transaction(["clusters"]).objectStore("clusters");
	      
	      let request = store.get(cluster);
	      
	      request.onerror = function(event) {

		const buf3 = new Uint8Array(size);
		buf3.fill(0xFF);
		
		Module.HEAPU8.set(buf3, buffer);
		
		wakeUp(0);
	      };
	      
	      request.onsuccess = function(event) {

		if (request.result) {

		  Module.HEAPU8.set(request.result.data, buffer);
		}
		else {

		  const buf3 = new Uint8Array(size);
		  buf3.fill(0xFF);
		
		  Module.HEAPU8.set(buf3, buffer);
		}

		wakeUp(0);
	      };
	    };

	    if (typeof Module.localfs_dict === 'undefined') {

	      Module.localfs_dict = {};
	    }

	    if (!(view in Module.localfs_dict)) {

	      let request = window.indexedDB.open(view, 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("clusters", { keyPath: "cluster" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		Module.localfs_dict[view] = event.target.result;
		
		do_read(Module.localfs_dict[view]);
		
	      };
	    }
	    else {

	      do_read(Module.localfs_dict[view]);
	    }

	  });
});

EM_JS(int, lfs_local_write, (int view_id, int cluster, char * buffer, int size), {
    
      return Asyncify.handleSleep(function (wakeUp) {

	const view = window.views[view_id];

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_write = (db) => {

	      let store = db.transaction(["clusters"], "readwrite").objectStore("clusters");
	      
	      let request = store.put({cluster: cluster, data: Module.HEAPU8.subarray(buffer, buffer+size)});
	      
	      request.onerror = function(event) {

		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		wakeUp(0);
		
	      };
	    };

	    if (typeof Module.localfs_dict === 'undefined') {

	      Module.localfs_dict = {};
	    }

	    if (!(view in Module.localfs_dict)) {
	      
	      let request = window.indexedDB.open(view, 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("clusters", { keyPath: "cluster" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		Module.localfs_dict[view] = event.target.result;
		
		do_write(Module.localfs_dict[view]);
		
	      };
	    }
	    else {

	      do_write(Module.localfs_dict[view]);
	    }

	  });
});

EM_JS(int, lfs_local_bulk_start, (int view_id), {

    //do nothing as clusters are written one after another
});

EM_JS(int, lfs_local_bulk_end, (int view_id), {

    // do nothing
});

EM_JS(int, store_local_salt, (char * view, int view_len, char * salt, int size), {
    
    return Asyncify.handleSleep(function (wakeUp) {
	  
	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	const v = UTF8ToString(view, view_len);

	let request = window.indexedDB.open("localfs_salts", 1);

	request.onerror = function(event) {

	  wakeUp(-1);
	};

	request.onupgradeneeded = function(event) {

	  let db = event.target.result;
	  
	  let objectStore = db.createObjectStore("list", { keyPath: "view" });
	};
	      
	request.onsuccess = function(event) {

	  let db = event.target.result;
		
	  let store = db.transaction(["list"], "readwrite").objectStore("list");
	      
	  let request2 = store.put({view:v, salt: Module.HEAPU8.subarray(salt, salt+size)});
	      
	  request2.onerror = function(event) {

	    wakeUp(-1);
	  };
	      
	  request2.onsuccess = function(event) {

	    wakeUp(0);
		
	  };
		
	};
      });
});

EM_JS(int, get_local_salt, (char * view, int view_len, char * salt, int size), {
    
    return Asyncify.handleSleep(function (wakeUp) {

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	const v = UTF8ToString(view, view_len);

	let request = window.indexedDB.open("localfs_salts", 1);

	request.onerror = function(event) {

	  wakeUp(-1);
	};

	request.onupgradeneeded = function(event) {

	  let db = event.target.result;
	  
	  let objectStore = db.createObjectStore("list", { keyPath: "view" });
	};
	      
	request.onsuccess = function(event) {

	  let db = event.target.result;
		
	  let store = db.transaction(["list"]).objectStore("list");
	      
	  let request2 = store.get(v);
	      
	  request2.onerror = function(event) {

	    wakeUp(-1);
	  };
	      
	  request2.onsuccess = function(event) {

	    if (request2.result) {

	      Module.HEAPU8.set(request2.result.salt, salt);
	      wakeUp(0);
	    }
	    else {

	      wakeUp(-1);
	    }
		
	  };
	};

      });

});
