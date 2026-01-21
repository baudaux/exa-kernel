/*
 * Copyright (C) 2026 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundationt, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, sees <https://www.gnu.org/licenses/>.
 */

#include "exafs_local_dev.h"

#include <emscripten.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG

#else
#define emscripten_log(...)
#endif

int exafs_local_clean_repo(struct exafs_ctx * ctx, const char * repo_name) {

  return 0;
}

EM_JS(int, exafs_local_read, (struct exafs_ctx * ctx, uint32_t id, void * buffer, int len, int off), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_read: id="+id);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_read = (db) => {

	      let store = db.transaction(["objects"]).objectStore("objects");
	      
	      let request = store.get(id);
	      
	      request.onerror = function(event) {

		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		if (request.result) {

		  Module.HEAPU8.set(request.result.data.subarray(off, off+len), buffer);

		  if ((request.result.data.length-off) <= len) {

		    wakeUp(request.result.data.length-off);
		  }
		  else {

		    wakeUp(-request.result.data.length);
		  }
		}
		else {

		  wakeUp(-1);
		}
		
	      };
	    };

	    if (typeof window.exafs_local === 'undefined') {

	      let request = window.indexedDB.open("exafs_local", 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("objects", { keyPath: "object" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		window.exafs_local = event.target.result;
		
		do_read(window.exafs_local);
		
	      };
	    }
	    else {

	      do_read(window.exafs_local);
	    }

	  });
});

EM_JS(int, exafs_local_read_range, (struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max, void * buffer, int len, uint32_t * last_obj), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_read_range: id_min="+id_min+" id_max="+id_max);
	
	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	let offset = 0;
	let last = 0;

	let do_read_range = (db) => {

	  let store = db.transaction(["objects"], "readwrite").objectStore("objects");
	      
	  const range = IDBKeyRange.bound(id_min, id_max); // inclusive

	  store.openCursor(range).onsuccess = (event) => {
		
	    const cursor = event.target.result;

	    console.log(cursor);
		
	    if (cursor) {

	      if (offset+cursor.value.data.length <= len) {
		      
		Module.HEAPU8.set(cursor.value.data, buffer+offset);

		offset += cursor.value.data.length;

		last = cursor.key;
		  
		cursor.continue();
	      }
	      else {

		Module.HEAPU8[last_obj] = last & 0xff;
		Module.HEAPU8[last_obj+1] = (last >> 8) & 0xff;
		Module.HEAPU8[last_obj+2] = (last >> 16) & 0xff;
		Module.HEAPU8[last_obj+3] = (last >> 24) & 0xff;

		wakeUp(-offset);
	      }
	    }
	    else {

	      Module.HEAPU8[last_obj] = last & 0xff;
	      Module.HEAPU8[last_obj+1] = (last >> 8) & 0xff;
	      Module.HEAPU8[last_obj+2] = (last >> 16) & 0xff;
	      Module.HEAPU8[last_obj+3] = (last >> 24) & 0xff;
	      
	      wakeUp(offset);
	    }
	  };
	};

	if (typeof window.exafs_local === 'undefined') {
	      
	  let request = window.indexedDB.open("exafs_local", 1);

	  request.onerror = function(event) {

	    wakeUp(-1);
	  };

	  request.onupgradeneeded = function(event) {

	    let db = event.target.result;

	    let objectStore = db.createObjectStore("objects", { keyPath: "object" });

	    //TODO
	    //objectStore.createIndex("cluster", "cluster", { unique: true });
	  };
	      
	  request.onsuccess = function(event) {

	    window.exafs_local = event.target.result;
		
	    do_read_range(window.exafs_local);
		
	  };
	}
	else {

	  do_read_range(window.exafs_local);
	}

      });
});

EM_JS(int, exafs_local_write, (struct exafs_ctx * ctx, uint32_t id, void * buffer, int len), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_write: id="+id);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_write = (db) => {

	      let store = db.transaction(["objects"], "readwrite").objectStore("objects");
	      
	      let request = store.put({object: id, data: Module.HEAPU8.subarray(buffer, buffer+len)});
	      
	      request.onerror = function(event) {

		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		wakeUp(len);
		
	      };
	    };

	    if (typeof window.exafs_local === 'undefined') {
	      
	      let request = window.indexedDB.open("exafs_local", 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("objects", { keyPath: "object" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		window.exafs_local = event.target.result;
		
		do_write(window.exafs_local);
		
	      };
	    }
	    else {

	      do_write(window.exafs_local);
	    }

      });
});

EM_JS(int, exafs_local_write_range, (struct exafs_ctx * ctx, void * buffer, int len), {

});

EM_JS(int, exafs_local_write_rand, (struct exafs_ctx * ctx, uint32_t max_reserved_id, void * buffer, uint32_t len, uint32_t * id), {

    return Asyncify.handleSleep(function (wakeUp) {

	console.log("exafs: exafs_local_write_ran: max_reserved_id="+max_reserved_id+" len="+len);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	let do_write = (db, obj_id) => {

	  let store = db.transaction(["objects"], "readwrite").objectStore("objects");
	      
	  let request = store.put({object: obj_id, data: Module.HEAPU8.subarray(buffer, buffer+len)});
	      
	  request.onerror = function(event) {

	    wakeUp(-1);
	  };
	      
	  request.onsuccess = function(event) {

	    console.log("exafs: found id="+obj_id);

	    Module.HEAPU8[id] = obj_id & 0xff;
	    Module.HEAPU8[id+1] = (obj_id >> 8) & 0xff;
	    Module.HEAPU8[id+2] = (obj_id >> 16) & 0xff;
	    Module.HEAPU8[id+3] = (obj_id >> 24) & 0xff;
	    
	    wakeUp(len);
		
	  };
	};


	let do_find_free_obj = (db) => {

	  let store = db.transaction(["objects"]).objectStore("objects");

	  function find_free() {

	    const id2 = Math.floor(Math.random() * (2147483648-max_reserved_id))+max_reserved_id+1;

	    console.log("exafs: try id="+id2);
	      
	    let request = store.get(id2);
	      
	    request.onerror = function(event) {

	      wakeUp(-1);
	    };
	      
	    request.onsuccess = function(event) {

	      if (request.result) {

		find_free();
	      }
	      else {
		
		do_write(db, id2);
	      }
	    };
		
	  }

	  find_free();
	      
	};

	if (typeof window.exafs_local === 'undefined') {

	  let request = window.indexedDB.open("exafs_local", 1);

	  request.onerror = function(event) {

	    wakeUp(-1);
	  };

	  request.onupgradeneeded = function(event) {

	    let db = event.target.result;

	    let objectStore = db.createObjectStore("objects", { keyPath: "object" });
	  };
	      
	  request.onsuccess = function(event) {

	    window.exafs_local = event.target.result;
		
	    do_find_free_obj(window.exafs_local);
		
	  };
	}
	else {

	  do_find_free_obj(window.exafs_local);
	}

	
      });
});

EM_JS(int, exafs_local_delete, (struct exafs_ctx * ctx, uint32_t id), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_delete: id="+id);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB) {
	  return -1;
	}

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_delete = (db) => {

	      let store = db.transaction(["objects"], "readwrite").objectStore("objects");
	      
	      let request = store.delete(id);
	      
	      request.onerror = function(event) {

		wakeUp(-1);
	      };
	      
	      request.onsuccess = function(event) {

		wakeUp(0);
		
	      };
	    };

	    if (typeof window.exafs_local === 'undefined') {
	      
	      let request = window.indexedDB.open("exafs_local", 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("objects", { keyPath: "object" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		window.exafs_local = event.target.result;
		
		do_delete(window.exafs_local);
		
	      };
	    }
	    else {

	      do_delete(window.exafs_local);
	    }

      });
});

EM_JS(int, exafs_local_delete_range, (struct exafs_ctx * ctx, uint32_t id_min, uint32_t id_max), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_delete_range: id_min="+id_min+" id_max="+id_max);
	
	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	    let do_delete_range = (db) => {

	      let store = db.transaction(["objects"], "readwrite").objectStore("objects");
	      
	      const range = IDBKeyRange.bound(id_min, id_max); // inclusive

	      store.openCursor(range).onsuccess = (event) => {
		
		const cursor = event.target.result;
		
		if (cursor) {
		  cursor.delete();
		  cursor.continue();
		}
		else {
		  
		  wakeUp(0);
		}
	      };
	    };

	    if (typeof window.exafs_local === 'undefined') {
	      
	      let request = window.indexedDB.open("exafs_local", 1);

	      request.onerror = function(event) {

		wakeUp(-1);
	      };

	      request.onupgradeneeded = function(event) {

		let db = event.target.result;

		let objectStore = db.createObjectStore("objects", { keyPath: "object" });

		//TODO
		//objectStore.createIndex("cluster", "cluster", { unique: true });
	      };
	      
	      request.onsuccess = function(event) {

		window.exafs_local = event.target.result;
		
		do_delete_range(window.exafs_local);
		
	      };
	    }
	    else {

	      do_delete_range(window.exafs_local);
	    }

      });
});
