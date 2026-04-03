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

EM_JS(int, exafs_local_init_repo, (const char * repo_name, const char * view), {

    return Asyncify.handleSleep(function (wakeUp) {

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	if (typeof window.repo_table === 'undefined') {

	  window.repo_table = new Array();
	}
	
	const name = UTF8ToString(repo_name);

	console.log("init_repo: "+name);
	
	let request = window.indexedDB.open(name, 1);

	request.onerror = function(event) {

	  wakeUp(-1);
	};

	request.onupgradeneeded = function(event) {

	  let db = event.target.result;

	  let objectStore = db.createObjectStore("objects", { keyPath: "object" });
	};
	      
	request.onsuccess = function(event) {

	  window.repo_table.push({name: name, db:event.target.result});

	  console.log(window.repo_table);
		
	  wakeUp(window.repo_table.length-1);	
	};

      });
  });

EM_JS(int, exafs_local_clean_repo, (uint32_t ctx_id), {

  return Asyncify.handleSleep(function (wakeUp) {

      window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

      if (!window.indexedDB)
	return -1;

      window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

      window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

      let do_clean_repo = (db) => {

	let store = db.transaction(["objects"], "readwrite").objectStore("objects");
	      
	let request = store.clear();
	      
	request.onerror = function(event) {

	  wakeUp(-1);
	};
	      
	request.onsuccess = function(event) {

	  wakeUp(0);
		
	};
      };

      do_clean_repo(window.repo_table[ctx_id].db);
      
    });
  
  });

EM_JS(int, exafs_local_read, (uint32_t ctx_id, uint32_t id, void * buffer, int len, int off), {

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

	    do_read(window.repo_table[ctx_id].db);

	  });
});

EM_JS(int, exafs_local_read_range, (uint32_t ctx_id, uint32_t id_min, uint32_t id_max, void * buffer, int len, uint32_t * last_obj), {

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

	  let store = db.transaction(["objects"]).objectStore("objects");
	      
	  const range = IDBKeyRange.bound(id_min, id_max); // inclusive

	  store.openCursor(range).onsuccess = (event) => {
		
	    const cursor = event.target.result;

	    console.log(cursor);
		
	    if (cursor) {

	      if ((offset+cursor.value.data.length+8) <= len) {
		
		Module.HEAPU8[buffer+offset] = cursor.key & 0xff;
		Module.HEAPU8[buffer+offset+1] = (cursor.key >> 8) & 0xff;
		Module.HEAPU8[buffer+offset+2] = (cursor.key >> 16) & 0xff;
		Module.HEAPU8[buffer+offset+3] = (cursor.key >> 24) & 0xff;
		
		const obj_length = cursor.value.data.length;
		
		Module.HEAPU8[buffer+offset+4] = obj_length & 0xff;
		Module.HEAPU8[buffer+offset+5] = (obj_length >> 8) & 0xff;
		Module.HEAPU8[buffer+offset+6] = (obj_length >> 16) & 0xff;
		Module.HEAPU8[buffer+offset+7] = (obj_length >> 24) & 0xff;
		
		Module.HEAPU8.set(cursor.value.data, buffer+offset+8);

		offset += obj_length+8;
		
		last = cursor.key;
		  
		cursor.continue();
	      }
	      else {

		Module.HEAPU8[last_obj] = last & 0xff;
		Module.HEAPU8[last_obj+1] = (last >> 8) & 0xff;
		Module.HEAPU8[last_obj+2] = (last >> 16) & 0xff;
		Module.HEAPU8[last_obj+3] = (last >> 24) & 0xff;
		
		wakeUp(-cursor.value.data.length);
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

	do_read_range(window.repo_table[ctx_id].db);

      });
});

EM_JS(int, exafs_local_read_set, (uint32_t ctx_id, uint32_t * obj_set, int nb_obj, char * data, int size), {

    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_read_set: nb_obj="+nb_obj+" size="+size);

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	let obj_index = 0;

	let offset = 0;

	let do_read_set = (db) => {

	  let store = db.transaction(["objects"]).objectStore("objects");

	  let do_read_obj = (idx) => {

	    if (idx >= nb_obj) {
	      
	      wakeUp(offset);
	      return;
	    }

	    let obj_id = Module.HEAPU8[obj_set+4*idx] | (Module.HEAPU8[obj_set+4*idx+1] << 8) | (Module.HEAPU8[obj_set+4*idx+2] << 16) | (Module.HEAPU8[obj_set+4*idx+3] << 24);

	    let request = store.get(obj_id);
	      
	    request.onerror = function(event) {

	      wakeUp(-1);
	    };
	      
	    request.onsuccess = function(event) {

	      if (request.result) {

		Module.HEAPU8[data+offset] = obj_id & 0xff;
		Module.HEAPU8[data+offset+1] = (obj_id >> 8) & 0xff;
		Module.HEAPU8[data+offset+2] = (obj_id >> 16) & 0xff;
		Module.HEAPU8[data+offset+3] = (obj_id >> 24) & 0xff;

		let obj_size = request.result.data.length;

		Module.HEAPU8[data+offset+4] = obj_size & 0xff;
		Module.HEAPU8[data+offset+5] = (obj_size >> 8) & 0xff;
		Module.HEAPU8[data+offset+6] = (obj_size >> 16) & 0xff;
		Module.HEAPU8[data+offset+7] = (obj_size >> 24) & 0xff;
		
		offset += 8;

		Module.HEAPU8.set(request.result.data, data+offset);

		offset += obj_size;

		do_read_obj(idx+1);
	      }
	      else {

		wakeUp(-1);
	      }
		
	    };
	  };
	  
	  do_read_obj(0);
	};

	do_read_set(window.repo_table[ctx_id].db);

      });
  });

EM_JS(int, exafs_local_write, (uint32_t ctx_id, uint32_t id, void * buffer, int len), {

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

	    do_write(window.repo_table[ctx_id].db);

      });
});

EM_JS(int, exafs_local_write_range, (uint32_t ctx_id, void * buffer, int len), {

});

EM_JS(int, exafs_local_write_rand, (uint32_t ctx_id, uint32_t max_reserved_id, void * buffer, uint32_t len, uint32_t * id), {

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

	do_find_free_obj(window.repo_table[ctx_id].db);
	
      });
});

EM_JS(int, exafs_local_delete, (uint32_t ctx_id, uint32_t id), {

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

	    do_delete(window.repo_table[ctx_id].db);

      });
});

EM_JS(int, exafs_local_delete_range, (uint32_t ctx_id, uint32_t id_min, uint32_t id_max), {

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

	    do_delete_range(window.repo_table[ctx_id].db);

      });
});

EM_JS(int, exafs_local_delete_set, (uint32_t ctx_id, uint32_t * buffer, int len), {
    
    return Asyncify.handleSleep(function (wakeUp) {
	
	console.log("exafs: exafs_local_delete_set");

	window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;

	if (!window.indexedDB)
	  return -1;

	window.IDBTransaction = window.IDBTransaction || window.webkitIDBTransaction || window.msIDBTransaction;

	window.IDBKeyRange = window.IDBKeyRange || window.webkitIDBKeyRange || window.msIDBKeyRange;

	let do_delete_set = (db) => {
	  
	  let store = db.transaction(["objects"], "readwrite").objectStore("objects");

	  let do_delete_obj = (offset) => {
	    
	    if (offset >= len) {

	      wakeUp(0);
	      return;
	    }

	    let id = Module.HEAPU8[buffer+offset] | (Module.HEAPU8[buffer+offset+1] << 8) | (Module.HEAPU8[buffer+offset+2] << 16) | (Module.HEAPU8[buffer+offset+3] << 24);

	    offset += 4;
	      
	    let request = store.delete(id);
	      
	    request.onerror = function(event) {

	      wakeUp(-1);
	    };
	      
	    request.onsuccess = function(event) {

	      console.log("exafs: exafs_local_delete_set -> obj deleted = "+id);

	      do_delete_obj(offset);
	    };
	  };

	  do_delete_obj(0);
	};

	do_delete_set(window.repo_table[ctx_id].db);

      });
  });
